import { query, withTransaction } from '../database/pool.js';
import { queueService } from './queueService.js';
import { redis, isRedisConnected } from './redisService.js';
import { config } from '../config/index.js';
import logger from '../utils/logger.js';
import { generateChannelName } from '../utils/helpers.js';

/**
 * Acquire a distributed lock for matchmaking
 */
async function acquireLock(userId) {
  if (!isRedisConnected()) return true;
  
  try {
    const result = await redis.set(
      `lock:match:${userId}`,
      '1',
      { NX: true, EX: config.matchLockTTL }
    );
    return result === 'OK';
  } catch (err) {
    logger.error({ err, userId, event: 'lock_error' }, 'Failed to acquire match lock');
    return false;
  }
}

/**
 * Release a distributed lock
 */
async function releaseLock(userId) {
  if (!isRedisConnected()) return;
  
  try {
    await redis.del(`lock:match:${userId}`);
  } catch (err) {
    logger.error({ err, userId, event: 'unlock_error' }, 'Failed to release match lock');
  }
}

/**
 * Get recently matched partners to avoid repeat matches
 */
async function getRecentPartners(userId) {
  try {
    const { rows } = await query(
      `SELECT CASE WHEN user_a = $1 THEN user_b ELSE user_a END as partner_id
       FROM matches
       WHERE (user_a = $1 OR user_b = $1)
       AND created_at > NOW() - INTERVAL '1 hour' * $2
       ORDER BY created_at DESC
       LIMIT 20`,
      [userId, config.antiRepeatWindowHours]
    );
    return new Set(rows.map(r => String(r.partner_id)));
  } catch (err) {
    logger.error({ err, userId, event: 'recent_partners_error' }, 'Failed to get recent partners');
    return new Set();
  }
}

/**
 * Calculate match score between two users
 */
function calculateScore(a, b, aWaitTime, bWaitTime) {
  let score = 0;
  const weights = config.matchWeights;

  // Location matching
  if (a.location === b.location && a.location !== 'any') {
    score += weights.location;
  } else if (a.location === 'any' || b.location === 'any') {
    score += weights.location * 0.5;
  }

  // Interest overlap
  const aInterests = new Set(a.interests || []);
  const bInterests = new Set(b.interests || []);
  let overlap = 0;
  for (const interest of aInterests) {
    if (bInterests.has(interest)) overlap++;
  }
  const maxInterests = Math.max(aInterests.size, bInterests.size, 1);
  score += weights.interests * (overlap / maxInterests);

  // Freshness (prefer users who waited longer)
  const maxWait = Math.max(aWaitTime, bWaitTime, 1000);
  const avgWaitRatio = ((aWaitTime + bWaitTime) / 2) / maxWait;
  score += weights.freshness * avgWaitRatio;

  // Gender preference matching
  const aWantsB = a.looking_for === 'any' || a.looking_for === b.gender;
  const bWantsA = b.looking_for === 'any' || b.looking_for === a.gender;
  if (aWantsB && bWantsA) {
    score += weights.gender;
  } else if (aWantsB || bWantsA) {
    score += weights.gender * 0.5;
  }

  return score;
}

export const matchService = {
  /**
   * Try to find a match for a user
   * Uses database transaction to prevent race conditions
   */
  async tryMatch(requesterUserId, getSocketIdFn, io) {
    const now = Date.now();
    
    const lockAcquired = await acquireLock(requesterUserId);
    if (!lockAcquired) {
      logger.debug({ userId: requesterUserId, event: 'lock_busy' }, 'Match lock busy');
      return null;
    }

    try {
      const allEntries = await queueService.getAll();
      const requester = allEntries.find(e => String(e.userId) === String(requesterUserId));
      
      if (!requester) {
        return null;
      }

      const recentPartners = await getRecentPartners(requesterUserId);
      
      let bestCandidate = null;
      let bestScore = -1;
      let candidatesEvaluated = 0;

      for (const candidate of allEntries) {
        if (String(candidate.userId) === String(requesterUserId)) continue;
        if (recentPartners.has(String(candidate.userId))) continue;
        if (candidatesEvaluated >= config.maxCandidatesToScan) break;

        const requesterWantsCandidate = requester.looking_for === 'any' || requester.looking_for === candidate.gender;
        const candidateWantsRequester = candidate.looking_for === 'any' || candidate.looking_for === requester.gender;
        
        if (!requesterWantsCandidate || !candidateWantsRequester) continue;

        const aWaitTime = now - (requester.ts || now);
        const bWaitTime = now - (candidate.ts || now);
        const score = calculateScore(requester, candidate, aWaitTime, bWaitTime);

        if (score > bestScore) {
          bestScore = score;
          bestCandidate = candidate;
        }
        candidatesEvaluated++;
      }

      if (!bestCandidate || bestScore < 20) {
        return null;
      }

      const requesterSocketId = await getSocketIdFn(String(requesterUserId));
      const candidateSocketId = await getSocketIdFn(String(bestCandidate.userId));
      
      if (!requesterSocketId || !candidateSocketId) {
        if (!requesterSocketId) await queueService.remove(requesterUserId);
        if (!candidateSocketId) await queueService.remove(bestCandidate.userId);
        return null;
      }

      const candidateLockAcquired = await acquireLock(bestCandidate.userId);
      if (!candidateLockAcquired) {
        return null;
      }

      try {
        // CRITICAL: Use database transaction to prevent duplicate matches
        const matchResult = await withTransaction(async (client) => {
          // Check for existing active match with FOR UPDATE lock
          const { rows: existingMatches } = await client.query(
            `SELECT id FROM matches 
             WHERE (user_a = $1 OR user_b = $1 OR user_a = $2 OR user_b = $2)
             AND ended_at IS NULL
             FOR UPDATE`,
            [requesterUserId, bestCandidate.userId]
          );
          
          if (existingMatches.length > 0) {
            return null; // Already in a match
          }

          // Check queue status with lock
          const { rows: inQueue } = await client.query(
            `SELECT user_id FROM queue 
             WHERE user_id IN ($1, $2)
             FOR UPDATE`,
            [requesterUserId, bestCandidate.userId]
          );
          
          if (inQueue.length < 2) {
            return null; // One or both not in queue
          }

          // Create the match
          const channelName = generateChannelName(requesterUserId, bestCandidate.userId);
          
          const { rows: [match] } = await client.query(
            `INSERT INTO matches (user_a, user_b, channel_name, created_at) 
             VALUES ($1, $2, $3, NOW()) 
             RETURNING *`,
            [requesterUserId, bestCandidate.userId, channelName]
          );

          // Remove from queue
          await client.query('DELETE FROM queue WHERE user_id = $1', [requesterUserId]);
          await client.query('DELETE FROM queue WHERE user_id = $1', [bestCandidate.userId]);

          return match;
        });

        if (!matchResult) {
          return null;
        }

        // Remove from in-memory/Redis queues (outside transaction - eventual consistency)
        await queueService.remove(requesterUserId);
        await queueService.remove(bestCandidate.userId);

        const requesterInfo = {
          username: requester.username || 'User',
          nickname: requester.nickname || '',
          avatar: requester.avatar || '',
          gender: requester.gender || 'any',
          location: requester.location || 'any',
          interests: requester.interests || [],
        };

        const candidateInfo = {
          username: bestCandidate.username || 'User',
          nickname: bestCandidate.nickname || '',
          avatar: bestCandidate.avatar || '',
          gender: bestCandidate.gender || 'any',
          location: bestCandidate.location || 'any',
          interests: bestCandidate.interests || [],
        };

        // Emit to both users
        io.to(requesterSocketId).emit('match_found', {
          peerId: bestCandidate.userId,
          channel: matchResult.channel_name,
          peerInfo: candidateInfo,
          score: Math.round(bestScore),
        });

        io.to(candidateSocketId).emit('match_found', {
          peerId: requesterUserId,
          channel: matchResult.channel_name,
          peerInfo: requesterInfo,
          score: Math.round(bestScore),
        });

        logger.info({ 
          user1: requesterUserId, 
          user2: bestCandidate.userId, 
          score: Math.round(bestScore),
          event: 'match_found' 
        }, 'Users matched');

        return { 
          peerId: bestCandidate.userId, 
          channel: matchResult.channel_name 
        };
      } finally {
        await releaseLock(bestCandidate.userId);
      }
    } finally {
      await releaseLock(requesterUserId);
    }
  },

  /**
   * End a match
   */
  async endMatch(userId) {
    const { rows } = await query(
      `UPDATE matches 
       SET ended_at = NOW() 
       WHERE (user_a = $1 OR user_b = $1) 
       AND ended_at IS NULL
       RETURNING *`,
      [userId]
    );
    
    return rows[0] || null;
  },

  /**
   * Get match history for a user
   */
  async getHistory(userId, page = 1, limit = 10) {
    const offset = (page - 1) * limit;
    
    const { rows } = await query(
      `SELECT m.*, 
              CASE WHEN m.user_a = $1 THEN m.user_b ELSE m.user_a END as partner_id,
              u.username as partner_username,
              u.avatar as partner_avatar
       FROM matches m
       JOIN users u ON (CASE WHEN m.user_a = $1 THEN m.user_b ELSE m.user_a END) = u.id
       WHERE (m.user_a = $1 OR m.user_b = $1)
       ORDER BY m.created_at DESC
       LIMIT $2 OFFSET $3`,
      [userId, limit, offset]
    );

    const { rows: countRows } = await query(
      'SELECT COUNT(*) as total FROM matches WHERE user_a = $1 OR user_b = $1',
      [userId]
    );

    return {
      matches: rows,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total: parseInt(countRows[0].total),
        pages: Math.ceil(countRows[0].total / limit),
      },
    };
  },
};
