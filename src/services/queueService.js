import { redis, isRedisConnected } from './redisService.js';
import { query, withTransaction } from '../database/pool.js';
import logger from '../utils/logger.js';
import { config } from '../config/index.js';

// Local fallback queue
const localQueue = new Map();

export const queueService = {
  /**
   * Add user to queue (both Redis and local)
   */
  async add(entry) {
    const uid = String(entry.userId);
    
    // Always add to local queue for fast access
    localQueue.set(uid, entry);
    
    // Add to Redis if available
    if (isRedisConnected()) {
      try {
        await redis.hSet(`matchq:${uid}`, {
          userId: uid,
          socketId: entry.socketId,
          gender: entry.gender || 'any',
          looking_for: entry.looking_for || 'any',
          location: entry.location || 'any',
          interests: JSON.stringify(entry.interests || []),
          nickname: entry.nickname || '',
          username: entry.username || '',
          avatar: entry.avatar || '',
          ts: String(entry.ts),
        });
        await redis.zAdd('match_queue', { score: entry.ts, value: uid });
        await redis.expire(`matchq:${uid}`, 3600);
      } catch (err) {
        logger.error({ err, userId: uid, event: 'redis_queue_add_error' }, 'Failed to add to Redis queue');
      }
    }
    
    // Always persist to database
    await query(
      `INSERT INTO queue (user_id, gender, looking_for, location, interests, nickname, joined_at) 
       VALUES ($1, $2, $3, $4, $5, $6, NOW()) 
       ON CONFLICT (user_id) DO UPDATE SET 
         gender = EXCLUDED.gender, 
         looking_for = EXCLUDED.looking_for, 
         location = EXCLUDED.location, 
         interests = EXCLUDED.interests, 
         nickname = EXCLUDED.nickname, 
         joined_at = NOW()`,
      [uid, entry.gender, entry.looking_for, entry.location, entry.interests, entry.nickname]
    );
  },

  /**
   * Remove user from queue
   */
  async remove(userId) {
    const uid = String(userId);
    
    localQueue.delete(uid);
    
    if (isRedisConnected()) {
      try {
        await redis.zRem('match_queue', uid);
        await redis.del(`matchq:${uid}`);
      } catch (err) {
        logger.error({ err, userId: uid, event: 'redis_queue_remove_error' }, 'Failed to remove from Redis queue');
      }
    }
    
    await query('DELETE FROM queue WHERE user_id = $1', [uid]).catch(() => {});
  },

  /**
   * Get all queue entries
   */
  async getAll() {
    if (isRedisConnected()) {
      try {
        const userIds = await redis.zRange('match_queue', 0, -1);
        const entries = [];
        
        // Pipeline for better performance
        for (const uid of userIds) {
          const data = await redis.hGetAll(`matchq:${uid}`);
          if (data?.userId) {
            entries.push({
              ...data,
              interests: JSON.parse(data.interests || '[]'),
              ts: parseInt(data.ts),
            });
          }
        }
        
        return entries;
      } catch (err) {
        logger.error({ err, event: 'redis_queue_getall_error' }, 'Failed to get Redis queue');
      }
    }
    
    return Array.from(localQueue.values());
  },

  /**
   * Get queue count
   */
  async getCount() {
    if (isRedisConnected()) {
      return await redis.zCard('match_queue');
    }
    return localQueue.size;
  },

  /**
   * Get local queue entry (fast lookup)
   */
  getLocal(userId) {
    return localQueue.get(String(userId));
  },

  /**
   * Check if user is in queue
   */
  isInQueue(userId) {
    return localQueue.has(String(userId));
  },

  /**
   * Clean stale entries (no active socket)
   */
  async cleanup(getSocketIdFn) {
    const fiveMinutesAgo = Date.now() - 5 * 60 * 1000;
    let cleaned = 0;
    
    // Clean local queue
    for (const [userId, entry] of localQueue) {
      if (entry.ts < fiveMinutesAgo) {
        const socketId = await getSocketIdFn(userId);
        if (!socketId) {
          localQueue.delete(userId);
          cleaned++;
          logger.debug({ userId, event: 'stale_local_entry' }, 'Cleaned stale local queue entry');
        }
      }
    }
    
    // Clean Redis queue
    if (isRedisConnected()) {
      try {
        const keys = await redis.keys('matchq:*');
        for (const key of keys) {
          const userId = key.replace('matchq:', '');
          const ts = await redis.hGet(key, 'ts');
          
          if (ts && parseInt(ts) < fiveMinutesAgo) {
            const socketId = await getSocketIdFn(userId);
            if (!socketId) {
              await this.remove(userId);
              cleaned++;
              logger.debug({ userId, event: 'stale_redis_entry' }, 'Cleaned stale Redis queue entry');
            }
          }
        }
      } catch (err) {
        logger.error({ err, event: 'redis_cleanup_error' }, 'Redis queue cleanup failed');
      }
    }
    
    // Clean database queue
    await query('DELETE FROM queue WHERE joined_at < NOW() - INTERVAL \'10 minutes\'').catch(() => {});
    
    return cleaned;
  },

  /**
   * Get queue statistics
   */
  async getStats() {
    const entries = await this.getAll();
    
    const stats = {
      total: entries.length,
      byLocation: {},
      byGender: {},
      mode: isRedisConnected() ? 'redis' : 'local',
    };
    
    for (const entry of entries) {
      const loc = entry.location || 'any';
      const gen = entry.gender || 'any';
      stats.byLocation[loc] = (stats.byLocation[loc] || 0) + 1;
      stats.byGender[gen] = (stats.byGender[gen] || 0) + 1;
    }
    
    return stats;
  },
};
