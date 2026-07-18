import { Router } from 'express';
import { query } from '../database/pool.js';
import { matchService } from '../services/matchService.js';
import { queueService } from '../services/queueService.js';
import { cacheService } from '../services/cacheService.js';
import { requireAuth } from '../middleware/auth.js';
import { validate } from '../middleware/validator.js';
import { enqueueSchema } from '../middleware/validator.js';
import { getOnlineSocketId, getIO } from '../sockets/index.js';
import { config } from '../config/index.js';
import { normalizeInterests, getClientIp } from '../utils/helpers.js';
import geoip from 'geoip-lite';
import logger from '../utils/logger.js';

const router = Router();

// DEPRECATED: Use socket events instead
router.post('/enqueue', requireAuth, validate(enqueueSchema), async (req, res, next) => {
  logger.warn({ userId: req.user.id, event: 'deprecated_enqueue' }, 'Deprecated /queue/enqueue called');

  try {
    const { gender, looking_for, location, interests, nickname } = req.validatedBody;
    const userId = String(req.user.id);

    // Check for active match
    const { rows: activeMatch } = await query(
      'SELECT id FROM matches WHERE (user_a = $1 OR user_b = $1) AND ended_at IS NULL',
      [userId]
    );
    if (activeMatch.length > 0) {
      return res.status(400).json({ error: "You're already in a match" });
    }

    // Get location
    let finalLocation = location;
    if (!finalLocation || finalLocation === 'any') {
      const ip = getClientIp(req);
      const geo = geoip.lookup(ip);
      finalLocation = geo?.country?.toLowerCase() || 'any';
    }

    // Check ban status
    if (req.user.banned_until && new Date(req.user.banned_until) > new Date()) {
      return res.status(403).json({ error: 'Account banned' });
    }

    if (!req.user.age_verified) {
      return res.status(403).json({ error: 'Age verification required for video features' });
    }

    const normalizedInterests = normalizeInterests(interests, config.maxInterests);
    const socketId = await getOnlineSocketId(userId);

    const queueEntry = {
      userId,
      socketId: socketId || '',
      gender: gender || 'any',
      looking_for: looking_for || 'any',
      location: finalLocation || 'any',
      interests: normalizedInterests,
      nickname: nickname || '',
      username: req.user.username || 'User',
      avatar: req.user.avatar || '',
      ts: Date.now(),
    };

    await queueService.add(queueEntry);

    const io = getIO();
    const match = await matchService.tryMatch(userId, getOnlineSocketId, io);

    if (match) {
      return res.json({ matched: true, peerId: match.peerId, channel: match.channel });
    }

    return res.json({ 
      matched: false, 
      locationUsed: finalLocation, 
      deprecated: true, 
      useSocket: true 
    });
  } catch (err) {
    next(err);
  }
});

// DEPRECATED: Use socket events instead
router.get('/check', requireAuth, async (req, res, next) => {
  logger.warn({ userId: req.user.id, event: 'deprecated_queue_check' }, 'Deprecated /queue/check called');

  try {
    const userId = String(req.user.id);
    const { rows } = await query(
      `SELECT * FROM matches 
       WHERE (user_a = $1 OR user_b = $1) 
       AND created_at > NOW() - INTERVAL '30 seconds' 
       AND ended_at IS NULL 
       LIMIT 1`,
      [userId]
    );

    if (rows.length > 0) {
      const match = rows[0];
      const peerId = match.user_a === userId ? match.user_b : match.user_a;
      const { rows: peerRows } = await query(
        'SELECT username, nickname, avatar, gender, location, interests FROM users WHERE id = $1',
        [peerId]
      );
      return res.json({ matched: true, peerId, channel: match.channel_name, peerInfo: peerRows[0] });
    }

    return res.json({ matched: false, deprecated: true, useSocket: true });
  } catch (err) {
    next(err);
  }
});

// DEPRECATED: Use socket events instead
router.post('/leave', requireAuth, async (req, res, next) => {
  logger.warn({ userId: req.user.id, event: 'deprecated_queue_leave' }, 'Deprecated /queue/leave called');

  try {
    await queueService.remove(String(req.user.id));
    return res.json({ ok: true, deprecated: true, useSocket: true });
  } catch (err) {
    next(err);
  }
});

export default router;
