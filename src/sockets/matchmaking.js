import { config } from '../config/index.js';
import { query } from '../database/pool.js';
import { matchService } from '../services/matchService.js';
import { queueService } from '../services/queueService.js';
import { getOnlineSocketId } from './index.js';
import { cacheService } from '../services/cacheService.js';
import { normalizeInterests, getClientIp } from '../utils/helpers.js';
import geoip from 'geoip-lite';
import logger from '../utils/logger.js';

export function registerMatchmakingHandlers(io, socket) {
  const userId = socket.data.userId;
  const user = socket.data.user;

  socket.on('join_queue', async (data = {}) => {
    if (!userId) return socket.emit('error', { message: 'Not authenticated' });

    try {
      const { rows: activeMatch } = await query(
        'SELECT id FROM matches WHERE (user_a = $1 OR user_b = $1) AND ended_at IS NULL',
        [userId]
      );
      if (activeMatch.length > 0) {
        return socket.emit('error', { message: "You're already in a match" });
      }

      if (user.banned_until && new Date(user.banned_until) > new Date()) {
        return socket.emit('error', { message: 'Account is banned' });
      }

      if (!user.age_verified) {
        return socket.emit('error', { message: 'Age verification required for video features' });
      }

      const nickname = data.nickname || user.nickname || '';
      if (nickname && (nickname.length > config.maxNicknameLength || nickname.length < 1)) {
        return socket.emit('error', { message: `Nickname must be between 1 and ${config.maxNicknameLength} characters` });
      }

      // Normalize interests to array for in-memory/Redis, will convert to string for DB inside queueService
      let interests = data.interests || user.interests || [];
      if (!Array.isArray(interests)) interests = [];
      interests = interests.filter(i => typeof i === 'string' && i.length > 0 && i.length <= 30).slice(0, config.maxInterests);

      let location = data.location || user.location || 'any';
      if (!location || location === 'any') {
        const ip = socket.handshake.headers['x-forwarded-for']?.split(',')[0] || socket.handshake.address;
        const geo = geoip.lookup(ip);
        location = geo?.country?.toLowerCase() || 'any';
      }

      const queueEntry = {
        userId: String(userId),
        socketId: socket.id,
        gender: data.gender || user.gender || 'any',
        looking_for: data.looking_for || user.looking_for || 'any',
        location,
        interests, // Keep as array for fast matching
        nickname,
        username: user.username || 'User',
        avatar: user.avatar || '',
        ts: Date.now(),
      };

      await queueService.add(queueEntry);
      socket.data.inQueue = true;

      // Save to users table (normalize interests to string for DB text column)
      const interestsStr = normalizeInterests(interests);
      await query(
        `UPDATE users SET gender = $1, looking_for = $2, location = $3, interests = $4, nickname = $5, updated_at = NOW()
         WHERE id = $6`,
        [queueEntry.gender, queueEntry.looking_for, location, interestsStr, nickname, userId]
      );
      await cacheService.invalidateUser(userId);

      const queueCount = await queueService.getCount();
      
      socket.emit('queue_joined', {
        position: queueCount,
        locationUsed: location,
        estimatedWait: queueCount > 1 ? 'Searching...' : 'Waiting for others...',
      });

      logger.info({ userId, queueCount, event: 'queue_joined' }, 'User joined queue');

      const match = await matchService.tryMatch(userId, getOnlineSocketId, io);
      
      if (match) {
        logger.info({ userId, peerId: match.peerId, event: 'instant_match' }, 'Instant match found');
      } else {
        socket.emit('queue_waiting', {
          position: await queueService.getCount(),
          message: 'Looking for someone to chat with...',
        });
      }
    } catch (err) {
      logger.error({ err, userId, event: 'join_queue_error' }, 'Failed to join queue');
      socket.emit('error', { message: 'Failed to join queue' });
    }
  });

  socket.on('leave_queue', async () => {
    if (!userId) return;
    try {
      await queueService.remove(userId);
      socket.data.inQueue = false;
      socket.emit('queue_left', { message: 'Left the queue' });
      logger.info({ userId, event: 'queue_left' }, 'User left queue');
    } catch (err) {
      logger.error({ err, userId, event: 'leave_queue_error' }, 'Failed to leave queue');
    }
  });

  socket.on('queue_status', async () => {
    if (!userId) return;
    try {
      const queueCount = await queueService.getCount();
      socket.emit('queue_status', {
        inQueue: socket.data.inQueue || queueService.isInQueue(userId),
        position: queueCount,
      });
    } catch (err) {
      logger.error({ err, userId, event: 'queue_status_error' }, 'Failed to get queue status');
    }
  });

  socket.on('next', async () => {
    if (!userId) return;
    try {
      await matchService.endMatch(userId);

      for (const room of socket.rooms) {
        if (room !== socket.id) {
          socket.leave(room);
          socket.to(room).emit('peer_left', { socketId: socket.id, userId });
        }
      }

      const cachedEntry = queueService.getLocal(String(userId));
      const preferences = cachedEntry ? {
        gender: cachedEntry.gender,
        looking_for: cachedEntry.looking_for,
        location: cachedEntry.location,
        interests: cachedEntry.interests,
        nickname: cachedEntry.nickname,
      } : {};

      socket.emit('next_ready');
      socket.emit('auto_requeue', { preferences });
    } catch (err) {
      logger.error({ err, userId, event: 'next_error' }, 'Failed to find next match');
      socket.emit('error', { message: 'Failed to find next match' });
    }
  });
}
