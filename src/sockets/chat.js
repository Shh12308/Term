import { query } from '../database/pool.js';
import { moderationService } from '../services/moderationService.js';
import { getSocketRooms } from './index.js';
import { config } from '../config/index.js';
import logger from '../utils/logger.js';

export function registerChatHandlers(io, socket) {
  const userId = socket.data.userId;
  const user = socket.data.user;

  socket.on('message', async ({ room, text }) => {
    if (!userId) {
      return socket.emit('error', { message: 'Not authenticated' });
    }

    try {
      // Determine target room
      let targetRoom = room;
      if (targetRoom) {
        if (!socket.rooms.has(targetRoom)) {
          return socket.emit('error', { message: "You're not in this room" });
        }
      } else {
        const rooms = getSocketRooms(socket);
        if (rooms.length > 0) {
          targetRoom = rooms[0];
        } else {
          return socket.emit('error', { message: "You're not in any room" });
        }
      }

      // Validate message
      if (!text || typeof text !== 'string' || text.length > 500 || text.trim().length === 0) {
        return socket.emit('error', { message: 'Invalid message' });
      }

      // Track activity for suspicious behavior detection
      await detectSuspiciousBehavior(userId, 'chat_message', { length: text.length });

      // Moderation check (synchronous for chat - immediate feedback needed)
      if (config.isModerationEnabled) {
        const mod = await moderationService.checkText(text);
        
        if (mod.flagged) {
          const banReason = `Inappropriate message: ${JSON.stringify(mod.categoryScores)}`;
          await moderationService.banUser(userId, banReason);
          
          socket.emit('moderation_action', {
            type: 'chat',
            text,
            banned: true,
            duration_hours: config.banHours,
            reason: banReason,
          });
          socket.disconnect(true);
          return;
        }
      }

      // Save message to database
      const { rows } = await query(
        'INSERT INTO chat_messages (user_id, room_id, message, created_at) VALUES ($1, $2, $3, NOW()) RETURNING *',
        [userId, targetRoom, text]
      );

      const messageData = {
        id: rows[0].id,
        uid: userId,
        text,
        timestamp: rows[0].created_at,
        username: user?.username || 'User',
      };

      // Emit to all room participants (including sender for confirmation)
      io.to(targetRoom).emit('message', messageData);
    } catch (err) {
      logger.error({ err, userId, event: 'chat_message_error' }, 'Failed to send message');
      socket.emit('error', { message: 'Failed to send message' });
    }
  });
}

async function detectSuspiciousBehavior(userId, action, metadata = {}) {
  try {
    await query(
      'INSERT INTO user_activity (user_id, action, metadata, created_at) VALUES ($1, $2, $3, NOW())',
      [userId, action, JSON.stringify(metadata)]
    );

    const { rows } = await query(
      `SELECT COUNT(*) as count FROM user_activity 
       WHERE user_id = $1 AND action = $2 AND created_at > NOW() - INTERVAL '1 hour'`,
      [userId, action]
    );

    if (parseInt(rows[0].count) > 50) {
      await query(
        'INSERT INTO flagged_users (user_id, reason, created_at) VALUES ($1, $2, NOW())',
        [userId, `Suspicious activity: ${action} performed ${rows[0].count} times in an hour`]
      );
      logger.warn({ userId, action, count: rows[0].count, event: 'suspicious_activity' }, 'Suspicious activity detected');
    }
  } catch (err) {
    logger.error({ err, userId, event: 'suspicious_detection_error' }, 'Error detecting suspicious behavior');
  }
}
