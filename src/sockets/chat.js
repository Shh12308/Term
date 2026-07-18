import { query } from '../database/pool.js';
import { moderationService } from '../services/moderationService.js';
import { getSocketRooms } from './index.js';
import { config } from '../config/index.js';
import logger from '../utils/logger.js';

export function registerChatHandlers(io, socket) {
  const userId = socket.data.userId;
  const user = socket.data.user;

  socket.on('message', async ({ room, text }) => {
    if (!userId) return socket.emit('error', { message: 'Not authenticated' });

    try {
      let targetRoom = room;
      if (targetRoom) {
        if (!socket.rooms.has(targetRoom)) return socket.emit('error', { message: "You're not in this room" });
      } else {
        const rooms = getSocketRooms(socket);
        if (rooms.length > 0) targetRoom = rooms[0];
        else return socket.emit('error', { message: "You're not in any room" });
      }

      if (!text || typeof text !== 'string' || text.length > 500 || text.trim().length === 0) {
        return socket.emit('error', { message: 'Invalid message' });
      }

      // Track activity using NEW schema columns (action, metadata)
      await query(
        `INSERT INTO user_activity (user_id, activity, action, metadata, created_at) 
         VALUES ($1, 'chat', 'chat_message', $2, NOW())`,
        [userId, JSON.stringify({ length: text.length })]
      ).catch(() => {});

      if (config.isModerationEnabled) {
        const mod = await moderationService.checkText(text);
        if (mod.flagged) {
          const banReason = `Inappropriate message detected`;
          await moderationService.banUser(userId, banReason);
          socket.emit('moderation_action', { type: 'chat', text, banned: true, duration_hours: config.banHours, reason: banReason });
          socket.disconnect(true);
          return;
        }
      }

      // Save to chat_messages (room_id column now exists)
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

      io.to(targetRoom).emit('message', messageData);
    } catch (err) {
      logger.error({ err, userId, event: 'chat_message_error' }, 'Failed to send message');
      socket.emit('error', { message: 'Failed to send message' });
    }
  });
}
