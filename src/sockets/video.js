import sharp from 'sharp';
import { config } from '../config/index.js';
import { moderationService } from '../services/moderationService.js';
import { getSocketRooms, getIO } from './index.js';
import logger from '../utils/logger.js';

export function registerVideoHandlers(io, socket) {
  const userId = socket.data.userId;

  socket.on('video_frame', async ({ frameBase64, roomId }) => {
    if (!userId) return;

    // Rate limit: Check interval (12 seconds instead of 1 second)
    const now = Date.now();
    if (now - socket.data.lastFrameModeration < config.videoModerationIntervalMs) {
      return; // Silently drop frame - too frequent
    }
    socket.data.lastFrameModeration = now;

    try {
      // Determine target room
      let targetRoom = roomId;
      if (targetRoom) {
        if (!socket.rooms.has(targetRoom)) return;
      } else {
        const rooms = getSocketRooms(socket);
        if (rooms.length > 0) {
          targetRoom = rooms[0];
        } else {
          return;
        }
      }

      // Process image
      const buffer = Buffer.from(frameBase64.split(',')[1], 'base64');
      const processedImage = await sharp(buffer)
        .resize({ width: 320, height: 240, fit: 'inside' })
        .jpeg({ quality: 70 })
        .toBuffer();
      
      const processedBase64 = `data:image/jpeg;base64,${processedImage.toString('base64')}`;

      // Queue async moderation (non-blocking)
      await moderationService.queueImageModeration({
        userId,
        base64: processedBase64,
        type: 'video',
        socketId: socket.id,
        io,
      });

      // Forward frame to peer immediately (don't wait for moderation)
      const roomSockets = await io.in(targetRoom).fetchSockets();
      for (const s of roomSockets) {
        if (String(s.data.userId) !== String(userId)) {
          io.to(s.id).emit('video_frame', {
            frameBase64: processedBase64,
            from: userId,
          });
        }
      }
    } catch (err) {
      logger.error({ err, userId, event: 'video_frame_error' }, 'Video frame processing failed');
    }
  });
}
