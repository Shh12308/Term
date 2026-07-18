import { query } from '../database/pool.js';
import { getSocketRooms, getOnlineSocketId } from './index.js';
import { cacheService } from '../services/cacheService.js';
import logger from '../utils/logger.js';

export function registerReportHandlers(io, socket) {
  const userId = socket.data.userId;

  socket.on('report_user', async ({ reportedUserId, reason, roomId }) => {
    if (!userId) return;

    try {
      // Validate reason
      if (!reason || reason.length < 10 || reason.length > 200) {
        return socket.emit('error', { message: 'Invalid report reason (10-200 characters required)' });
      }

      // Verify user is in the same room if roomId provided
      if (roomId && !socket.rooms.has(roomId)) {
        return socket.emit('error', { message: 'You can only report users in the same room' });
      }

      // Check for duplicate report
      const { rows: existingReport } = await query(
        `SELECT id FROM user_reports 
         WHERE reporter_id = $1 AND reported_id = $2 AND created_at > NOW() - INTERVAL '24 hours'`,
        [userId, reportedUserId]
      );
      
      if (existingReport.length > 0) {
        return socket.emit('error', { message: 'You already reported this user recently' });
      }

      // Create report
      await query(
        'INSERT INTO user_reports (reporter_id, reported_id, reason, room_id, created_at) VALUES ($1, $2, $3, $4, NOW())',
        [userId, reportedUserId, reason, roomId]
      );

      // Check report count for auto-ban
      const { rows: reportCount } = await query(
        `SELECT COUNT(*) as count FROM user_reports 
         WHERE reported_id = $1 AND created_at > NOW() - INTERVAL '24 hours'`,
        [reportedUserId]
      );

      if (parseInt(reportCount[0].count) >= 3) {
        // Auto-ban for multiple reports
        await query(
          "UPDATE users SET banned_until = NOW() + INTERVAL '168 hours', ban_reason = $1 WHERE id = $2",
          ['Multiple user reports', reportedUserId]
        );
        
        await cacheService.invalidateUser(reportedUserId);

        // Notify and disconnect reported user
        const reportedSocketId = await getOnlineSocketId(String(reportedUserId));
        if (reportedSocketId) {
          const reportedSocket = io.sockets.sockets.get(reportedSocketId);
          if (reportedSocket) {
            reportedSocket.emit('banned', {
              reason: 'Multiple user reports',
              until: new Date(Date.now() + 168 * 60 * 60 * 1000),
              canAppeal: true,
            });
            reportedSocket.disconnect(true);
          }
        }

        logger.warn({ reportedUserId, reporterId: userId, event: 'auto_ban_reports' }, 'User auto-banned due to reports');
      }

      socket.emit('report_submitted', { message: 'Report submitted successfully' });
      logger.info({ reporterId: userId, reportedUserId, event: 'user_reported' }, 'User reported');
    } catch (err) {
      logger.error({ err, userId, event: 'report_error' }, 'Failed to submit report');
      socket.emit('error', { message: 'Failed to submit report' });
    }
  });
}
