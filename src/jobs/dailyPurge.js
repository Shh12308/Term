import cron from 'node-cron';
import { query } from '../database/pool.js';
import logger from '../utils/logger.js';

/**
 * Daily data purge at 3 AM
 */
export function startDailyPurge() {
  cron.schedule('0 3 * * *', async () => {
    try {
      logger.info({ event: 'daily_purge_start' }, 'Starting daily data purge');

      const { rowCount: messagesDeleted } = await query(
        "DELETE FROM chat_messages WHERE created_at < NOW() - INTERVAL '30 days'"
      );

      const { rowCount: activityDeleted } = await query(
        "DELETE FROM user_activity WHERE created_at < NOW() - INTERVAL '90 days'"
      );

      const { rowCount: appealsDeleted } = await query(
        "DELETE FROM appeals WHERE status IN ('approved', 'rejected') AND reviewed_at < NOW() - INTERVAL '180 days'"
      );

      logger.info({ 
        messagesDeleted, 
        activityDeleted, 
        appealsDeleted,
        event: 'daily_purge_complete' 
      }, 'Daily purge completed');
    } catch (err) {
      logger.error({ err, event: 'daily_purge_error' }, 'Daily purge failed');
    }
  });

  logger.info({ event: 'daily_purge_started' }, 'Daily purge job started (3 AM)');
}
