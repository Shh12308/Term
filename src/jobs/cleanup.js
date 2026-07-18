import cron from 'node-cron';
import { queueService } from '../services/queueService.js';
import { getOnlineSocketId } from '../sockets/index.js';
import logger from '../utils/logger.js';

/**
 * Clean stale queue entries every 5 minutes
 */
export function startQueueCleanup() {
  cron.schedule('*/5 * * * *', async () => {
    try {
      const cleaned = await queueService.cleanup(getOnlineSocketId);
      if (cleaned > 0) {
        logger.info({ cleaned, event: 'queue_cleanup' }, 'Cleaned stale queue entries');
      }
    } catch (err) {
      logger.error({ err, event: 'queue_cleanup_error' }, 'Queue cleanup failed');
    }
  });

  logger.info({ event: 'queue_cleanup_started' }, 'Queue cleanup job started (every 5 minutes)');
}
