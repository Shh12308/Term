import cron from 'node-cron';
import { query } from '../database/pool.js';
import { cacheService } from '../services/cacheService.js';
import logger from '../utils/logger.js';

/**
 * Check for expired bans every hour
 * Could send notifications to users
 */
export function startBanExpiryCheck() {
  cron.schedule('0 * * * *', async () => {
    try {
      // Find users whose bans just expired
      const { rows } = await query(
        `SELECT id, username FROM users 
         WHERE banned_until IS NOT NULL 
         AND banned_until <= NOW() 
         AND banned_until > NOW() - INTERVAL '1 hour'`
      );

      for (const user of rows) {
        await cacheService.invalidateUser(user.id);
        logger.info({ userId: user.id, event: 'ban_expired' }, 'User ban expired');
      }

      if (rows.length > 0) {
        logger.info({ count: rows.length, event: 'ban_expiry_check' }, 'Processed expired bans');
      }
    } catch (err) {
      logger.error({ err, event: 'ban_expiry_error' }, 'Ban expiry check failed');
    }
  });

  logger.info({ event: 'ban_expiry_started' }, 'Ban expiry check job started (hourly)');
}
