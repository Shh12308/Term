import OpenAI from 'openai';
import { env, config } from '../config/index.js';
import logger from '../utils/logger.js';
import { query } from '../database/pool.js';
import { cacheService } from './cacheService.js';

const openai = new OpenAI({
  apiKey: env.OPENAI_API_KEY,
  timeout: 10000,
  maxRetries: 1,
});

// Moderation result queue for async processing
const moderationQueue = [];
let isProcessing = false;

export const moderationService = {
  /**
   * Synchronously check text content
   * Use for: usernames, display names, short inputs
   */
  async checkText(text) {
    if (!config.isModerationEnabled) {
      return { flagged: false, reason: 'moderation_disabled' };
    }

    try {
      const mod = await openai.moderations.create({
        model: 'omni-moderation-latest',
        input: text,
      });

      const result = mod.results?.[0];
      if (!result) {
        return { flagged: false, reason: 'no_result' };
      }

      return {
        flagged: result.flagged,
        categories: result.categories,
        categoryScores: result.category_scores,
      };
    } catch (err) {
      logger.error({ err, event: 'moderation_error' }, 'Text moderation failed');
      return { flagged: false, reason: 'error', error: err.message };
    }
  },

  /**
   * Queue image for async moderation
   * Returns immediately - moderation happens in background
   */
  async queueImageModeration({ userId, base64, type, socketId, io }) {
    if (!config.isModerationEnabled) {
      return;
    }

    moderationQueue.push({
      userId,
      base64,
      type,
      socketId,
      io,
      queuedAt: Date.now(),
    });

    if (!isProcessing) {
      processModerationQueue();
    }
  },

  /**
   * Synchronously check image content
   * Use sparingly - blocks the event loop
   */
  async checkImage(base64) {
    if (!config.isModerationEnabled) {
      return { flagged: false, reason: 'moderation_disabled' };
    }

    try {
      const mod = await openai.moderations.create({
        model: 'omni-moderation-latest',
        input: base64,
      });

      const result = mod.results?.[0];
      if (!result) {
        return { flagged: false, reason: 'no_result' };
      }

      return {
        flagged: result.flagged,
        categories: result.categories,
        categoryScores: result.category_scores,
      };
    } catch (err) {
      logger.error({ err, event: 'image_moderation_error' }, 'Image moderation failed');
      return { flagged: false, reason: 'error', error: err.message };
    }
  },

  /**
   * Ban a user for moderation violation
   */
  async banUser(userId, reason, banHours = config.banHours) {
    try {
      await query(
        `UPDATE users 
         SET banned_until = NOW() + INTERVAL '1 hour' * $1, 
             ban_reason = $2 
         WHERE id = $3`,
        [banHours, reason, userId]
      );
      
      await query(
        `INSERT INTO moderation_logs (user_id, action, reason, created_at) 
         VALUES ($1, 'auto_ban', $2, NOW())`,
        [userId, reason]
      );
      
      await cacheService.invalidateUser(userId);
      
      logger.warn({ userId, reason, banHours, event: 'user_auto_banned' }, 'User auto-banned');
      
      return true;
    } catch (err) {
      logger.error({ err, userId, event: 'ban_error' }, 'Failed to ban user');
      return false;
    }
  },
};

/**
 * Background processor for moderation queue
 * Processes one item at a time to avoid overwhelming OpenAI
 */
async function processModerationQueue() {
  isProcessing = true;
  
  while (moderationQueue.length > 0) {
    const item = moderationQueue.shift();
    
    // Skip if queued too long (user likely disconnected)
    if (Date.now() - item.queuedAt > 30000) {
      continue;
    }
    
    try {
      const result = await moderationService.checkImage(item.base64);
      
      if (result.flagged) {
        await moderationService.banUser(item.userId, 'Inappropriate content detected');
        
        // Notify and disconnect user
        if (item.io && item.socketId) {
          const socket = item.io.sockets.sockets.get(item.socketId);
          if (socket) {
            socket.emit('moderation_action', {
              type: item.type,
              banned: true,
              duration_hours: config.banHours,
              reason: 'Inappropriate content detected',
            });
            socket.disconnect(true);
          }
        }
      }
    } catch (err) {
      logger.error({ err, userId: item.userId, event: 'queue_moderation_error' }, 'Queue moderation failed');
    }
    
    // Small delay between requests to avoid rate limits
    await new Promise(resolve => setTimeout(resolve, 100));
  }
  
  isProcessing = false;
}
