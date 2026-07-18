import { redis } from './redisService.js';
import logger from '../utils/logger.js';
import NodeCache from 'node-cache';

// Fallback to NodeCache only if Redis is not available
const localCache = new NodeCache({ stdTTL: 300, checkperiod: 120 });

const CACHE_PREFIX = 'cache:';
const DEFAULT_TTL = 300; // 5 minutes

export const cacheService = {
  /**
   * Get a value from cache
   */
  async get(key) {
    const fullKey = `${CACHE_PREFIX}${key}`;
    
    // Try Redis first
    const value = await redis.get(fullKey);
    if (value !== null) {
      return JSON.parse(value);
    }
    
    // Fallback to local cache
    return localCache.get(key);
  },

  /**
   * Set a value in cache
   */
  async set(key, value, ttl = DEFAULT_TTL) {
    const fullKey = `${CACHE_PREFIX}${key}`;
    const serialized = JSON.stringify(value);
    
    // Try Redis first
    const result = await redis.set(fullKey, serialized, { EX: ttl });
    if (result === 'OK') {
      return true;
    }
    
    // Fallback to local cache
    return localCache.set(key, value, ttl);
  },

  /**
   * Delete a value from cache
   */
  async del(key) {
    const fullKey = `${CACHE_PREFIX}${key}`;
    
    // Try Redis
    await redis.del(fullKey);
    
    // Also clear local cache
    localCache.del(key);
    
    return true;
  },

  /**
   * Get user from cache or fetch from database
   */
  async getUser(userId, fetchFn) {
    const cacheKey = `user:${userId}`;
    const cached = await this.get(cacheKey);
    
    if (cached) {
      return cached;
    }
    
    const user = await fetchFn();
    if (user) {
      await this.set(cacheKey, user);
    }
    
    return user;
  },

  /**
   * Invalidate user cache
   */
  async invalidateUser(userId) {
    await this.del(`user:${userId}`);
  },

  /**
   * Clear all cache (use with caution)
   */
  async clear() {
    const keys = await redis.keys(`${CACHE_PREFIX}*`);
    if (keys.length > 0) {
      await redis.del(keys);
    }
    localCache.flushAll();
  },
};
