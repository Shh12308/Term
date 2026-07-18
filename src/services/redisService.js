import { env, config } from '../config/index.js';
import logger from '../utils/logger.js';

let redisClient = null;
let pubClient = null;
let subClient = null;

export async function initRedis() {
  if (!config.isRedisEnabled) {
    logger.warn({ event: 'redis_disabled' }, 'No REDIS_URL — running in single-instance mode');
    return false;
  }

  try {
    const { createClient } = await import('redis');
    
    pubClient = createClient({ 
      url: env.REDIS_URL,
      socket: {
        reconnectStrategy: (retries) => {
          if (retries > 10) {
            logger.error({ event: 'redis_max_retries' }, 'Redis max reconnection attempts reached');
            return false;
          }
          return Math.min(retries * 100, 3000);
        },
      },
    });
    
    subClient = pubClient.duplicate();

    pubClient.on('error', (err) => {
      logger.error({ err, event: 'redis_error' }, 'Redis client error');
    });

    subClient.on('error', (err) => {
      logger.error({ err, event: 'redis_sub_error' }, 'Redis subscriber error');
    });

    await pubClient.connect();
    await subClient.connect();
    
    redisClient = pubClient;
    
    logger.info({ event: 'redis_connected' }, 'Redis connected successfully');
    return true;
  } catch (err) {
    logger.warn({ err, event: 'redis_init_failed' }, 'Redis initialization failed, falling back to local');
    return false;
  }
}

export function getRedisClient() {
  return redisClient;
}

export function isRedisConnected() {
  return redisClient?.isReady ?? false;
}

// Safe Redis operations with error handling
export const redis = {
  async get(key) {
    if (!redisClient) return null;
    try {
      return await redisClient.get(key);
    } catch (err) {
      logger.error({ err, key, event: 'redis_get_error' }, 'Redis GET error');
      return null;
    }
  },

  async set(key, value, options = {}) {
    if (!redisClient) return false;
    try {
      return await redisClient.set(key, value, options);
    } catch (err) {
      logger.error({ err, key, event: 'redis_set_error' }, 'Redis SET error');
      return false;
    }
  },

  async del(key) {
    if (!redisClient) return 0;
    try {
      return await redisClient.del(key);
    } catch (err) {
      logger.error({ err, key, event: 'redis_del_error' }, 'Redis DEL error');
      return 0;
    }
  },

  async hSet(key, data) {
    if (!redisClient) return 0;
    try {
      return await redisClient.hSet(key, data);
    } catch (err) {
      logger.error({ err, key, event: 'redis_hset_error' }, 'Redis HSET error');
      return 0;
    }
  },

  async hGetAll(key) {
    if (!redisClient) return null;
    try {
      return await redisClient.hGetAll(key);
    } catch (err) {
      logger.error({ err, key, event: 'redis_hgetall_error' }, 'Redis HGETALL error');
      return null;
    }
  },

  async zAdd(key, members) {
    if (!redisClient) return 0;
    try {
      return await redisClient.zAdd(key, members);
    } catch (err) {
      logger.error({ err, key, event: 'redis_zadd_error' }, 'Redis ZADD error');
      return 0;
    }
  },

  async zRem(key, members) {
    if (!redisClient) return 0;
    try {
      return await redisClient.zRem(key, members);
    } catch (err) {
      logger.error({ err, key, event: 'redis_zrem_error' }, 'Redis ZREM error');
      return 0;
    }
  },

  async zRange(key, start, stop) {
    if (!redisClient) return [];
    try {
      return await redisClient.zRange(key, start, stop);
    } catch (err) {
      logger.error({ err, key, event: 'redis_zrange_error' }, 'Redis ZRANGE error');
      return [];
    }
  },

  async zCard(key) {
    if (!redisClient) return 0;
    try {
      return await redisClient.zCard(key);
    } catch (err) {
      logger.error({ err, key, event: 'redis_zcard_error' }, 'Redis ZCARD error');
      return 0;
    }
  },

  async keys(pattern) {
    if (!redisClient) return [];
    try {
      return await redisClient.keys(pattern);
    } catch (err) {
      logger.error({ err, pattern, event: 'redis_keys_error' }, 'Redis KEYS error');
      return [];
    }
  },

  async expire(key, seconds) {
    if (!redisClient) return false;
    try {
      return await redisClient.expire(key, seconds);
    } catch (err) {
      logger.error({ err, key, event: 'redis_expire_error' }, 'Redis EXPIRE error');
      return false;
    }
  },
};

export { pubClient, subClient };
