import Redis from 'ioredis';
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
    pubClient = new Redis(env.REDIS_URL, {
      maxRetriesPerRequest: 3,
      retryStrategy(times) {
        if (times > 10) {
          logger.error({ event: 'redis_max_retries' }, 'Redis max reconnection attempts reached');
          return null; // Stop retrying
        }
        return Math.min(times * 100, 3000);
      },
      lazyConnect: true,
    });

    subClient = new Redis(env.REDIS_URL, {
      maxRetriesPerRequest: null, // Subscribers don't need retry limit
      lazyConnect: true,
    });

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
  return redisClient?.status === 'ready';
}

// Safe Redis operations with error handling
export const redis = {
  async get(key) {
    if (!redisClient) return null;
    try {
      const value = await redisClient.get(key);
      return value;
    } catch (err) {
      logger.error({ err, key, event: 'redis_get_error' }, 'Redis GET error');
      return null;
    }
  },

  async set(key, value, options = {}) {
    if (!redisClient) return false;
    try {
      if (options.EX) {
        await redisClient.setex(key, options.EX, value);
        return 'OK';
      }
      return await redisClient.set(key, value);
    } catch (err) {
      logger.error({ err, key, event: 'redis_set_error' }, 'Redis SET error');
      return false;
    }
  },

  async del(...keys) {
    if (!redisClient) return 0;
    try {
      return await redisClient.del(...keys);
    } catch (err) {
      logger.error({ err, keys, event: 'redis_del_error' }, 'Redis DEL error');
      return 0;
    }
  },

  async hSet(key, data) {
    if (!redisClient) return 0;
    try {
      return await redisClient.hset(key, data);
    } catch (err) {
      logger.error({ err, key, event: 'redis_hset_error' }, 'Redis HSET error');
      return 0;
    }
  },

  async hGetAll(key) {
    if (!redisClient) return null;
    try {
      return await redisClient.hgetall(key);
    } catch (err) {
      logger.error({ err, key, event: 'redis_hgetall_error' }, 'Redis HGETALL error');
      return null;
    }
  },

  async zAdd(key, members) {
    if (!redisClient) return 0;
    try {
      // ioredis accepts: zadd(key, score, member, score, member, ...) or zadd(key, [{score, value}])
      // Handle single member or array
      if (Array.isArray(members) && members.length > 0) {
        const args = members.flatMap(m => [m.score, m.value]);
        return await redisClient.zadd(key, ...args);
      }
      return 0;
    } catch (err) {
      logger.error({ err, key, event: 'redis_zadd_error' }, 'Redis ZADD error');
      return 0;
    }
  },

  async zRem(key, ...members) {
    if (!redisClient) return 0;
    try {
      return await redisClient.zrem(key, ...members);
    } catch (err) {
      logger.error({ err, key, event: 'redis_zrem_error' }, 'Redis ZREM error');
      return 0;
    }
  },

  async zRange(key, start, stop) {
    if (!redisClient) return [];
    try {
      return await redisClient.zrange(key, start, stop);
    } catch (err) {
      logger.error({ err, key, event: 'redis_zrange_error' }, 'Redis ZRANGE error');
      return [];
    }
  },

  async zCard(key) {
    if (!redisClient) return 0;
    try {
      return await redisClient.zcard(key);
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
