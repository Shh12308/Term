import pg from 'pg';
import { env } from '../config/index.js';
import logger from '../utils/logger.js';

const { Pool } = pg;

export const pool = new Pool({
  connectionString: env.DATABASE_URL,
  ssl: env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : undefined,
  max: 20,
  min: 2,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000,
});

pool.on('connect', (client) => {
  logger.debug({ event: 'db_connect' }, 'New database connection');
});

pool.on('error', (err) => {
  logger.error({ err, event: 'db_error' }, 'Unexpected database error');
});

pool.on('remove', (client) => {
  logger.debug({ event: 'db_remove' }, 'Database connection removed');
});

/**
 * Execute a query with optional transaction support
 */
export async function query(text, params, options = {}) {
  const start = Date.now();
  try {
    const result = await pool.query(text, params);
    const duration = Date.now() - start;
    
    if (duration > 100) {
      logger.warn({ 
        duration, 
        query: text.substring(0, 100),
        event: 'slow_query' 
      }, 'Slow query detected');
    }
    
    return result;
  } catch (err) {
    logger.error({ 
      err, 
      query: text.substring(0, 100),
      params: options.logParams ? params : undefined,
      event: 'query_error' 
    }, 'Query failed');
    throw err;
  }
}

/**
 * Execute a function within a database transaction
 * Handles commit/rollback automatically
 */
export async function withTransaction(fn) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const result = await fn(client);
    await client.query('COMMIT');
    return result;
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

/**
 * Test database connection
 */
export async function testConnection() {
  try {
    const result = await pool.query('SELECT NOW() as now');
    logger.info({ 
      dbTime: result.rows[0].now,
      event: 'db_connected' 
    }, 'Database connected successfully');
    return true;
  } catch (err) {
    logger.error({ err, event: 'db_connection_failed' }, 'Database connection failed');
    throw err;
  }
}

export default pool;
