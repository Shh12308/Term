import pg from 'pg';
import { env } from '../config/index.js';
import logger from '../utils/logger.js';

const { Pool } = pg;

export const pool = new Pool({
  connectionString: env.DATABASE_URL,
  ssl: env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : undefined,
  max: 10,
  min: 1,
  // CRITICAL: Set lower than Neon's 5-minute timeout to prevent "unexpectedly terminated" errors
  idleTimeoutMillis: 10000, 
  connectionTimeoutMillis: 10000,
  // Recycle connections periodically to prevent memory leaks
  maxUses: 7500, 
});

// Only log actual critical pool errors, not routine disconnects
pool.on('error', (err) => {
  // Ignore "Connection terminated unexpectedly" as we handle it via idle timeout
  if (err.message?.includes('Connection terminated unexpectedly')) {
    return; 
  }
  console.error('❌ Critical database error:', err.message);
  logger.error({ err, event: 'db_critical_error' }, 'Critical database error');
});

/**
 * Execute a query
 */
export async function query(text, params) {
  const start = Date.now();
  try {
    const result = await pool.query(text, params);
    const duration = Date.now() - start;
    
    // Increased to 1000ms - serverless DBs naturally have higher latency
    if (duration > 1000) {
      logger.warn({ duration, query: text.substring(0, 100), event: 'slow_query' }, 'Slow query');
    }
    
    return result;
  } catch (err) {
    // Only log actual query syntax/permission errors, not connection drops
    if (!err.message?.includes('terminated') && !err.message?.includes('connect')) {
      logger.error({ err, query: text.substring(0, 100), event: 'query_error' }, 'Query failed');
    }
    throw err;
  }
}

/**
 * Execute a function within a database transaction
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
    logger.info({ dbTime: result.rows[0].now, event: 'db_connected' }, 'Database connected');
    return true;
  } catch (err) {
    console.error('❌ Database connection failed:', err.message);
    throw err;
  }
}

export default pool;
