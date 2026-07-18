import { query } from './pool.js';
import logger from '../utils/logger.js';

const migrations = [
  {
    name: '001_create_appeals_table',
    up: `
      CREATE TABLE IF NOT EXISTS appeals (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        message TEXT NOT NULL,
        status VARCHAR(20) DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected')),
        admin_response TEXT,
        admin_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
        created_at TIMESTAMP DEFAULT NOW(),
        reviewed_at TIMESTAMP
      );
    `,
  },
  {
    name: '002_create_coin_transactions_table',
    up: `
      CREATE TABLE IF NOT EXISTS coin_transactions (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        coins INTEGER NOT NULL,
        amount DECIMAL(10,2) NOT NULL DEFAULT 0,
        transaction_type VARCHAR(30) NOT NULL CHECK (transaction_type IN ('purchase', 'spend', 'gift_sent', 'gift_received', 'refund')),
        gift_type VARCHAR(30),
        recipient_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
        transaction_id VARCHAR(255),
        created_at TIMESTAMP DEFAULT NOW()
      );
    `,
  },
  {
    name: '003_add_user_columns',
    up: `
      ALTER TABLE users ADD COLUMN IF NOT EXISTS coins INTEGER DEFAULT 0;
      ALTER TABLE users ADD COLUMN IF NOT EXISTS looking_for VARCHAR(20) DEFAULT 'any' CHECK (looking_for IN ('male', 'female', 'any'));
      ALTER TABLE users ADD COLUMN IF NOT EXISTS role VARCHAR(20) DEFAULT 'user' CHECK (role IN ('user', 'admin', 'moderator'));
      ALTER TABLE users ADD COLUMN IF NOT EXISTS age_verified BOOLEAN DEFAULT FALSE;
      ALTER TABLE users ADD COLUMN IF NOT EXISTS banned_until TIMESTAMP;
      ALTER TABLE users ADD COLUMN IF NOT EXISTS ban_reason TEXT;
      ALTER TABLE users ADD COLUMN IF NOT EXISTS nickname VARCHAR(20);
      ALTER TABLE users ADD COLUMN IF NOT EXISTS display_name VARCHAR(20);
      ALTER TABLE users ADD COLUMN IF NOT EXISTS interests TEXT[] DEFAULT '{}';
      ALTER TABLE users ADD COLUMN IF NOT EXISTS gender VARCHAR(20) DEFAULT 'any' CHECK (gender IN ('male', 'female', 'any'));
      ALTER TABLE users ADD COLUMN IF NOT EXISTS location VARCHAR(50) DEFAULT 'any';
    `,
  },
  {
    name: '004_add_queue_columns',
    up: `
      ALTER TABLE queue ADD COLUMN IF NOT EXISTS looking_for VARCHAR(20) DEFAULT 'any';
      ALTER TABLE queue ADD COLUMN IF NOT EXISTS gender VARCHAR(20) DEFAULT 'any';
      ALTER TABLE queue ADD COLUMN IF NOT EXISTS location VARCHAR(50) DEFAULT 'any';
      ALTER TABLE queue ADD COLUMN IF NOT EXISTS interests TEXT[] DEFAULT '{}';
      ALTER TABLE queue ADD COLUMN IF NOT EXISTS nickname VARCHAR(20);
    `,
  },
  {
    name: '005_create_indexes',
    up: `
      -- User lookups
      CREATE INDEX IF NOT EXISTS idx_users_email ON users(email) WHERE email IS NOT NULL;
      CREATE INDEX IF NOT EXISTS idx_users_provider_id ON users(provider_id) WHERE provider_id IS NOT NULL;
      CREATE INDEX IF NOT EXISTS idx_users_banned_until ON users(banned_until) WHERE banned_until IS NOT NULL;
      CREATE INDEX IF NOT EXISTS idx_users_location ON users(location) WHERE location IS NOT NULL AND location != 'any';
      
      -- Matches
      CREATE INDEX IF NOT EXISTS idx_matches_user_a ON matches(user_a);
      CREATE INDEX IF NOT EXISTS idx_matches_user_b ON matches(user_b);
      CREATE INDEX IF NOT EXISTS idx_matches_channel_name ON matches(channel_name);
      CREATE INDEX IF NOT EXISTS idx_matches_created_at ON matches(created_at);
      CREATE INDEX IF NOT EXISTS idx_matches_active ON matches(ended_at) WHERE ended_at IS NULL;
      
      -- Chat messages
      CREATE INDEX IF NOT EXISTS idx_chat_messages_room_id ON chat_messages(room_id);
      CREATE INDEX IF NOT EXISTS idx_chat_messages_created_at ON chat_messages(created_at);
      
      -- Queue
      CREATE INDEX IF NOT EXISTS idx_queue_user_id ON queue(user_id) UNIQUE;
      CREATE INDEX IF NOT EXISTS idx_queue_joined_at ON queue(joined_at);
      
      -- Reports
      CREATE INDEX IF NOT EXISTS idx_user_reports_reported ON user_reports(reported_id, created_at);
      CREATE INDEX IF NOT EXISTS idx_user_reports_reporter ON user_reports(reporter_id, created_at);
      
      -- Coin transactions
      CREATE INDEX IF NOT EXISTS idx_coin_transactions_user ON coin_transactions(user_id, created_at);
      
      -- Activity tracking
      CREATE INDEX IF NOT EXISTS idx_user_activity_user_action ON user_activity(user_id, action, created_at);
      
      -- Moderation
      CREATE INDEX IF NOT EXISTS idx_moderation_logs_user ON moderation_logs(user_id, created_at);
      CREATE INDEX IF NOT EXISTS idx_flagged_users ON flagged_users(created_at);
      
      -- Appeals
      CREATE INDEX IF NOT EXISTS idx_appeals_status ON appeals(status) WHERE status = 'pending';
    `,
  },
];

/**
 * Run all pending migrations
 * Uses a migrations table to track what's been applied
 */
export async function runMigrations() {
  try {
    // Create migrations tracking table
    await query(`
      CREATE TABLE IF NOT EXISTS schema_migrations (
        name VARCHAR(100) PRIMARY KEY,
        applied_at TIMESTAMP DEFAULT NOW()
      )
    `);

    const { rows: applied } = await query(
      'SELECT name FROM schema_migrations ORDER BY name'
    );
    const appliedNames = new Set(applied.map(r => r.name));

    for (const migration of migrations) {
      if (appliedNames.has(migration.name)) {
        continue;
      }

      logger.info({ migration: migration.name }, 'Running migration');
      
      await query(migration.up);
      await query(
        'INSERT INTO schema_migrations (name) VALUES ($1)',
        [migration.name]
      );
      
      logger.info({ migration: migration.name }, 'Migration completed');
    }

    logger.info({ event: 'migrations_complete' }, 'All migrations up to date');
  } catch (err) {
    logger.error({ err, event: 'migration_failed' }, 'Migration failed');
    throw err;
  }
}
