import { query } from './pool.js';

/**
 * Safely create an index only if table/column exist and index doesn't exist
 */
async function safeCreateIndex(indexName, table, column, where = '') {
  try {
    const { rows: tableExists } = await query(
      `SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = $1)`,
      [table]
    );
    if (!tableExists[0].exists) return;

    const { rows: colExists } = await query(
      `SELECT EXISTS (SELECT FROM information_schema.columns WHERE table_name = $1 AND column_name = $2)`,
      [table, column]
    );
    if (!colExists[0].exists) return;

    const { rows: idxExists } = await query(
      `SELECT EXISTS (SELECT FROM pg_indexes WHERE indexname = $1)`,
      [indexName]
    );
    if (idxExists[0].exists) return;

    await query(`CREATE INDEX ${indexName} ON ${table}(${column}) ${where}`);
    console.log(`   ✅ ${indexName}`);
  } catch (err) {
    console.log(`   ⚠️  ${indexName}: ${err.message.substring(0, 60)}`);
  }
}

/**
 * Safely add column if it doesn't exist
 */
async function safeAddColumn(table, column, type, defaultVal = '') {
  try {
    const { rows: exists } = await query(
      `SELECT EXISTS (SELECT FROM information_schema.columns WHERE table_name = $1 AND column_name = $2)`,
      [table, column]
    );
    if (exists[0].exists) return;

    await query(`ALTER TABLE ${table} ADD COLUMN ${column} ${type} ${defaultVal}`);
    console.log(`   ✅ Added ${table}.${column}`);
  } catch (err) {
    console.log(`   ⚠️  ${table}.${column}: ${err.message.substring(0, 60)}`);
  }
}

const migrations = [
  {
    name: '001_fix_chat_messages',
    up: async () => {
      console.log('   Adding room_id to chat_messages...');
      await safeAddColumn('chat_messages', 'room_id', 'TEXT');
    },
  },
  {
    name: '002_fix_user_activity',
    up: async () => {
      console.log('   Adding action/metadata to user_activity...');
      await safeAddColumn('user_activity', 'action', 'VARCHAR(50)');
      await safeAddColumn('user_activity', 'metadata', 'TEXT');
    },
  },
  {
    name: '003_fix_coin_transactions',
    up: async () => {
      console.log('   Adding missing columns to coin_transactions...');
      await safeAddColumn('coin_transactions', 'transaction_type', 'VARCHAR(30)');
      await safeAddColumn('coin_transactions', 'gift_type', 'VARCHAR(30)');
      await safeAddColumn('coin_transactions', 'recipient_id', 'INTEGER');
    },
  },
  {
    name: '004_create_missing_tables',
    up: async () => {
      console.log('   Creating missing tables...');

      await query(`
        CREATE TABLE IF NOT EXISTS user_reports (
          id SERIAL PRIMARY KEY,
          reporter_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
          reported_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
          reason TEXT NOT NULL,
          room_id TEXT,
          created_at TIMESTAMP DEFAULT NOW()
        )
      `).then(() => console.log('   ✅ user_reports'));

      await query(`
        CREATE TABLE IF NOT EXISTS moderation_logs (
          id SERIAL PRIMARY KEY,
          user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
          action VARCHAR(50) NOT NULL,
          reason TEXT,
          created_at TIMESTAMP DEFAULT NOW()
        )
      `).then(() => console.log('   ✅ moderation_logs'));

      await query(`
        CREATE TABLE IF NOT EXISTS flagged_users (
          id SERIAL PRIMARY KEY,
          user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
          reason TEXT,
          created_at TIMESTAMP DEFAULT NOW()
        )
      `).then(() => console.log('   ✅ flagged_users'));

      await query(`
        CREATE TABLE IF NOT EXISTS room_activity (
          id SERIAL PRIMARY KEY,
          user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
          room_id TEXT NOT NULL,
          action VARCHAR(30) NOT NULL,
          created_at TIMESTAMP DEFAULT NOW()
        )
      `).then(() => console.log('   ✅ room_activity'));
    },
  },
  {
    name: '005_create_indexes',
    up: async () => {
      console.log('   Creating indexes...');

      // Users
      await safeCreateIndex('idx_users_banned_until', 'users', 'banned_until', 'WHERE banned_until IS NOT NULL');
      await safeCreateIndex('idx_users_role', 'users', 'role');
      
      // Matches
      await safeCreateIndex('idx_matches_user_a', 'matches', 'user_a');
      await safeCreateIndex('idx_matches_user_b', 'matches', 'user_b');
      await safeCreateIndex('idx_matches_created_at', 'matches', 'created_at');
      await safeCreateIndex('idx_matches_active', 'matches', 'ended_at', 'WHERE ended_at IS NULL');

      // Chat messages
      await safeCreateIndex('idx_chat_messages_room_id', 'chat_messages', 'room_id');
      await safeCreateIndex('idx_chat_messages_created_at', 'chat_messages', 'created_at');

      // Queue (idx_queue_joined_at already exists)
      await safeCreateIndex('idx_queue_looking_for', 'queue', 'looking_for');

      // Reports
      await safeCreateIndex('idx_user_reports_reported', 'user_reports', 'reported_id');
      await safeCreateIndex('idx_user_reports_reporter', 'user_reports', 'reporter_id');

      // Coin transactions
      await safeCreateIndex('idx_coin_transactions_user', 'coin_transactions', 'user_id');

      // Activity
      await safeCreateIndex('idx_user_activity_action', 'user_activity', 'action');

      // Moderation
      await safeCreateIndex('idx_moderation_logs_user', 'moderation_logs', 'user_id');
      await safeCreateIndex('idx_flagged_users_created', 'flagged_users', 'created_at');

      // Appeals
      await safeCreateIndex('idx_appeals_status', 'appeals', 'status', "WHERE status = 'pending'");
    },
  },
];

/**
 * Run all pending migrations
 */
export async function runMigrations() {
  try {
    // Ensure schema_migrations table exists
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

      console.log(`🔄 ${migration.name}`);

      try {
        if (typeof migration.up === 'function') {
          await migration.up();
        } else if (typeof migration.up === 'string') {
          await query(migration.up);
        }

        await query(
          'INSERT INTO schema_migrations (name) VALUES ($1)',
          [migration.name]
        );
        console.log(`✅ Done: ${migration.name}\n`);
      } catch (err) {
        console.error(`❌ Failed: ${migration.name}`);
        console.error(`   ${err.message}`);
        throw err;
      }
    }

    console.log('✅ All migrations up to date\n');
  } catch (err) {
    console.error('❌ Migration failed:', err.message);
    throw err;
  }
}
