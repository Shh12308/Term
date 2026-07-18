import http from 'http';
import { env, config } from './config/index.js';
import app from './app.js';
import { initSocketIO } from './sockets/index.js';
import { initRedis, isRedisConnected } from './services/redisService.js';
import { testConnection, runMigrations } from './database/migrations.js';
import { startQueueCleanup } from './jobs/cleanup.js';
import { startDailyPurge } from './jobs/dailyPurge.js';
import { startBanExpiryCheck } from './jobs/banExpiry.js';
import logger from './utils/logger.js';

// Setup Passport (separate file would be cleaner, but keeping it here for session config)
import session from 'express-session';
import pgSessionImport from 'connect-pg-simple';
import passport from 'passport';
import { pool } from './database/pool.js';
import './passport/strategies.js'; // Register strategies

const PGStore = pgSessionImport(session);

app.use(
  session({
    store: new PGStore({
      pool,
      tableName: 'user_sessions',
      createTableIfMissing: true,
    }),
    secret: env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      maxAge: 14 * 24 * 60 * 60 * 1000,
      httpOnly: true,
      secure: config.isProduction,
      sameSite: 'lax',
    },
  })
);

app.use(passport.initialize());
app.use(passport.session());

// Create HTTP server
const server = http.createServer(app);

// Initialize Socket.IO
const io = initSocketIO(server);

/**
 * Start the server
 */
async function startServer() {
  try {
    // Test database connection
    await testConnection();

    // Run migrations
    await runMigrations();

    // Initialize Redis
    const redisConnected = await initRedis();

    // Start background jobs
    startQueueCleanup();
    startDailyPurge();
    startBanExpiryCheck();

    // Start listening
    server.listen(env.PORT, () => {
      logger.info({
        port: env.PORT,
        env: env.NODE_ENV,
        redis: redisConnected ? 'connected' : 'not_configured',
        matchmaking: isRedisConnected() ? 'redis' : 'local',
        stripe: config.isStripeEnabled ? 'configured' : 'not_configured',
        coinbase: config.isCoinbaseEnabled ? 'configured' : 'not_configured',
        moderation: config.isModerationEnabled ? 'enabled' : 'disabled',
        event: 'server_started',
      }, `🚀 Server running on port ${env.PORT}`);

      console.log('');
      console.log('📱 Socket Events:');
      console.log('   • join_queue - Join matchmaking queue');
      console.log('   • leave_queue - Leave queue');
      console.log('   • queue_status - Check queue position');
      console.log('   • next - Skip current match');
      console.log('   • auto_requeue - Auto re-queue');
      console.log('   • message - Send chat message');
      console.log('   • video_frame - Send video frame');
      console.log('   • report_user - Report a user');
      console.log('   • join_room - Join a room');
      console.log('   • leave_room - Leave a room');
    });
  } catch (err) {
    logger.error({ err, event: 'server_start_failed' }, 'Failed to start server');
    process.exit(1);
  }
}

// Graceful shutdown
function gracefulShutdown(signal) {
  logger.info({ signal, event: 'shutdown_started' }, 'Starting graceful shutdown');
  
  server.close(() => {
    logger.info({ event: 'server_closed' }, 'HTTP server closed');
    process.exit(0);
  });

  // Force exit after 10 seconds
  setTimeout(() => {
    logger.error({ event: 'shutdown_timeout' }, 'Forced shutdown after timeout');
    process.exit(1);
  }, 10000);
}

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

// Handle uncaught exceptions
process.on('uncaughtException', (err) => {
  logger.error({ err, event: 'uncaught_exception' }, 'Uncaught exception');
  gracefulShutdown('uncaughtException');
});

process.on('unhandledRejection', (reason, promise) => {
  logger.error({ reason, event: 'unhandled_rejection' }, 'Unhandled rejection');
  gracefulShutdown('unhandledRejection');
});

// Start the server
startServer();

export { server, io };
