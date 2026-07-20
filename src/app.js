import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import { env, config } from './config/index.js';
import { generalLimiter } from './middleware/rateLimit.js';
import { errorHandler, notFoundHandler } from './middleware/errorHandler.js';
import logger from './utils/logger.js';
import { generateRequestId } from './utils/helpers.js';

// Import routes
import authRoutes from './routes/auth.js';
import userRoutes from './routes/users.js';
import adminRoutes from './routes/admin.js';
import paymentRoutes from './routes/payments.js';
import queueRoutes from './routes/queue.js';
import { matchService } from './services/matchService.js';

const app = express();

// Security headers
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "'unsafe-inline'", 'https://apis.google.com'],
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", 'data:', 'https:'],
        connectSrc: ["'self'", 'wss:', 'https://api.openai.com'],
      },
    },
  })
);

app.set('trust proxy', 1);

app.use(
  cors({
    origin: env.FRONTEND_URL,
    credentials: true,
  })
);

app.use((req, res, next) => {
  req.id = generateRequestId();
  next();
});

app.use(generalLimiter);
app.use(express.json({ limit: '5mb' }));

app.use((req, res, next) => {
  logger.debug({ method: req.method, path: req.path, requestId: req.id, event: 'request' }, `${req.method} ${req.path}`);
  next();
});

// Health check
app.get('/health', (req, res) => {
  res.json({ ok: true, env: env.NODE_ENV, timestamp: new Date().toISOString(), uptime: process.uptime() });
});

// Root route
app.get('/', (req, res) => {
  res.status(200).send(`
    <h1>🚀 Omevo Backend is Running</h1>
    <p>Status: <strong>Online</strong></p>
    <p>Time: ${new Date().toISOString()}</p>
    <hr>
    <p><strong>Configuration Status:</strong></p>
    <ul>
      <li>Environment: ${env.NODE_ENV}</li>
      <li>Redis: ${config.isRedisEnabled ? '✅ Configured' : '⚠️ Not Configured'}</li>
      <li>Stripe: ${config.isStripeEnabled ? '✅ Configured' : '⚠️ Not Configured'}</li>
      <li>Coinbase: ${config.isCoinbaseEnabled ? '✅ Configured' : '⚠️ Not Configured'}</li>
      <li>Moderation: ${config.isModerationEnabled ? '✅ Enabled' : '⚠️ Disabled'}</li>
    </ul>
    <p><a href="/auth/google">Login with Google</a></p>
  `);
});

// Mount routes
app.use('/auth', authRoutes);

// User routes - mount at BOTH paths for frontend compatibility
app.use('/api/user', userRoutes);
app.use('/user', userRoutes); // Alias without /api prefix

app.use('/api/admin', adminRoutes);
app.use('/api', paymentRoutes);
app.use('/queue', queueRoutes);

// Match history endpoint (frontend might call this directly)
app.get('/api/user/match-history', async (req, res, next) => {
  try {
    if (!req.user) return res.status(401).json({ error: 'Authentication required' });
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const result = await matchService.getHistory(req.user.id, page, limit);
    res.json(result);
  } catch (err) {
    next(err);
  }
});

// 404 handler
app.use(notFoundHandler);

// Error handler
app.use(errorHandler);

export default app;
