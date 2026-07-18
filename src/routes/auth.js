import { Router } from 'express';
import passport from 'passport';
import jwt from 'jsonwebtoken';
import { env } from '../config/index.js';
import { cacheService } from '../services/cacheService.js';
import { query } from '../database/pool.js';
import { authLimiter } from '../middleware/rateLimit.js';
import logger from '../utils/logger.js';
import geoip from 'geoip-lite';

const router = Router();

function signJwt(user) {
  return jwt.sign(
    { id: user.id, email: user.email, provider: user.provider },
    env.JWT_SECRET,
    { expiresIn: '14d' }
  );
}

// OAuth callback handler factory
function oauthCallback(provider) {
  return (req, res) => {
    const token = signJwt(req.user);
    res.redirect(`${env.FRONTEND_URL}/auth/callback?token=${token}`);
  };
}

// Google OAuth
router.get('/google', authLimiter, passport.authenticate('google', { scope: ['profile', 'email'] }));
router.get('/google/callback', authLimiter, passport.authenticate('google', { failureRedirect: '/auth/failure', session: true }), oauthCallback('google'));

// Discord OAuth
router.get('/discord', authLimiter, passport.authenticate('discord'));
router.get('/discord/callback', authLimiter, passport.authenticate('discord', { failureRedirect: '/auth/failure', session: true }), oauthCallback('discord'));

// Facebook OAuth
router.get('/facebook', authLimiter, passport.authenticate('facebook', { scope: ['email'] }));
router.get('/callback/facebook', authLimiter, passport.authenticate('facebook', { failureRedirect: '/auth/failure', session: true }), oauthCallback('facebook'));

// Get current user
router.get('/me', async (req, res, next) => {
  try {
    if (!req.user) {
      return res.status(401).json({ error: 'Not authenticated' });
    }

    const { rows } = await query(
      `SELECT *, 
              GREATEST(1, FLOOR(EXTRACT(EPOCH FROM (NOW() - created_at)) / 3600)) as level 
       FROM users WHERE id = $1`,
      [req.user.id]
    );
    
    let user = rows[0];
    
    // Auto-detect location if not set
    if (!user.location || user.location === 'any') {
      const ip = req.headers['x-forwarded-for']?.split(',')[0] || req.socket.remoteAddress;
      const geo = geoip.lookup(ip);
      const loc = geo?.country?.toLowerCase() || 'any';
      await query('UPDATE users SET location = $1 WHERE id = $2', [loc, req.user.id]);
      user.location = loc;
    }

    await cacheService.set(`user:${req.user.id}`, user);
    res.json({ authenticated: true, user });
  } catch (err) {
    next(err);
  }
});

// Auth failure
router.get('/failure', (req, res) => {
  const errorMsg = req.query.error || 'Unknown error';
  logger.error({ error: errorMsg, event: 'oauth_failure' }, 'OAuth authentication failed');
  res.status(401).json({ error: 'Authentication failed', details: errorMsg });
});

export default router;
