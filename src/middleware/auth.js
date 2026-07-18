import jwt from 'jsonwebtoken';
import { env } from '../config/index.js';
import { cacheService } from '../services/cacheService.js';
import { query } from '../database/pool.js';
import { UnauthorizedError } from '../utils/errors.js';
import logger from '../utils/logger.js';

/**
 * JWT authentication middleware for Express routes
 */
export function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization || req.body?.token || req.query?.token;
  
  if (!authHeader) {
    return next(new UnauthorizedError('Missing authentication token'));
  }

  const token = authHeader.replace(/^Bearer\s*/i, '');
  
  verifyToken(token)
    .then(user => {
      req.user = user;
      next();
    })
    .catch(err => next(err));
}

/**
 * Admin role check middleware
 */
export function requireAdmin(req, res, next) {
  if (req.user?.role !== 'admin') {
    return next(new ForbiddenError('Admin access required'));
  }
  next();
}

/**
 * Socket.IO authentication middleware
 */
export function socketAuthMiddleware(socket, next) {
  const token = socket.handshake.auth.token || socket.handshake.query.token;
  
  if (!token) {
    return next(new Error('Authentication token required'));
  }

  verifyToken(token)
    .then(user => {
      if (user.banned_until && new Date(user.banned_until) > new Date()) {
        return next(new Error('Account is banned'));
      }

      socket.data.userId = user.id;
      socket.data.user = user;
      socket.data.lastFrameModeration = 0;
      socket.data.inQueue = false;
      
      next();
    })
    .catch(err => {
      logger.error({ err, event: 'socket_auth_failed' }, 'Socket authentication failed');
      next(new Error('Unauthorized'));
    });
}

/**
 * Verify JWT token and return user
 */
async function verifyToken(token) {
  try {
    const decoded = jwt.verify(token, env.JWT_SECRET);
    
    // Try cache first
    const cached = await cacheService.get(`user:${decoded.id}`);
    if (cached) {
      return cached;
    }
    
    // Fetch from database
    const { rows } = await query('SELECT * FROM users WHERE id = $1', [decoded.id]);
    
    if (!rows[0]) {
      throw new UnauthorizedError('User not found');
    }
    
    // Cache for future requests
    await cacheService.set(`user:${decoded.id}`, rows[0]);
    
    return rows[0];
  } catch (err) {
    if (err instanceof jwt.JsonWebTokenError) {
      throw new UnauthorizedError('Invalid token');
    }
    if (err instanceof jwt.TokenExpiredError) {
      throw new UnauthorizedError('Token expired');
    }
    throw err;
  }
}
