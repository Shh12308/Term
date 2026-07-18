import { Router } from 'express';
import { query } from '../database/pool.js';
import { queueService } from '../services/queueService.js';
import { cacheService } from '../services/cacheService.js';
import { requireAuth } from '../middleware/auth.js';
import { validate } from '../middleware/validator.js';
import { 
  appealSchema, 
  adminBanSchema, 
  adminAppealResponseSchema 
} from '../middleware/validator.js';
import { getOnlineSocketId, getIO } from '../sockets/index.js';
import logger from '../utils/logger.js';

const router = Router();

// Get pending appeals
router.get('/appeals', requireAuth, async (req, res, next) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }

    const { rows } = await query(
      `SELECT a.*, u.username, u.email 
       FROM appeals a 
       JOIN users u ON a.user_id = u.id 
       WHERE a.status = 'pending' 
       ORDER BY a.created_at DESC`
    );

    res.json(rows);
  } catch (err) {
    next(err);
  }
});

// Respond to appeal
router.post('/appeals/:id/respond', requireAuth, validate(adminAppealResponseSchema), async (req, res, next) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }

    const { id } = req.params;
    const { approved, response } = req.validatedBody;

    const { rows } = await query('SELECT * FROM appeals WHERE id = $1', [id]);
    if (!rows.length) {
      return res.status(404).json({ error: 'Appeal not found' });
    }

    const appeal = rows[0];

    await query(
      'UPDATE appeals SET status = $1, admin_response = $2, admin_id = $3, reviewed_at = NOW() WHERE id = $4',
      [approved ? 'approved' : 'rejected', response, req.user.id, id]
    );

    if (approved) {
      await query(
        'UPDATE users SET banned_until = NULL, ban_reason = NULL WHERE id = $1',
        [appeal.user_id]
      );
      await query(
        'INSERT INTO moderation_logs (user_id, action, reason, created_at) VALUES ($1, $2, $3, NOW())',
        [appeal.user_id, 'appeal_approved', 'Appeal approved by admin']
      );
      await cacheService.invalidateUser(appeal.user_id);
    }

    logger.info({ appealId: id, approved, adminId: req.user.id, event: 'appeal_responded' }, 'Appeal responded');

    res.json({ ok: true });
  } catch (err) {
    next(err);
  }
});

// Search users
router.get('/users', requireAuth, async (req, res, next) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }

    const { query: searchQuery } = req.query;
    if (!searchQuery) {
      return res.status(400).json({ error: 'Search query required' });
    }

    const { rows } = await query(
      `SELECT id, username, email, banned_until, ban_reason 
       FROM users 
       WHERE username ILIKE $1 OR email ILIKE $1 
       LIMIT 20`,
      [`%${searchQuery}%`]
    );

    res.json({ users: rows });
  } catch (err) {
    next(err);
  }
});

// Ban user
router.post('/ban', requireAuth, validate(adminBanSchema), async (req, res, next) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }

    const { userId } = req.validatedBody;
    const banUntil = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);

    await query(
      'UPDATE users SET banned_until = $1, ban_reason = $2, updated_at = NOW() WHERE id = $3',
      [banUntil, 'Banned by admin', userId]
    );

    await query(
      'INSERT INTO moderation_logs (user_id, action, reason, created_at) VALUES ($1, $2, $3, NOW())',
      [userId, 'admin_ban', 'Banned by admin']
    );

    await cacheService.invalidateUser(userId);
    await queueService.remove(userId);

    // Disconnect user if online
    const socketId = await getOnlineSocketId(String(userId));
    if (socketId) {
      const io = getIO();
      if (io) {
        const targetSocket = io.sockets.sockets.get(socketId);
        if (targetSocket) {
          targetSocket.emit('banned', { reason: 'Banned by admin', until: banUntil, canAppeal: true });
          targetSocket.disconnect(true);
        }
      }
    }

    logger.info({ targetUserId: userId, adminId: req.user.id, event: 'admin_ban' }, 'User banned by admin');

    res.json({ ok: true });
  } catch (err) {
    next(err);
  }
});

// Unban user
router.post('/unban', requireAuth, validate(adminBanSchema), async (req, res, next) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }

    const { userId } = req.validatedBody;

    await query(
      'UPDATE users SET banned_until = NULL, ban_reason = NULL, updated_at = NOW() WHERE id = $1',
      [userId]
    );

    await query(
      'INSERT INTO moderation_logs (user_id, action, reason, created_at) VALUES ($1, $2, $3, NOW())',
      [userId, 'admin_unban', 'Unbanned by admin']
    );

    await cacheService.invalidateUser(userId);

    logger.info({ targetUserId: userId, adminId: req.user.id, event: 'admin_unban' }, 'User unbanned by admin');

    res.json({ ok: true });
  } catch (err) {
    next(err);
  }
});

// Get queue stats
router.get('/queue-stats', requireAuth, async (req, res, next) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }

    const stats = await queueService.getStats();
    res.json(stats);
  } catch (err) {
    next(err);
  }
});

export default router;
