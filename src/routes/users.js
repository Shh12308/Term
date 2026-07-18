import { Router } from 'express';
import { query } from '../database/pool.js';
import { cacheService } from '../services/cacheService.js';
import { moderationService } from '../services/moderationService.js';
import { requireAuth } from '../middleware/auth.js';
import { validate } from '../middleware/validator.js';
import { 
  preferencesSchema, 
  ageVerificationSchema, 
  displayNameSchema, 
  avatarSchema 
} from '../middleware/validator.js';
import { config } from '../config/index.js';
import { getClientIp } from '../utils/helpers.js';
import geoip from 'geoip-lite';
import logger from '../utils/logger.js';

const router = Router();

// Get user profile
router.get('/profile', requireAuth, async (req, res, next) => {
  try {
    const { rows } = await query(
      `SELECT id, username, email, provider, avatar, gender, looking_for, location, 
              interests, nickname, display_name, age_verified, created_at, updated_at, 
              coins, role, 
              GREATEST(1, FLOOR(EXTRACT(EPOCH FROM (NOW() - created_at)) / 3600)) as level 
       FROM users WHERE id = $1`,
      [req.user.id]
    );
    
    if (!rows.length) {
      return res.status(404).json({ error: 'User not found' });
    }

    const user = rows[0];
    await cacheService.set(`user:${user.id}`, user);
    
    res.json({
      ...user,
      display_name: user.display_name || user.username,
      is_admin: user.role === 'admin',
    });
  } catch (err) {
    next(err);
  }
});

// Update preferences
router.post('/preferences', requireAuth, validate(preferencesSchema), async (req, res, next) => {
  try {
    const { gender, looking_for, location, interests, nickname } = req.validatedBody;
    
    // Check ban status
    if (req.user.banned_until && new Date(req.user.banned_until) > new Date()) {
      return res.status(403).json({ error: 'Account banned' });
    }

    // Auto-detect location if needed
    let finalLocation = location;
    if (!finalLocation || finalLocation === 'any') {
      const ip = getClientIp(req);
      const geo = geoip.lookup(ip);
      finalLocation = geo?.country?.toLowerCase() || 'any';
    }

    await query(
      `UPDATE users SET gender = $1, looking_for = $2, location = $3, interests = $4, 
       nickname = $5, updated_at = NOW() WHERE id = $6`,
      [gender, looking_for, finalLocation, interests, nickname, req.user.id]
    );

    const updatedUser = { ...req.user, gender, looking_for, location: finalLocation, interests, nickname };
    await cacheService.set(`user:${req.user.id}`, updatedUser);

    res.json({ ok: true, locationUsed: finalLocation });
  } catch (err) {
    next(err);
  }
});

// Verify age
router.post('/verify-age', requireAuth, validate(ageVerificationSchema), async (req, res, next) => {
  try {
    const { age } = req.validatedBody;
    
    if (age < config.minAgeForVideo) {
      return res.status(400).json({ 
        error: `You must be at least ${config.minAgeForVideo} to use video features` 
      });
    }

    await query(
      'UPDATE users SET age_verified = $1, updated_at = NOW() WHERE id = $2',
      [true, req.user.id]
    );

    const updatedUser = { ...req.user, age_verified: true };
    await cacheService.set(`user:${req.user.id}`, updatedUser);

    res.json({ ok: true });
  } catch (err) {
    next(err);
  }
});

// Update display name
router.post('/display-name', requireAuth, validate(displayNameSchema), async (req, res, next) => {
  try {
    const { display_name } = req.validatedBody;

    // Moderate display name
    if (config.isModerationEnabled) {
      const mod = await moderationService.checkText(display_name);
      if (mod.flagged) {
        return res.status(400).json({ error: 'Display name contains inappropriate content' });
      }
    }

    await query(
      'UPDATE users SET username = $1, display_name = $1, updated_at = NOW() WHERE id = $2',
      [display_name, req.user.id]
    );

    const updatedUser = { ...req.user, username: display_name, display_name };
    await cacheService.set(`user:${req.user.id}`, updatedUser);

    res.json({ ok: true });
  } catch (err) {
    next(err);
  }
});

// Update avatar
router.post('/avatar', requireAuth, validate(avatarSchema), async (req, res, next) => {
  try {
    const { avatarBase64 } = req.validatedBody;
    const sharp = (await import('sharp')).default;

    const buffer = Buffer.from(avatarBase64.split(',')[1], 'base64');
    const metadata = await sharp(buffer).metadata();

    if (metadata.width > 500 || metadata.height > 500) {
      return res.status(400).json({ error: 'Avatar must be at most 500x500 pixels' });
    }

    if (!['jpeg', 'jpg', 'png', 'webp'].includes(metadata.format)) {
      return res.status(400).json({ error: 'Avatar must be in JPEG, PNG, or WebP format' });
    }

    // Moderate avatar
    if (config.isModerationEnabled) {
      const mod = await moderationService.checkImage(avatarBase64);
      if (mod.flagged) {
        return res.status(400).json({ error: 'Avatar contains inappropriate content' });
      }
    }

    const processedImage = await sharp(buffer)
      .resize({ width: 200, height: 200, fit: 'cover' })
      .jpeg({ quality: 80 })
      .toBuffer();

    const processedBase64 = `data:image/jpeg;base64,${processedImage.toString('base64')}`;

    await query(
      'UPDATE users SET avatar = $1, updated_at = NOW() WHERE id = $2',
      [processedBase64, req.user.id]
    );

    const updatedUser = { ...req.user, avatar: processedBase64 };
    await cacheService.set(`user:${req.user.id}`, updatedUser);

    res.json({ ok: true, avatar: processedBase64 });
  } catch (err) {
    next(err);
  }
});

export default router;
