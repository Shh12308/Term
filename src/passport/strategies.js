import passport from 'passport';
import { env } from '../config/index.js';
import { query } from '../database/pool.js';
import { cacheService } from '../services/cacheService.js';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import { Strategy as DiscordStrategy } from 'passport-discord';
import { Strategy as FacebookStrategy } from 'passport-facebook';
import logger from '../utils/logger.js';

// Serialize user to session
passport.serializeUser((user, done) => {
  done(null, user.id);
});

// Deserialize user from session
passport.deserializeUser(async (id, done) => {
  try {
    const user = await cacheService.getUser(id, async () => {
      const { rows } = await query('SELECT * FROM users WHERE id = $1', [id]);
      return rows[0] || null;
    });
    done(null, user);
  } catch (err) {
    done(err, null);
  }
});

// Google Strategy
if (env.GOOGLE_CLIENT_ID && env.GOOGLE_CLIENT_SECRET) {
  passport.use(
    new GoogleStrategy(
      {
        clientID: env.GOOGLE_CLIENT_ID,
        clientSecret: env.GOOGLE_CLIENT_SECRET,
        callbackURL: env.GOOGLE_CALLBACK_URL,
      },
      async (accessToken, refreshToken, profile, done) => {
        try {
          const email = profile.emails?.[0]?.value || null;
          const providerId = profile.id;
          const avatar = profile.photos?.[0]?.value || null;
          const username = profile.displayName || profile.username || email;

          const { rows } = await query('SELECT * FROM users WHERE email = $1', [email]);
          
          if (rows.length > 0) {
            const { rows: updated } = await query(
              `UPDATE users SET provider = 'google', provider_id = $1, username = $2, avatar = $3, updated_at = NOW()
               WHERE id = $4 RETURNING *`,
              [providerId, username, avatar, rows[0].id]
            );
            await cacheService.invalidateUser(rows[0].id);
            return done(null, updated[0]);
          }

          const { rows: created } = await query(
            `INSERT INTO users (username, email, provider, provider_id, avatar, created_at, updated_at)
             VALUES ($1, $2, 'google', $3, $4, NOW(), NOW()) RETURNING *`,
            [username, email, providerId, avatar]
          );
          return done(null, created[0]);
        } catch (err) {
          logger.error({ err, event: 'google_oauth_error' }, 'Google OAuth failed');
          done(err, null);
        }
      }
    )
  );
}

// Discord Strategy
if (env.DISCORD_CLIENT_ID && env.DISCORD_CLIENT_SECRET) {
  passport.use(
    new DiscordStrategy(
      {
        clientID: env.DISCORD_CLIENT_ID,
        clientSecret: env.DISCORD_CLIENT_SECRET,
        callbackURL: env.DISCORD_CALLBACK_URL,
        scope: ['identify', 'email'],
      },
      async (accessToken, refreshToken, profile, done) => {
        try {
          const email = profile.email || null;
          const providerId = profile.id;
          const avatar = profile.avatar
            ? `https://cdn.discordapp.com/avatars/${profile.id}/${profile.avatar}.png`
            : null;
          const username = profile.username || profile.displayName;

          const { rows } = await query('SELECT * FROM users WHERE email = $1', [email]);
          
          if (rows.length > 0) {
            const { rows: updated } = await query(
              `UPDATE users SET provider = 'discord', provider_id = $1, username = $2, avatar = $3, updated_at = NOW()
               WHERE id = $4 RETURNING *`,
              [providerId, username, avatar, rows[0].id]
            );
            await cacheService.invalidateUser(rows[0].id);
            return done(null, updated[0]);
          }

          const { rows: created } = await query(
            `INSERT INTO users (username, email, provider, provider_id, avatar, created_at, updated_at)
             VALUES ($1, $2, 'discord', $3, $4, NOW(), NOW()) RETURNING *`,
            [username, email, providerId, avatar]
          );
          return done(null, created[0]);
        } catch (err) {
          logger.error({ err, event: 'discord_oauth_error' }, 'Discord OAuth failed');
          done(err, null);
        }
      }
    )
  );
}

// Facebook Strategy
if (env.FACEBOOK_APP_ID && env.FACEBOOK_APP_SECRET) {
  passport.use(
    new FacebookStrategy(
      {
        clientID: env.FACEBOOK_APP_ID,
        clientSecret: env.FACEBOOK_APP_SECRET,
        callbackURL: env.FACEBOOK_CALLBACK_URL,
        profileFields: ['id', 'displayName', 'emails', 'photos'],
      },
      async (accessToken, refreshToken, profile, done) => {
        try {
          const email = profile.emails?.[0]?.value || null;
          const providerId = profile.id;
          const avatar = profile.photos?.[0]?.value || null;
          const username = profile.displayName || profile.username || email;

          const { rows } = await query('SELECT * FROM users WHERE email = $1', [email]);
          
          if (rows.length > 0) {
            const { rows: updated } = await query(
              `UPDATE users SET provider = 'facebook', provider_id = $1, username = $2, avatar = $3, updated_at = NOW()
               WHERE id = $4 RETURNING *`,
              [providerId, username, avatar, rows[0].id]
            );
            await cacheService.invalidateUser(rows[0].id);
            return done(null, updated[0]);
          }

          const { rows: created } = await query(
            `INSERT INTO users (username, email, provider, provider_id, avatar, created_at, updated_at)
             VALUES ($1, $2, 'facebook', $3, $4, NOW(), NOW()) RETURNING *`,
            [username, email, providerId, avatar]
          );
          return done(null, created[0]);
        } catch (err) {
          logger.error({ err, event: 'facebook_oauth_error' }, 'Facebook OAuth failed');
          done(err, null);
        }
      }
    )
  );
}

export default passport;
