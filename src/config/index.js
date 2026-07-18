/**
 * Environment configuration with validation
 * No external dependencies required
 */

function requireEnv(key, defaultValue = undefined) {
  const value = process.env[key] ?? defaultValue;
  if (value === undefined) {
    throw new Error(`Missing required environment variable: ${key}`);
  }
  return value;
}

function requireUrl(key, defaultValue = undefined) {
  const value = requireEnv(key, defaultValue);
  try {
    new URL(value);
    return value;
  } catch {
    throw new Error(`Invalid URL for ${key}: ${value}`);
  }
}

function requirePort(key, defaultValue = 5000) {
  const value = parseInt(process.env[key] ?? String(defaultValue), 10);
  if (isNaN(value) || value < 1 || value > 65535) {
    throw new Error(`Invalid port for ${key}: ${process.env[key]}`);
  }
  return value;
}

function requireChoice(key, choices, defaultValue = undefined) {
  const value = requireEnv(key, defaultValue);
  if (!choices.includes(value)) {
    throw new Error(`Invalid value for ${key}: "${value}". Must be one of: ${choices.join(', ')}`);
  }
  return value;
}

// Validate all required environment variables at startup
export const env = {
  NODE_ENV: requireChoice('NODE_ENV', ['development', 'production', 'test'], 'development'),
  PORT: requirePort('PORT', 5000),
  DATABASE_URL: requireUrl('DATABASE_URL'),
  REDIS_URL: process.env.REDIS_URL || '',
  
  // CRITICAL: No fallback - fail fast if missing
  JWT_SECRET: requireEnv('JWT_SECRET'),
  SESSION_SECRET: requireEnv('SESSION_SECRET'),
  
  FRONTEND_URL: requireUrl('FRONTEND_URL'),
  
  // Optional with empty defaults
  OPENAI_API_KEY: process.env.OPENAI_API_KEY || '',
  AGORA_APP_ID: requireEnv('AGORA_APP_ID'),
  AGORA_APP_CERTIFICATE: requireEnv('AGORA_APP_CERTIFICATE'),
  
  STRIPE_SECRET_KEY: process.env.STRIPE_SECRET_KEY || '',
  STRIPE_WEBHOOK_SECRET: process.env.STRIPE_WEBHOOK_SECRET || '',
  
  COINBASE_COMMERCE_API_KEY: process.env.COINBASE_COMMERCE_API_KEY || '',
  COINBASE_COMMERCE_WEBHOOK_SECRET: process.env.COINBASE_COMMERCE_WEBHOOK_SECRET || '',
  
  GOOGLE_CLIENT_ID: process.env.GOOGLE_CLIENT_ID || '',
  GOOGLE_CLIENT_SECRET: process.env.GOOGLE_CLIENT_SECRET || '',
  GOOGLE_CALLBACK_URL: process.env.GOOGLE_CALLBACK_URL || 'http://localhost:3000/auth/google/callback',
  
  DISCORD_CLIENT_ID: process.env.DISCORD_CLIENT_ID || '',
  DISCORD_CLIENT_SECRET: process.env.DISCORD_CLIENT_SECRET || '',
  DISCORD_CALLBACK_URL: process.env.DISCORD_CALLBACK_URL || 'http://localhost:3000/auth/discord/callback',
  
  FACEBOOK_APP_ID: process.env.FACEBOOK_APP_ID || '',
  FACEBOOK_APP_SECRET: process.env.FACEBOOK_APP_SECRET || '',
  FACEBOOK_CALLBACK_URL: process.env.FACEBOOK_CALLBACK_URL || 'http://localhost:3000/auth/callback/facebook',
};

// Derived configuration
export const config = {
  isProduction: env.NODE_ENV === 'production',
  isDevelopment: env.NODE_ENV === 'development',
  
  // Moderation - check if key looks valid
  isModerationEnabled: Boolean(
    env.OPENAI_API_KEY && 
    !env.OPENAI_API_KEY.includes('sk-xxxx') &&
    !env.OPENAI_API_KEY.includes('sk-test') &&
    env.OPENAI_API_KEY.startsWith('sk-')
  ),
  
  // Payment providers
  isStripeEnabled: Boolean(env.STRIPE_SECRET_KEY),
  isCoinbaseEnabled: Boolean(env.COINBASE_COMMERCE_API_KEY),
  
  // Redis
  isRedisEnabled: Boolean(env.REDIS_URL),
  
  // Matchmaking
  matchWeights: {
    location: 40,
    interests: 30,
    freshness: 20,
    gender: 10,
  },
  antiRepeatWindowHours: 2,
  maxCandidatesToScan: 100,
  matchLockTTL: 5,
  
  // User limits
  maxInterests: 5,
  maxNicknameLength: 20,
  minAgeForVideo: 18,
  
  // Moderation
  banHours: 750,
  unbanPrice: 5.99,
  
  // Video moderation - 12 seconds instead of 1
  videoModerationIntervalMs: 12000,
  
  // Gift costs
  giftCoinCosts: {
    rose: 10,
    heart: 25,
    star: 50,
    diamond: 100,
    crown: 200,
    rocket: 500,
  },
};

// Log configuration status on load (after validation passes)
console.log('✅ Environment configuration validated');
console.log(`   Environment: ${env.NODE_ENV}`);
console.log(`   Redis: ${config.isRedisEnabled ? '✅' : '⚠️  '} ${config.isRedisEnabled ? 'Enabled' : 'Disabled'}`);
console.log(`   Stripe: ${config.isStripeEnabled ? '✅' : '⚠️  '} ${config.isStripeEnabled ? 'Enabled' : 'Disabled'}`);
console.log(`   Coinbase: ${config.isCoinbaseEnabled ? '✅' : '⚠️  '} ${config.isCoinbaseEnabled ? 'Enabled' : 'Disabled'}`);
console.log(`   Moderation: ${config.isModerationEnabled ? '✅' : '⚠️  '} ${config.isModerationEnabled ? 'Enabled' : 'Disabled'}`);
