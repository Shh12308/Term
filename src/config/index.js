import { cleanEnv, str, num, bool, url, makeValidator } from 'envalid';

const portValidator = makeValidator((v) => {
  const n = parseInt(v, 10);
  if (isNaN(n) || n < 1 || n > 65535) throw new Error('Invalid port');
  return n;
});

export const env = cleanEnv(process.env, {
  NODE_ENV: str({ choices: ['development', 'production', 'test'], default: 'development' }),
  PORT: portValidator({ default: 5000 }),
  DATABASE_URL: url({ desc: 'PostgreSQL connection string' }),
  REDIS_URL: url({ desc: 'Redis connection string', default: '' }),
  
  JWT_SECRET: str({ desc: 'JWT signing secret' }),
  SESSION_SECRET: str({ desc: 'Session encryption secret' }),
  
  FRONTEND_URL: url({ desc: 'Frontend origin URL' }),
  
  OPENAI_API_KEY: str({ desc: 'OpenAI API key', default: '' }),
  AGORA_APP_ID: str({ desc: 'Agora application ID' }),
  AGORA_APP_CERTIFICATE: str({ desc: 'Agora app certificate' }),
  
  STRIPE_SECRET_KEY: str({ desc: 'Stripe secret key', default: '' }),
  STRIPE_WEBHOOK_SECRET: str({ desc: 'Stripe webhook secret', default: '' }),
  
  COINBASE_COMMERCE_API_KEY: str({ desc: 'Coinbase Commerce API key', default: '' }),
  COINBASE_COMMERCE_WEBHOOK_SECRET: str({ desc: 'Coinbase webhook secret', default: '' }),
  
  GOOGLE_CLIENT_ID: str({ desc: 'Google OAuth client ID', default: '' }),
  GOOGLE_CLIENT_SECRET: str({ desc: 'Google OAuth client secret', default: '' }),
  GOOGLE_CALLBACK_URL: url({ desc: 'Google OAuth callback', default: 'http://localhost:3000/auth/google/callback' }),
  
  DISCORD_CLIENT_ID: str({ desc: 'Discord client ID', default: '' }),
  DISCORD_CLIENT_SECRET: str({ desc: 'Discord client secret', default: '' }),
  DISCORD_CALLBACK_URL: url({ desc: 'Discord callback', default: 'http://localhost:3000/auth/discord/callback' }),
  
  FACEBOOK_APP_ID: str({ desc: 'Facebook app ID', default: '' }),
  FACEBOOK_APP_SECRET: str({ desc: 'Facebook app secret', default: '' }),
  FACEBOOK_CALLBACK_URL: url({ desc: 'Facebook callback', default: 'http://localhost:3000/auth/callback/facebook' }),
});

// Derived config
export const config = {
  isProduction: env.NODE_ENV === 'production',
  isDevelopment: env.NODE_ENV === 'development',
  
  // Moderation
  isModerationEnabled: env.OPENAI_API_KEY && 
    !env.OPENAI_API_KEY.includes('sk-xxxx') &&
    !env.OPENAI_API_KEY.includes('sk-test'),
  
  // Stripe
  isStripeEnabled: !!env.STRIPE_SECRET_KEY,
  
  // Coinbase
  isCoinbaseEnabled: !!env.COINBASE_COMMERCE_API_KEY,
  
  // Redis
  isRedisEnabled: !!env.REDIS_URL,
  
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
  
  // Video moderation
  videoModerationIntervalMs: 12000, // 12 seconds instead of 1 second
  
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
