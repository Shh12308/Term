import express from "express";
import dotenv from "dotenv";
dotenv.config();

import cookieParser from "cookie-parser";
import { PrismaClient } from "@prisma/client";
import argon2 from "argon2";
import jwt from "jsonwebtoken";
import passport from "passport";
import GoogleStrategy from "passport-google-oauth20";
import cors from "cors";
import Stripe from "stripe";
import bodyParser from "body-parser";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import morgan from "morgan";
import winston from "winston";
import nodemailer from "nodemailer";
import redis from "redis";
import axios from "axios";
import { v4 as uuidv4 } from "uuid";

import { S3Client, PutObjectCommand, GetObjectCommand } from "@aws-sdk/client-s3";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";
import { MediaConvertClient, CreateJobCommand } from "@aws-sdk/client-mediaconvert";

import { MeiliSearch } from "meilisearch";
import fetch from "node-fetch";
import crypto from "crypto";
import { CloudFrontClient, CreateInvalidationCommand } from "@aws-sdk/client-cloudfront";

const prisma = new PrismaClient();

/* -----------------------------
   Redis setup for caching and rate limiting
   ----------------------------- */
const redisClient = redis.createClient({
  url: process.env.REDIS_URL || "redis://localhost:6379"
});
redisClient.on("error", (err) => logger.error("Redis error:", err));
redisClient.connect();

/* -----------------------------
   Environment variables
   ----------------------------- */
const {
  DATABASE_URL,
  JWT_SECRET,
  REFRESH_TOKEN_SECRET,
  GOOGLE_CLIENT_ID,
  GOOGLE_CLIENT_SECRET,
  SERVER_BASE_URL,
  REDIRECT_URI,
  STRIPE_SECRET_KEY,
  STRIPE_WEBHOOK_SECRET,
  SMTP_HOST,
  SMTP_PORT,
  SMTP_USER,
  SMTP_PASS,
  CORS_ORIGINS,
  NODE_ENV,
  PORT,
  AWS_ACCESS_KEY_ID,
  AWS_SECRET_ACCESS_KEY,
  AWS_REGION,
  S3_BUCKET_NAME,
  MEDIACONVERT_ROLE_ARN,
  MEDIACONVERT_ENDPOINT,
  WATERMARK_LOGO_S3,
  MEILISEARCH_HOST,
  MEILISEARCH_API_KEY,
  CLOUDFRONT_DOMAIN,
  CLOUDFRONT_KEY_PAIR_ID,
  CLOUDFRONT_PRIVATE_KEY,
  ONE_SIGNAL_APP_ID,
  ONE_SIGNAL_API_KEY,
  STRIPE_BASIC_PRICE_ID,
  STRIPE_STANDARD_PRICE_ID,
  STRIPE_PREMIUM_PRICE_ID,
  STRIPE_AVOD_PRICE_ID,
  RAW_UPLOAD_BUCKET,
  PROCESSED_BUCKET,
  TMDB_API_KEY,
  REDIS_URL
} = process.env;

/* -----------------------------
   Third-party clients
   ----------------------------- */
const stripe = new Stripe(STRIPE_SECRET_KEY || "", { apiVersion: "2022-11-15" });

const tierRenditions = {
  free: ["_480p"],
  basic: ["_480p", "_720p"],
  standard: ["_480p", "_720p", "_1080p"],
  premium: ["_480p", "_720p", "_1080p", "_2k", "_4k", "_6k", "_8k"],
};

const s3 = new S3Client({
  region: AWS_REGION,
  credentials: { accessKeyId: AWS_ACCESS_KEY_ID, secretAccessKey: AWS_SECRET_ACCESS_KEY },
});

const cloudfront = new CloudFrontClient({
  region: AWS_REGION,
  credentials: { accessKeyId: AWS_ACCESS_KEY_ID, secretAccessKey: AWS_SECRET_ACCESS_KEY },
});

const mediaconvert = new MediaConvertClient({
  region: AWS_REGION,
  credentials: { accessKeyId: AWS_ACCESS_KEY_ID, secretAccessKey: AWS_SECRET_ACCESS_KEY },
  endpoint: MEDIACONVERT_ENDPOINT || undefined
});

const meili = MEILISEARCH_HOST ? new MeiliSearch({ host: MEILISEARCH_HOST, apiKey: MEILISEARCH_API_KEY }) : null;

/* -----------------------------
   Logger
   ----------------------------- */
const logger = winston.createLogger({
  level: NODE_ENV === "production" ? "info" : "debug",
  format: winston.format.combine(winston.format.timestamp(), winston.format.json()),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: "logs/error.log", level: "error" }),
    new winston.transports.File({ filename: "logs/combined.log" })
  ]
});

/* -----------------------------
   Security and rate limiting helpers
   ----------------------------- */
export const checkLoginLock = async (email) => {
  const key = `login_fail:${email}`;
  const attempts = await redisClient.get(key);
  if (attempts && Number(attempts) >= 5) {
    throw new Error("Account locked. Try again later.");
  }
};

export const recordLoginFail = async (email) => {
  const key = `login_fail:${email}`;
  await redisClient.multi()
    .incr(key)
    .expire(key, 900) // 15 min
    .exec();
};

export const clearLoginFails = async (email) => {
  await redisClient.del(`login_fail:${email}`);
};

export const isBreachedPassword = async (password) => {
  const sha1 = crypto.createHash("sha1").update(password).digest("hex");
  const prefix = sha1.slice(0, 5);
  const suffix = sha1.slice(5);

  const res = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`);
  const text = await res.text();

  return text.includes(suffix);
};

/* -----------------------------
   App setup
   ----------------------------- */
const app = express();
app.set("trust proxy", 1);

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
    },
  },
}));
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(morgan("combined", { stream: { write: (msg) => logger.info(msg.trim()) } }));
const allowed = (CORS_ORIGINS || "http://localhost:3000").split(",");
app.use(cors({ origin: allowed, credentials: true }));

// Advanced rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: "Too many requests from this IP, please try again later",
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(limiter);

// Auth-specific rate limiting
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // Limit each IP to 5 auth requests per windowMs
  message: "Too many authentication attempts, please try again later",
  standardHeaders: true,
  legacyHeaders: false,
});

/* -----------------------------
   Passport Google OAuth
   ----------------------------- */
const serverBase = SERVER_BASE_URL || `http://localhost:${PORT || 5000}`;
const googleCallback = `${serverBase}/api/auth/google/callback`;

passport.use(new GoogleStrategy.Strategy({
  clientID: GOOGLE_CLIENT_ID,
  clientSecret: GOOGLE_CLIENT_SECRET,
  callbackURL: googleCallback
}, async (accessToken, refreshToken, profile, done) => {
  try {
    const email = profile.emails?.[0]?.value;
    if (!email) return done(new Error("No email"), null);
    let user = await prisma.user.findUnique({ where: { email } });
    if (!user) {
      user = await prisma.user.create({
        data: {
          googleId: profile.id,
          name: profile.displayName || email.split("@")[0],
          email,
          picture: profile.photos?.[0]?.value || null,
          subscriptionType: "free",
          role: "user"
        }
      });
    } else if (!user.googleId) {
      user = await prisma.user.update({ where: { email }, data: { googleId: profile.id, picture: profile.photos?.[0]?.value || user.picture } });
    }
    return done(null, user);
  } catch (err) {
    logger.error("Google strategy error", err);
    return done(err, null);
  }
}));
app.use(passport.initialize());

/* -----------------------------
   JWT helpers & RBAC
   ----------------------------- */
const signRefreshToken = (payload) =>
  jwt.sign(payload, REFRESH_TOKEN_SECRET || "refresh_secret", { expiresIn: "7d" });

const signToken = (payload, expiresIn = "7d") => jwt.sign(payload, JWT_SECRET || "secret", { expiresIn });
const verifyToken = (token) => jwt.verify(token, JWT_SECRET || "secret");

const requireAuth = async (req, res, next) => {
  try {
    const header = req.headers.authorization || req.cookies?.token;
    if (!header) return res.status(401).json({ error: "Missing token" });
    const token = header.startsWith("Bearer ") ? header.split(" ")[1] : header;
    const decoded = verifyToken(token);
    const user = await prisma.user.findUnique({ where: { id: decoded.id } });
    if (!user) return res.status(404).json({ error: "User not found" });
    if (user.isBanned) return res.status(403).json({ error: "Banned" });
    
    // Check if token version matches (for global logout)
    if (decoded.v !== user.tokenVersion) {
      return res.status(401).json({ error: "Token revoked" });
    }
    
    req.user = user;
    next();
  } catch (err) {
    logger.warn("Auth error", err?.message || err);
    return res.status(401).json({ error: "Invalid token" });
  }
};

const requireRoles = (roles = []) => (req, res, next) => {
  if (!req.user) return res.status(401).json({ error: "Unauthorized" });
  if (!roles.includes(req.user.role)) return res.status(403).json({ error: "Forbidden" });
  next();
};

const requireProvider = (req, res, next) => {
  if (!req.user) return res.status(401).json({ error: "Unauthorized" });
  if (req.user.role !== "provider") return res.status(403).json({ error: "Providers only" });
  next();
};

const PASSWORD_PEPPER = process.env.PASSWORD_PEPPER || "";

const hashPassword = async (password) => {
  return argon2.hash(password + PASSWORD_PEPPER, {
    type: argon2.argon2id,
    memoryCost: 65536, // 64 MB
    timeCost: 3,
    parallelism: 2
  });
};

const verifyPassword = async (hash, password) => {
  return argon2.verify(hash, password + PASSWORD_PEPPER);
};

// Password migration function (from bcrypt to argon2)
const verifyAndMigratePassword = async (user, password) => {
  if (user.password.startsWith("$2")) {
    // This is a bcrypt hash, verify and migrate
    const bcrypt = await import("bcrypt");
    const valid = await bcrypt.compare(password, user.password);
    if (valid) {
      // Update to argon2
      const newHash = await hashPassword(password);
      await prisma.user.update({
        where: { id: user.id },
        data: { password: newHash }
      });
      return true;
    }
    return false;
  } else {
    // This is an argon2 hash
    return await verifyPassword(user.password, password);
  }
};

/* -----------------------------
   Email helper
   ----------------------------- */
const sendMail = async ({ to, subject, text, html }) => {
  if (!SMTP_HOST) {
    logger.warn("SMTP not configured - skipping email");
    return;
  }
  const transporter = nodemailer.createTransport({
    host: SMTP_HOST,
    port: Number(SMTP_PORT || 587),
    secure: Number(SMTP_PORT || 587) === 465,
    auth: { user: SMTP_USER, pass: SMTP_PASS }
  });
  return transporter.sendMail({ from: SMTP_USER, to, subject, text, html });
};

/* -----------------------------
   Utility: CloudFront signed URL implementation
   ----------------------------- */
function getCloudFrontUrl(path, expiresInSeconds = 3600) {
  if (!CLOUDFRONT_DOMAIN) {
    return `https://${S3_BUCKET_NAME}.s3.${AWS_REGION}.amazonaws.com/${path}`;
  }
  
  if (!CLOUDFRONT_KEY_PAIR_ID || !CLOUDFRONT_PRIVATE_KEY) {
    // If no signing credentials, return unsigned URL
    return `https://${CLOUDFRONT_DOMAIN}/${path}`;
  }
  
  // Create a signed CloudFront URL
  const dateLessThan = new Date();
  dateLessThan.setSeconds(dateLessThan.getSeconds() + expiresInSeconds);
  
  const policy = {
    Statement: [
      {
        Resource: `https://${CLOUDFRONT_DOMAIN}/${path}`,
        Condition: {
          DateLessThan: { "AWS:EpochTime": Math.floor(dateLessThan.getTime() / 1000) }
        }
      }
    ]
  };
  
  const policyString = JSON.stringify(policy);
  const policyBase64 = Buffer.from(policyString).toString("base64");
  
  const sign = crypto.createSign("RSA-SHA1");
  sign.update(policyBase64);
  const signature = sign.sign(CLOUDFRONT_PRIVATE_KEY, "base64");
  
  return `https://${CLOUDFRONT_DOMAIN}/${path}?Policy=${policyBase64}&Signature=${signature}&Key-Pair-Id=${CLOUDFRONT_KEY_PAIR_ID}`;
}

/* -----------------------------
   MediaConvert job implementation
   ----------------------------- */
export async function startMediaConvertJob(inputKey, outputPrefix, tier = "basic") {
  // Define all possible output resolutions
  const allOutputs = [
    { label: "480p", width: 854, height: 480, codec: "H_264", bitrate: 900_000, profile: "MAIN" },
    { label: "720p", width: 1280, height: 720, codec: "H_264", bitrate: 2_500_000, profile: "MAIN" },
    { label: "1080p", width: 1920, height: 1080, codec: "H_264", bitrate: 4_500_000, profile: "HIGH" },
    { label: "2k", width: 2048, height: 1080, codec: "H_265", bitrate: 8_000_000, profile: "MAIN" },
    { label: "4k", width: 3840, height: 2160, codec: "H_265", bitrate: 15_000_000, profile: "MAIN" },
    { label: "6k", width: 5760, height: 3240, codec: "H_265", bitrate: 25_000_000, profile: "MAIN" },
    { label: "8k", width: 7680, height: 4320, codec: "H_265", bitrate: 40_000_000, profile: "MAIN" },
  ];

  // Select outputs based on subscription tier
  let selectedOutputs;
  if (tier === "free") {
    selectedOutputs = allOutputs.filter(o => o.label === "480p");
  } else if (tier === "basic") {
    selectedOutputs = allOutputs.filter(o => o.label === "480p" || o.label === "720p");
  } else if (tier === "standard") {
    selectedOutputs = allOutputs.filter(o => o.label === "480p" || o.label === "720p" || o.label === "1080p");
  } else if (tier === "premium") {
    selectedOutputs = allOutputs; // all resolutions including 6K/8K
  } else {
    throw new Error(`Unknown subscription tier: ${tier}`);
  }

  // Convert selected outputs into MediaConvert-friendly objects
  const outputs = selectedOutputs.map(o => ({
    VideoDescription: o.codec === "H_264"
      ? {
          CodecSettings: {
            Codec: "H_264",
            H264Settings: {
              Bitrate: o.bitrate,
              RateControlMode: "CBR",
              GopSize: 90,
              GopSizeUnits: "FRAMES",
              GopClosedCadence: 1,
              Profile: o.profile,
              MaxBitrate: Math.round(o.bitrate * 1.1),
              EntropyEncoding: "CABAC",
            },
          },
        }
      : {
          CodecSettings: {
            Codec: "H_265",
            H265Settings: {
              Bitrate: o.bitrate,
              RateControlMode: "CBR",
              GopSize: 90,
              GopSizeUnits: "FRAMES",
              Profile: o.profile,
              MaxBitrate: Math.round(o.bitrate * 1.1),
            },
          },
        },
    Width: o.width,
    Height: o.height,
    AudioDescriptions: [
      {
        CodecSettings: {
          Codec: "AAC",
          AacSettings: { Bitrate: 128_000, CodingMode: "CODING_MODE_2_0", SampleRate: 48_000 },
        },
      },
    ],
    OutputSettings: {
      HlsSettings: {
        SegmentModifier: `_${o.label}`,
        HlsOutputSettings: { NameModifier: `_${o.label}` },
      },
    },
  }));

  // Create the MediaConvert job parameters
  const params = {
    Role: MEDIACONVERT_ROLE_ARN,
    Settings: {
      TimecodeConfig: { Source: "ZEROBASED" },
      Inputs: [
        {
          FileInput: `s3://${RAW_UPLOAD_BUCKET}/${inputKey}`,
          AudioSelectors: { "Audio Selector 1": { DefaultSelection: "DEFAULT" } },
          VideoSelector: {},
          TimecodeSource: "ZEROBASED",
        },
      ],
      OutputGroups: [
        {
          Name: "HLS Group",
          OutputGroupSettings: {
            Type: "HLS_GROUP_SETTINGS",
            HlsGroupSettings: {
              Destination: `s3://${PROCESSED_BUCKET}/${outputPrefix}/`,
              SegmentLength: 4,
              ManifestDurationFormat: "INTEGER",
              DirectoryStructure: "SINGLE_DIRECTORY",
              ManifestCompression: "NONE",
              ClientCache: "ENABLED",
              CodecSpecification: "RFC_4281",
              OutputSelection: "MANIFESTS_AND_SEGMENTS",
              HlsCdnSettings: {},
            },
          },
          Outputs: outputs,
        },
      ],
    },
    UserMetadata: {
      source: inputKey,
      output: outputPrefix,
      tier
    }
  };

  try {
    const command = new CreateJobCommand(params);
    const response = await mediaconvert.send(command);
    logger.info("MediaConvert job created", { jobId: response.Job?.Id });
    return response;
  } catch (err) {
    logger.error("MediaConvert job error", err);
    throw err;
  }
}

/* -----------------------------
   HLS Master Playlist Filtering
   ----------------------------- */
async function getFilteredHlsMaster(mediaId, userSubscription) {
  const allowed = tierRenditions[userSubscription] || ["_480p"];
  const masterKey = `processed/${mediaId}/master.m3u8`;

  // Check if we have a cached version
  const cacheKey = `hls_master:${mediaId}:${userSubscription}`;
  const cached = await redisClient.get(cacheKey);
  if (cached) {
    return cached;
  }

  // Fetch raw master playlist from S3
  const cmd = new GetObjectCommand({ Bucket: PROCESSED_BUCKET, Key: masterKey });
  const signedUrl = await getSignedUrl(s3, cmd, { expiresIn: 600 });
  const response = await fetch(signedUrl);
  const masterText = await response.text();

  const lines = masterText.split("\n");
  const filteredLines = [];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line.startsWith("#EXT-X-STREAM-INF")) {
      const nextLine = lines[i + 1];
      if (allowed.some(r => nextLine.includes(r))) {
        filteredLines.push(line, nextLine);
      }
      i++; // skip the next line
    } else if (!line.includes(".m3u8")) {
      filteredLines.push(line); // keep metadata lines
    }
  }

  const result = filteredLines.join("\n");
  
  // Cache the result for 1 hour
  await redisClient.setEx(cacheKey, 3600, result);
  
  return result;
}

/* -----------------------------
   Meilisearch helpers (optional)
   ----------------------------- */
async function indexMediaToSearch(media) {
  if (!meili) return;
  try {
    await meili.index("media").addDocuments([{
      id: media.id,
      title: media.title,
      category: media.category,
      season: media.season,
      episode: media.episode,
      forKids: media.forKids,
      createdAt: media.createdAt
    }]);
  } catch (err) {
    logger.warn("Meili index error", err);
  }
}

/* -----------------------------
   TMDB Helper
   ----------------------------- */
const TMDB_BASE = "https://api.themoviedb.org/3";

async function tmdb(path, params = {}) {
  const { data } = await axios.get(`${TMDB_BASE}${path}`, {
    params: { api_key: TMDB_API_KEY, ...params }
  });
  return data;
}

function mapTMDB(m) {
  return {
    id: m.id,
    title: m.title || m.name,
    poster: m.poster_path
      ? `https://image.tmdb.org/t/p/w500${m.poster_path}`
      : null,
    backdrop: m.backdrop_path
      ? `https://image.tmdb.org/t/p/original${m.backdrop_path}`
      : null,
    release: m.release_date,
    rating: m.vote_average,
    popularity: m.popularity,
    genres: m.genre_ids,
    source: "tmdb"
  };
}

/* -----------------------------
   Helper: check regional availability
   ----------------------------- */
async function checkMediaAvailability(mediaId, userCountry) {
  const cacheKey = `availability:${mediaId}:${userCountry}`;
  const cached = await redisClient.get(cacheKey);
  if (cached !== null) {
    return cached === "true";
  }
  
  const avail = await prisma.mediaAvailability.findFirst({ where: { mediaId } });
  let result = true;
  
  if (avail) {
    if (avail.blockedCountries?.length && avail.blockedCountries.includes(userCountry)) {
      result = false;
    } else if (avail.allowedCountries?.length) {
      result = avail.allowedCountries.includes(userCountry);
    }
  }
  
  // Cache for 30 minutes
  await redisClient.setEx(cacheKey, 1800, result.toString());
  return result;
}

/* -----------------------------
   Stripe price -> tier mapping
   ----------------------------- */
const priceToTier = {
  [STRIPE_BASIC_PRICE_ID]: "basic",
  [STRIPE_STANDARD_PRICE_ID]: "standard",
  [STRIPE_PREMIUM_PRICE_ID]: "premium",
  [STRIPE_AVOD_PRICE_ID]: "avod"
};

/* -----------------------------
   Genre definitions
   ----------------------------- */
const GENRES = [
  // Standard Movie Genres
  { id: 1,  name: "Action" },
  { id: 2,  name: "Adventure" },
  { id: 3,  name: "Animation" },
  { id: 4,  name: "Biography" },
  { id: 5,  name: "Comedy" },
  { id: 6,  name: "Crime" },
  { id: 7,  name: "Documentary" },
  { id: 8,  name: "Drama" },
  { id: 9,  name: "Family" },
  { id: 10, name: "Fantasy" },
  { id: 11, name: "History" },
  { id: 12, name: "Horror" },
  { id: 13, name: "Mystery" },
  { id: 14, name: "Romance" },
  { id: 15, name: "Sci-Fi" },
  { id: 16, name: "Thriller" },
  { id: 17, name: "War" },
  { id: 18, name: "Western" },
  { id: 19, name: "Music" },
  { id: 20, name: "Musical" },

  // TV Genres
  { id: 30, name: "Reality" },
  { id: 31, name: "Talk Show" },
  { id: 32, name: "Game Show" },
  { id: 33, name: "News" },
  { id: 34, name: "Soap" },
  { id: 35, name: "Variety" },

  // Anime Genres
  { id: 50, name: "Anime" },
  { id: 51, name: "Anime Action" },
  { id: 52, name: "Anime Adventure" },
  { id: 53, name: "Anime Comedy" },
  { id: 54, name: "Anime Drama" },
  { id: 55, name: "Anime Fantasy" },
  { id: 56, name: "Anime Horror" },
  { id: 57, name: "Anime Sci-Fi" },
  { id: 58, name: "Anime Romance" },
  { id: 59, name: "Anime Mystery" },

  // Sports Genres
  { id: 70, name: "Sports" },
  { id: 71, name: "Sports Documentary" },
  { id: 72, name: "Live Sports" },
  { id: 73, name: "Esports" },
  { id: 74, name: "Wrestling" },
  { id: 75, name: "MMA" },
  { id: 76, name: "Football" },
  { id: 77, name: "Basketball" },
  { id: 78, name: "Baseball" },
  { id: 79, name: "Soccer" },

  // Music Content
  { id: 90, name: "Music Videos" },
  { id: 91, name: "Concerts" },

  // Lifestyle Content
  { id: 100, name: "Lifestyle" },
  { id: 101, name: "Travel" },
  { id: 102, name: "Food" },
  { id: 103, name: "Art & Culture" }
];

/* -----------------------------
   API Routes
   ----------------------------- */

// Health check
app.get("/", (req, res) => res.json({ message: "ZenStream API (full) up" }));

// Genres
app.get("/api/genres", (req, res) => {
  res.json({
    success: true,
    genres: GENRES
  });
});

// Signup
app.post("/signup", authLimiter, async (req, res) => {
  try {
    const { fullName, email, password } = req.body;
    if (!fullName || !email || !password) {
      return res.status(400).json({ message: "All fields required" });
    }

    // Check if password is breached
    if (await isBreachedPassword(password)) {
      return res.status(400).json({ message: "Password found in data breaches. Please choose a different password." });
    }

    const existing = await prisma.user.findUnique({ where: { email } });
    if (existing) {
      return res.status(400).json({ message: "Email in use" });
    }

    const hash = await hashPassword(password);

    const user = await prisma.user.create({
      data: {
        name: fullName,
        email,
        password: hash,
        role: "user",
        subscriptionType: "free"
      }
    });

    // Send welcome email
    await sendMail({
      to: email,
      subject: "Welcome to ZenStream",
      text: `Hi ${fullName},\n\nWelcome to ZenStream! Your account has been created successfully.\n\nBest regards,\nThe ZenStream Team`,
      html: `<p>Hi ${fullName},</p><p>Welcome to ZenStream! Your account has been created successfully.</p><p>Best regards,<br>The ZenStream Team</p>`
    });

    res.status(201).json({ userId: user.id });
  } catch (err) {
    logger.error("Signup error", err);
    res.status(500).json({ message: "Server error" });
  }
});

// Login
app.post("/login", authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: "All fields required" });
    }

    // Rate-limit / lockout check
    await checkLoginLock(email);

    const user = await prisma.user.findUnique({ where: { email } });
    if (!user || !user.password) {
      await recordLoginFail(email);
      return res.status(400).json({ message: "Invalid credentials" });
    }

    // Verify + auto-migrate bcrypt → argon2
    const ok = await verifyAndMigratePassword(user, password, prisma);
    if (!ok) {
      await recordLoginFail(email);
      return res.status(400).json({ message: "Invalid credentials" });
    }

    // Success
    await clearLoginFails(email);

    const token = signToken({
      id: user.id,
      v: user.tokenVersion // allows global logout later
    });

    const refreshToken = signRefreshToken({
      id: user.id,
      v: user.tokenVersion
    });

    // Store refresh token in Redis
    await redisClient.setEx(`refresh_token:${user.id}`, 7 * 24 * 60 * 60, refreshToken);

    await prisma.user.update({
      where: { id: user.id },
      data: { lastLogin: new Date() }
    });

    // Set refresh token cookie
    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: NODE_ENV === "production",
      sameSite: "strict",
      maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
    });

    res.json({
      token,
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        role: user.role,
        plan: user.subscriptionType
      }
    });
  } catch (err) {
    logger.error("Login error", err);
    res.status(429).json({ message: err.message || "Server error" });
  }
});

// Refresh token
app.post("/refresh-token", async (req, res) => {
  try {
    const token = req.cookies.refreshToken || req.body.refreshToken;
    if (!token) return res.status(401).json({ error: "Missing refresh token" });

    let payload = null;
    try {
      payload = jwt.verify(token, REFRESH_TOKEN_SECRET || "refresh_secret");
    } catch {
      return res.status(401).json({ error: "Invalid refresh token" });
    }

    // Check if refresh token exists in Redis
    const storedToken = await redisClient.get(`refresh_token:${payload.id}`);
    if (storedToken !== token) {
      return res.status(401).json({ error: "Refresh token revoked" });
    }

    const user = await prisma.user.findUnique({ where: { id: payload.id } });
    if (!user || user.tokenVersion !== payload.v) {
      return res.status(401).json({ error: "User not found or token revoked" });
    }

    const newToken = signToken({
      id: user.id,
      v: user.tokenVersion
    });

    res.json({ token: newToken });
  } catch (err) {
    logger.error("Refresh token error", err);
    res.status(500).json({ error: "Server error" });
  }
});

// Logout
app.post("/logout", async (req, res) => {
  try {
    const token = req.cookies.refreshToken || req.body.refreshToken;
    if (token) {
      // Remove refresh token from Redis
      const payload = jwt.decode(token);
      if (payload && payload.id) {
        await redisClient.del(`refresh_token:${payload.id}`);
      }
      
      // Clear cookie
      res.cookie("refreshToken", "", {
        httpOnly: true,
        secure: NODE_ENV === "production",
        sameSite: "strict",
        maxAge: 0
      });
    }
    
    res.json({ success: true });
  } catch (err) {
    logger.error("Logout error", err);
    res.status(500).json({ error: "Server error" });
  }
});

// Global logout (invalidate all sessions)
app.post("/global-logout", requireAuth, async (req, res) => {
  try {
    // Increment token version to invalidate all tokens
    await prisma.user.update({
      where: { id: req.user.id },
      data: { tokenVersion: { increment: 1 } }
    });
    
    // Remove all refresh tokens for this user
    await redisClient.del(`refresh_token:${req.user.id}`);
    
    // Clear cookie
    res.cookie("refreshToken", "", {
      httpOnly: true,
      secure: NODE_ENV === "production",
      sameSite: "strict",
      maxAge: 0
    });
    
    res.json({ success: true });
  } catch (err) {
    logger.error("Global logout error", err);
    res.status(500).json({ error: "Server error" });
  }
});

// Google OAuth
app.get("/api/auth/google", passport.authenticate("google", { scope: ["profile", "email"] }));
app.get("/api/auth/google/callback", passport.authenticate("google", { session: false, failureRedirect: "/auth-failure" }), async (req, res) => {
  try {
    const token = signToken({ id: req.user.id, v: req.user.tokenVersion });
    const refreshToken = signRefreshToken({ id: req.user.id, v: req.user.tokenVersion });
    
    // Store refresh token in Redis
    await redisClient.setEx(`refresh_token:${req.user.id}`, 7 * 24 * 60 * 60, refreshToken);
    
    // Set refresh token cookie
    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: NODE_ENV === "production",
      sameSite: "strict",
      maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
    });
    
    const isMobile = req.headers["user-agent"]?.includes("Mobile");
    if (isMobile) return res.redirect(`yourapp://login-success?token=${token}`);
    return res.redirect(`${REDIRECT_URI || "http://localhost:3000"}/auth-success?token=${token}`);
  } catch (err) {
    logger.error("Google callback error", err);
    res.status(500).send("Auth failed");
  }
});

// Profiles
app.post("/api/profiles", requireAuth, async (req, res) => {
  try {
    const { name, avatar, isKids } = req.body;
    const profile = await prisma.profile.create({ 
      data: { 
        name, 
        avatar, 
        isKids: !!isKids, 
        userId: req.user.id 
      }
    });
    res.json({ profile });
  } catch (err) {
    logger.error("Create profile error", err);
    res.status(500).json({ error: "Server error" });
  }
});

app.get("/api/profiles", requireAuth, async (req, res) => {
  try {
    const profiles = await prisma.profile.findMany({ where: { userId: req.user.id }});
    res.json({ profiles });
  } catch (err) {
    logger.error("Get profiles error", err);
    res.status(500).json({ error: "Server error" });
  }
});

// Recommendations
const router = express.Router();

// Because you watched X
router.get("/recommend/because/:tmdbId", requireAuth, async (req, res) => {
  const tmdbId = Number(req.params.tmdbId);

  try {
    const similar = await tmdb(`/movie/${tmdbId}/similar`);

    const boost = await prisma.analyticsEvent.groupBy({
      by: ["tmdbId"],
      where: {
        tmdbId: { in: similar.results.map(m => m.id) },
        action: "play"
      },
      _count: true
    });

    const boostMap = Object.fromEntries(
      boost.map(b => [b.tmdbId, b._count])
    );

    const scored = similar.results.map(m => ({
      ...m,
      score: (boostMap[m.id] || 0) + m.popularity
    }));

    scored.sort((a, b) => b.score - a.score);

    res.json({ results: scored.slice(0, 20).map(mapTMDB) });
  } catch {
    res.status(500).json({ error: "Failed" });
  }
});

// Taste clustering
router.get("/recommend/taste", requireAuth, async (req, res) => {
  const userId = req.user.id;

  const history = await prisma.analyticsEvent.findMany({
    where: { userId, action: "play", tmdbId: { not: null } },
    take: 100,
    orderBy: { at: "desc" }
  });

  if (!history.length) {
    return res.redirect("/api/recommend/cold-start");
  }

  const movies = await Promise.all(
    history.map(h => tmdb(`/movie/${h.tmdbId}`))
  );

  const genreScore = {};
  movies.forEach(m =>
    m.genres.forEach(g => {
      genreScore[g.id] = (genreScore[g.id] || 0) + 1;
    })
  );

  const topGenres = Object.entries(genreScore)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 3)
    .map(([id]) => id);

  const discover = await tmdb("/discover/movie", {
    with_genres: topGenres.join(","),
    sort_by: "popularity.desc"
  });

  res.json({ results: discover.results.map(mapTMDB) });
});

// Hybrid row
router.get("/recommend/hybrid", requireAuth, async (req, res) => {
  const uploaded = await prisma.media.findMany({
    where: { visibility: "public" },
    orderBy: { views: "desc" },
    take: 10
  });

  const popular = await tmdb("/movie/popular");

  res.json({
    results: [
      ...uploaded.map(m => ({
        id: m.id,
        title: m.title,
        poster: m.posterUrl,
        source: "uploaded"
      })),
      ...popular.results.slice(0, 10).map(mapTMDB)
    ]
  });
});

// Cold start
router.get("/recommend/cold-start", async (req, res) => {
  const [popular, trending] = await Promise.all([
    tmdb("/movie/popular"),
    tmdb("/trending/movie/week")
  ]);

  res.json({
    results: [...popular.results.slice(0, 10), ...trending.results.slice(0, 10)]
      .map(mapTMDB)
  });
});

// Smart continue watching
router.get("/user/continue-watching", requireAuth, async (req, res) => {
  const userId = req.user.id;

  const progress = await prisma.watchProgress.findMany({
    where: { userId },
    orderBy: { updatedAt: "desc" }
  });

  const scored = progress.map(p => {
    const recency = Date.now() - new Date(p.updatedAt).getTime();
    const recencyScore = Math.max(0, 30 - recency / 3.6e6); // hours

    const completionBoost =
      p.progress > 0.7 ? 15 :
      p.progress > 0.3 ? 8 :
      -5;

    return {
      ...p,
      score: recencyScore + completionBoost
    };
  });

  scored.sort((a, b) => b.score - a.score);

  res.json({
    results: scored.slice(0, 12)
  });
});

app.use("/api", router);

// Provider: upload media
app.post("/api/provider/upload-media", requireAuth, requireProvider, async (req, res) => {
  try {
    const {
      title,
      category,
      season,
      episode,
      forKids = false
    } = req.body;

    if (!title || !category) {
      return res.status(400).json({ error: "title and category required" });
    }

    const mediaId = uuidv4();

    // S3 raw upload path
    const rawKey = `raw/${req.user.id}/${mediaId}.mp4`;

    // Create media record in Prisma
    const media = await prisma.media.create({
      data: {
        id: mediaId,
        title,
        category,
        season: season ? Number(season) : null,
        episode: episode ? Number(episode) : null,
        forKids,
        forFreeUsers: false,
        s3Key: rawKey,
        processingStatus: "processing",
        uploadedById: req.user.id
      }
    });

    // Generate a pre-signed upload URL
    const uploadUrl = await getSignedUrl(
      s3,
      new PutObjectCommand({
        Bucket: RAW_UPLOAD_BUCKET,
        Key: rawKey,
        ContentType: "video/mp4"
      }),
      { expiresIn: 3600 }
    );

    // Create output folder path for MediaConvert
    const outputPrefix = `processed/${mediaId}`;

    // Start MediaConvert job
    const job = await startMediaConvertJob(rawKey, outputPrefix, "basic"); // Default to basic tier

    return res.json({
      message: "Upload URL generated, MediaConvert job started",
      uploadUrl,
      mediaId,
      jobId: job.Job.Id
    });

  } catch (err) {
    console.error("Media upload error", err);
    return res.status(500).json({
      error: "Server error during media upload"
    });
  }
});

// Stream endpoint
app.get("/api/media/:id/stream", requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const profileId = req.query.profileId; // optional, for progress check & kid mode
    const media = await prisma.media.findUnique({ where: { id } });
    if (!media) return res.status(404).json({ error: "Media not found" });

    // Regional availability
    if (!(await checkMediaAvailability(media.id, req.user.country))) {
      return res.status(403).json({ error: "Not available in your region" });
    }

    // Subscription / free access check
    if (!req.user.subscriptionActive && !media.forFreeUsers) {
      return res.status(403).json({ error: "Premium required" });
    }

    // If HLS/CloudFront assets exist, prefer CloudFront signed HLS path
    const cdnAsset = await prisma.cdnAsset.findFirst({ 
      where: { mediaId: id, hlsKey: { not: null } }, 
      orderBy: { quality: "desc" }
    });
    
    let playbackUrl;
    if (cdnAsset && cdnAsset.hlsKey) {
      // For HLS, we need to filter the master playlist based on user's subscription tier
      const filteredMaster = await getFilteredHlsMaster(id, req.user.subscriptionType);
      
      // Cache the filtered playlist in S3 temporarily
      const filteredKey = `filtered/${id}/${req.user.subscriptionType}/master.m3u8`;
      await s3.send(new PutObjectCommand({
        Bucket: PROCESSED_BUCKET,
        Key: filteredKey,
        Body: filteredMaster,
        ContentType: "application/vnd.apple.mpegurl"
      }));
      
      playbackUrl = getCloudFrontUrl(filteredKey, 3600);
    } else {
      // Fallback: generate signed S3 GetObject for direct mp4
      const cmd = new GetObjectCommand({ Bucket: S3_BUCKET_NAME, Key: media.s3Key });
      playbackUrl = await getSignedUrl(s3, cmd, { expiresIn: 3600 });
    }

    // Log watch history and analytics
    await prisma.watchHistory.create({ 
      data: { 
        userId: req.user.id, 
        mediaId: id,
        profileId: profileId || null
      }
    });
    
    await prisma.analyticsEvent.create({ 
      data: { 
        userId: req.user.id, 
        profileId: profileId || null, 
        mediaId: id, 
        action: "play", 
        meta: { 
          source: "stream",
          subscription: req.user.subscriptionType
        } 
      }
    });

    res.json({ url: playbackUrl });
  } catch (err) {
    logger.error("Stream media error", err);
    res.status(500).json({ error: "Server error" });
  }
});

// Stripe checkout
app.post("/create-checkout-session", requireAuth, async (req, res) => {
  try {
    const { priceId } = req.body;
    if (!priceId) return res.status(400).json({ error: "Missing priceId" });
    
    const session = await stripe.checkout.sessions.create({
      payment_method_types: ["card"],
      mode: "subscription",
      line_items: [{ price: priceId, quantity: 1 }],
      success_url: `${REDIRECT_URI || "https://yourfrontend.com"}/success?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${REDIRECT_URI || "https://yourfrontend.com"}/cancel`,
      metadata: { userId: req.user.id, priceId }
    });
    res.json({ sessionId: session.id });
  } catch (err) {
    logger.error("Create checkout error", err);
    res.status(500).json({ error: err.message });
  }
});

// Stripe webhook
app.post("/webhook", bodyParser.raw({ type: "application/json" }), async (req, res) => {
  const sig = req.headers["stripe-signature"];
  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, sig, STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    logger.error("Stripe webhook signature failed", err?.message || err);
    return res.status(400).send(`Webhook Error: ${err?.message || err}`);
  }
  try {
    if (event.type === "checkout.session.completed") {
      const session = event.data.object;
      const userId = session.metadata.userId;
      const priceId = session.metadata.priceId;
      const tier = priceToTier[priceId] || "premium";
      
      await prisma.user.update({ 
        where: { id: userId }, 
        data: { 
          subscriptionType: tier, 
          subscriptionActive: true, 
          subscriptionEnd: null 
        }
      });
      
      // Invalidate CloudFront cache for this user's content
      await cloudfront.send(new CreateInvalidationCommand({
        DistributionId: process.env.CLOUDFRONT_DISTRIBUTION_ID,
        InvalidationBatch: {
          Paths: {
            Quantity: 1,
            Items: [`/filtered/*`]
          },
          CallerReference: `user-${userId}-${Date.now()}`
        }
      }));
      
      logger.info("Stripe subscription activated", { userId, tier });
    } else if (event.type === "invoice.payment_failed") {
      const invoice = event.data.object;
      const userId = invoice.metadata?.userId;
      if (userId) {
        await prisma.user.update({ where: { id: userId }, data: { subscriptionActive: false }});
      }
    }
    res.json({ received: true });
  } catch (err) {
    logger.error("Webhook processing error", err);
    res.status(500).send("Webhook internal error");
  }
});

// Admin dashboard
app.get("/api/admin/dashboard", requireAuth, requireRoles(["admin", "superadmin"]), async (req, res) => {
  try {
    const totalUsers = await prisma.user.count();
    const activeSubs = await prisma.user.count({ where: { subscriptionActive: true }});
    const totalMedia = await prisma.media.count();
    const plays = await prisma.analyticsEvent.count({ 
      where: { 
        action: "play", 
        at: { gte: new Date(Date.now() - 24*3600*1000) } 
      } 
    });
    
    // Get subscription breakdown
    const subsByTier = await prisma.user.groupBy({
      by: ["subscriptionType"],
      _count: true
    });
    
    // Get recent uploads
    const recentUploads = await prisma.media.findMany({
      take: 5,
      orderBy: { createdAt: "desc" },
      include: { uploader: { select: { name: true } } }
    });
    
    res.json({ 
      totalUsers, 
      activeSubs, 
      totalMedia, 
      plays,
      subsByTier,
      recentUploads
    });
  } catch (err) {
    logger.error("Admin dashboard error", err);
    res.status(500).json({ error: "Server error" });
  }
});

// Advanced trending with AI prediction
app.get("/api/trending/advanced", requireAuth, async (req, res) => {
  try {
    const hours = Number(req.query.hours || 24);
    const limit = Number(req.query.limit || 20);
    const country = req.query.country || req.user.country;

    const since = new Date(Date.now() - hours * 3600000);

    // Friends IDs
    const follows = await prisma.follow.findMany({
      where: { followerId: req.user.id },
      select: { followingId: true }
    });
    const friendIds = follows.map(f => f.followingId);

    // Trending + geo + friends
    const trending = await prisma.$queryRaw`
      SELECT
        ae."mediaId",
        COUNT(DISTINCT ae."userId") AS users,
        MAX(ae.at) AS last_play,
        (
          COUNT(DISTINCT ae."userId")
          *
          (1 / (EXTRACT(EPOCH FROM (NOW() - MAX(ae.at))) / 3600 + 1))
          *
          CASE WHEN ae.country = ${country} THEN 1.25 ELSE 1 END
          *
          CASE WHEN ae."userId" = ANY(${friendIds}) THEN 1.3 ELSE 1 END
        ) AS score
      FROM "AnalyticsEvent" ae
      WHERE ae.action = 'play'
        AND ae.at >= ${since}
      GROUP BY ae."mediaId"
      ORDER BY score DESC
      LIMIT ${limit};
    `;

    if (!trending.length) {
      return res.json({ trending: [] });
    }

    const ids = trending.map(t => t.mediaId);

    // Momentum (24h vs 7d)
    const momentum = await prisma.$queryRaw`
      SELECT
        "mediaId",
        COUNT(*) FILTER (WHERE at >= NOW() - INTERVAL '24 hours') AS d1,
        COUNT(*) FILTER (WHERE at >= NOW() - INTERVAL '7 days') AS d7
      FROM "AnalyticsEvent"
      WHERE "mediaId" = ANY(${ids})
      GROUP BY "mediaId";
    `;

    const momentumMap = new Map(
      momentum.map(m => [
        m.mediaId,
        m.d7 ? Number(m.d1) / Number(m.d7) : 0
      ])
    );

    // AI prediction boost
    function aiBoost(score, momentum) {
      if (momentum > 0.6) return score * 1.4;
      if (momentum > 0.4) return score * 1.25;
      return score;
    }

    // Media fetch
    const media = await prisma.media.findMany({
      where: { id: { in: ids } }
    });
    const mediaMap = new Map(media.map(m => [m.id, m]));

    // Final build
    const result = trending.map(t => {
      const momentumValue = momentumMap.get(t.mediaId) || 0;
      const boostedScore = aiBoost(Number(t.score), momentumValue);

      // Save snapshot for charts
      prisma.trendingSnapshot.create({
        data: {
          mediaId: t.mediaId,
          score: boostedScore,
          windowHrs: hours
        }
      }).catch(() => {});

      return {
        mediaId: t.mediaId,
        score: boostedScore,
        momentum: momentumValue,
        predictedTrending: momentumValue > 0.5,
        media: mediaMap.get(t.mediaId)
      };
    });

    res.json({
      windowHours: hours,
      geo: country,
      count: result.length,
      trending: result.sort((a, b) => b.score - a.score)
    });

  } catch (err) {
    logger.error("Advanced trending error", err);
    res.status(500).json({ error: "Server error" });
  }
});

// Error handling
app.use((err, req, res, next) => {
  logger.error("Unhandled error", err);
  res.status(500).json({ error: "Internal server error" });
});

// Start server
const _PORT = Number(PORT || 5000);
app.listen(_PORT, () => logger.info(`Server running on port ${_PORT}`));
