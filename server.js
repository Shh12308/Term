// server.js - MonkeyApp backend (OAuth + matchmaking + AI + Agora)
import express from "express";
import pg from "pg";
import dotenv from "dotenv";
import passport from "passport";
import session from "express-session";
import jwt from "jsonwebtoken";
import cors from "cors";
import http from "http";
import { Server as SocketIOServer } from "socket.io";
import agora from "agora-access-token";
const { RtcTokenBuilder, RtcRole, RtmTokenBuilder } = agora;
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import { Strategy as DiscordStrategy } from "passport-discord";
import { Strategy as FacebookStrategy } from "passport-facebook";
import OpenAI from "openai";
import crypto from "crypto";

dotenv.config();

const app = express();
app.use(cors({ origin: true }));
app.use(express.json({ limit: "2mb" }));

// --- Postgres Pool ---
const pool = new pg.Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASS,
  port: process.env.DB_PORT,
});

// --- JWT secret ---
const JWT_SECRET = process.env.JWT_SECRET || "super_secret_jwt_key";

// --- Session (passport requires it for OAuth flows) ---
app.use(
  session({
    secret: process.env.SESSION_SECRET || "session_secret_omevo",
    resave: false,
    saveUninitialized: false,
  })
);
app.use(passport.initialize());
app.use(passport.session());

// --- Passport user serialization ---
passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
  try {
    const { rows } = await pool.query("SELECT * FROM users WHERE id=$1", [id]);
    done(null, rows[0] || null);
  } catch (err) {
    done(err, null);
  }
});

// --- Passport strategies ---
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: process.env.GOOGLE_CALLBACK_URL,
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        const email = profile.emails?.[0]?.value;
        const providerId = profile.id;
        const text = `
          INSERT INTO users (username, email, provider, provider_id, created_at, updated_at)
          VALUES ($1,$2,'google',$3,NOW(),NOW())
          ON CONFLICT (email) DO UPDATE SET provider='google', provider_id=$3, username=EXCLUDED.username, updated_at=NOW()
          RETURNING *`;
        const values = [profile.displayName || profile.username || email, email, providerId];
        const result = await pool.query(text, values);
        done(null, result.rows[0]);
      } catch (err) {
        done(err, null);
      }
    }
  )
);

passport.use(
  new DiscordStrategy(
    {
      clientID: process.env.DISCORD_CLIENT_ID,
      clientSecret: process.env.DISCORD_CLIENT_SECRET,
      callbackURL: process.env.DISCORD_CALLBACK_URL,
      scope: ["identify", "email"],
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        const email = profile.email;
        const providerId = profile.id;
        const text = `
          INSERT INTO users (username, email, provider, provider_id, created_at, updated_at)
          VALUES ($1,$2,'discord',$3,NOW(),NOW())
          ON CONFLICT (email) DO UPDATE SET provider='discord', provider_id=$3, username=EXCLUDED.username, updated_at=NOW()
          RETURNING *`;
        const values = [profile.username || profile.displayName, email, providerId];
        const result = await pool.query(text, values);
        done(null, result.rows[0]);
      } catch (err) {
        done(err, null);
      }
    }
  )
);

passport.use(
  new FacebookStrategy(
    {
      clientID: process.env.FACEBOOK_APP_ID,
      clientSecret: process.env.FACEBOOK_APP_SECRET,
      callbackURL: process.env.FACEBOOK_CALLBACK_URL,
      profileFields: ["id", "displayName", "emails"],
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        const email = profile.emails?.[0]?.value || null;
        const providerId = profile.id;
        const text = `
          INSERT INTO users (username, email, provider, provider_id, created_at, updated_at)
          VALUES ($1,$2,'facebook',$3,NOW(),NOW())
          ON CONFLICT (email) DO UPDATE SET provider='facebook', provider_id=$3, username=EXCLUDED.username, updated_at=NOW()
          RETURNING *`;
        const values = [profile.displayName || profile.username || email, email, providerId];
        const result = await pool.query(text, values);
        done(null, result.rows[0]);
      } catch (err) {
        done(err, null);
      }
    }
  )
);

// --- Helper: sign JWT ---
function signJwtForUser(user) {
  const payload = { id: user.id, email: user.email, provider: user.provider };
  return jwt.sign(payload, JWT_SECRET, { expiresIn: "14d" });
}

// --- OAuth Routes ---
app.get("/auth/google", passport.authenticate("google", { scope: ["profile", "email"] }));
app.get(
  "/auth/google/callback",
  passport.authenticate("google", { failureRedirect: "/auth/failure", session: true }),
  (req, res) => {
    const token = signJwtForUser(req.user);
    res.redirect(`${process.env.FRONTEND_URL || "/"}?token=${token}`);
  }
);

app.get("/auth/discord", passport.authenticate("discord"));
app.get(
  "/auth/discord/callback",
  passport.authenticate("discord", { failureRedirect: "/auth/failure", session: true }),
  (req, res) => {
    const token = signJwtForUser(req.user);
    res.redirect(`${process.env.FRONTEND_URL || "/"}?token=${token}`);
  }
);

app.get("/auth/facebook", passport.authenticate("facebook", { scope: ["email"] }));
app.get(
  "/auth/facebook/callback",
  passport.authenticate("facebook", { failureRedirect: "/auth/failure", session: true }),
  (req, res) => {
    const token = signJwtForUser(req.user);
    res.redirect(`${process.env.FRONTEND_URL || "/"}?token=${token}`);
  }
);

app.get("/auth/failure", (req, res) => res.status(401).json({ error: "Authentication failed" }));

// --- Protected middleware ---
async function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization || req.body.token || req.query.token;
  if (!authHeader) return res.status(401).json({ error: "Missing token" });
  const token = authHeader.replace(/^Bearer\s*/i, "");
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const { rows } = await pool.query("SELECT * FROM users WHERE id=$1", [decoded.id]);
    if (!rows[0]) return res.status(401).json({ error: "User not found" });
    req.user = rows[0];
    next();
  } catch (err) {
    return res.status(401).json({ error: "Invalid token" });
  }
}

// --- Socket.IO setup ---
const server = http.createServer(app);
const io = new SocketIOServer(server, { cors: { origin: "*" } });
const onlineSockets = new Map();

io.on("connection", (socket) => {
  socket.on("auth", async ({ token }) => {
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      onlineSockets.set(String(decoded.id), socket.id);
      socket.data.userId = String(decoded.id);
      console.log("Socket auth success for user:", decoded.id);
    } catch {
      socket.disconnect(true);
    }
  });

  socket.on("disconnect", () => {
    const uid = socket.data.userId;
    if (uid) onlineSockets.delete(String(uid));
  });
});

// --- OpenAI setup ---
const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

// --- AES Encryption helpers ---
const ENCRYPTION_SECRET = process.env.ENCRYPTION_SECRET || "32_characters_minimum!";
function encrypt(text) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", Buffer.from(ENCRYPTION_SECRET), iv);
  const enc = Buffer.concat([cipher.update(text, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, enc]).toString("base64");
}
function decrypt(encData) {
  const raw = Buffer.from(encData, "base64");
  const iv = raw.slice(0, 12);
  const tag = raw.slice(12, 28);
  const text = raw.slice(28);
  const decipher = crypto.createDecipheriv("aes-256-gcm", Buffer.from(ENCRYPTION_SECRET), iv);
  decipher.setAuthTag(tag);
  return decipher.update(text, "binary", "utf8") + decipher.final("utf8");
}

// --- Matchmaking queue helpers ---
async function tryFindMatch(userId, genderPref, locationPref, interests = []) {
  const candidateQuery = `
    SELECT q.user_id, q.gender, q.location, q.nickname, q.interests
    FROM queue q
    WHERE q.user_id <> $1
      AND ($2 = 'any' OR q.gender = $2)
      AND ($3 = 'any' OR q.location = $3)
    ORDER BY q.joined_at ASC
    LIMIT 5
  `;
  const { rows } = await pool.query(candidateQuery, [userId, genderPref, locationPref]);
  if (!rows.length) return null;

  // find first candidate sharing at least one interest
  let matched = null;
  for (const r of rows) {
    const candidateInterests = (r.interests || "").split(",").map(s => s.trim().toLowerCase());
    if (!interests.length || interests.some(i => candidateInterests.includes(i.toLowerCase()))) {
      matched = r;
      break;
    }
  }
  if (!matched) return null;

  const peerId = matched.user_id;
  const channelNameRaw = `monkeyapp_${Math.min(userId, peerId)}_${Math.max(userId, peerId)}_${Date.now()}`;
  const channelNameEncrypted = encrypt(channelNameRaw);

  // save match record
  await pool.query(
    `INSERT INTO matches (user_a, user_b, channel_name, created_at) VALUES ($1,$2,$3,NOW())`,
    [userId, peerId, channelNameEncrypted]
  );

  // remove both from queue
  await pool.query("DELETE FROM queue WHERE user_id IN ($1,$2)", [userId, peerId]).catch(() => {});

  // notify peer if online via socket.io
  const peerSocketId = onlineSockets.get(String(peerId));
  if (peerSocketId) {
    io.to(peerSocketId).emit("match_found", { peerId: userId, channel: channelNameEncrypted });
  }
  const requesterSocketId = onlineSockets.get(String(userId));
  if (requesterSocketId) {
    io.to(requesterSocketId).emit("match_found", { peerId: peerId, channel: channelNameEncrypted });
  }

  // Generate icebreaker using OpenAI
  const prompt = `
    Suggest a friendly, short icebreaker for two users.
    User A interests: ${interests.join(", ")}
    User B interests: ${matched.interests || ""}
  `;
  let icebreaker = "Hey, nice to meet you!";
  try {
    const res = await openai.chat.completions.create({
      model: "gpt-4o-mini",
      messages: [{ role: "user", content: prompt }],
      max_tokens: 40,
    });
    icebreaker = res.choices[0].message.content.trim();
  } catch (e) {
    console.warn("OpenAI icebreaker failed", e);
  }

  return { peerId, channel: channelNameEncrypted, icebreaker };
}

// --- Queue endpoints ---
app.post("/queue/enqueue", requireAuth, async (req, res) => {
  try {
    const { gender = "any", location = "any", interests = "", nickname = "" } = req.body;
    const userId = String(req.user.id);

    await pool.query(
      `INSERT INTO queue (user_id, gender, location, interests, nickname, joined_at)
       VALUES ($1,$2,$3,$4,$5,NOW())
       ON CONFLICT (user_id) DO UPDATE SET gender=EXCLUDED.gender, location=EXCLUDED.location, interests=EXCLUDED.interests, nickname=EXCLUDED.nickname, joined_at=NOW()`,
      [userId, gender, location, interests, nickname]
    );

    const interestsArr = interests.split(",").map(i => i.trim().toLowerCase());
    const match = await tryFindMatch(userId, gender, location, interestsArr);
    if (match) {
      return res.json({ matched: true, peerId: match.peerId, channel: match.channel, icebreaker: match.icebreaker });
    }
    return res.json({ matched: false });
  } catch (err) {
    console.error("enqueue error:", err);
    res.status(500).json({ error: "enqueue failed" });
  }
});

app.post("/queue/leave", requireAuth, async (req, res) => {
  try {
    await pool.query("DELETE FROM queue WHERE user_id=$1", [String(req.user.id)]);
    return res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "leave failed" });
  }
});

// --- Generate Agora RTC / RTM tokens ---
app.post("/generateToken", requireAuth, async (req, res) => {
  try {
    const { channelName, uid: requestedUid, role = "publisher", expirySeconds = 3600 } = req.body;
    if (!channelName) return res.status(400).json({ error: "channelName required" });

    const appID = process.env.AGORA_APP_ID;
    const appCertificate = process.env.AGORA_APP_CERTIFICATE;
    if (!appID || !appCertificate) return res.status(500).json({ error: "Agora credentials not configured" });

    const uid = requestedUid !== undefined ? String(requestedUid) : String(req.user.id);
    const rtcRole = role === "publisher" ? RtcRole.PUBLISHER : RtcRole.SUBSCRIBER;

    const currentTs = Math.floor(Date.now() / 1000);
    const privilegeExpiredTs = currentTs + Number(expirySeconds);

    const rtcToken = RtcTokenBuilder.buildTokenWithAccount(
      appID,
      appCertificate,
      channelName,
      uid,
      rtcRole,
      privilegeExpiredTs
    );

    const rtmToken = RtmTokenBuilder.buildToken(appID, appCertificate, uid, privilegeExpiredTs);

    return res.json({ rtcToken, rtmToken, appID, uid });
  } catch (err) {
    console.error("generateToken error", err);
    res.status(500).json({ error: "token generation failed" });
  }
});

// --- Basic health check ---
app.get("/health", (req, res) => res.json({ ok: true, env: process.env.NODE_ENV || "dev" }));

// --- Start the server ---
const PORT = process.env.PORT || 5000;
server.listen(PORT, () => {
  console.log(`MonkeyApp backend listening on port ${PORT}`);
  console.log("Ensure env vars: AGORA_APP_ID, AGORA_APP_CERTIFICATE, DB_*, GOOGLE_*, DISCORD_*, FACEBOOK_*, OPENAI_API_KEY, ENCRYPTION_SECRET");
});
