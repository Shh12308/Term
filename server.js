// server.js - Backend for OmeVo app with Socket.IO, WebRTC, Coinbase Commerce, and OpenAI moderation

import express from "express";
import pg from "pg";
import geoip from "geoip-lite"; 
import dotenv from "dotenv";
import passport from "passport";
import session from "express-session";
import pgSessionImport from "connect-pg-simple";
import jwt from "jsonwebtoken";
import cors from "cors";
import http from "http";
import { Server as SocketIOServer } from "socket.io";
import agora from "agora-access-token";
import CoinbaseCommerce from "coinbase-commerce-node";

import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import { Strategy as DiscordStrategy } from "passport-discord";
import { Strategy as FacebookStrategy } from "passport-facebook";

import OpenAI from "openai";

dotenv.config();

// ------------------- CONFIG -------------------
const app = express();
app.use(cors({ origin: true }));
app.use(express.json({ limit: "5mb" }));
const server = http.createServer(app);
const io = new SocketIOServer(server, { cors: { origin: "*" } });

const pool = new pg.Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASS,
  port: process.env.DB_PORT,
});

const JWT_SECRET = process.env.JWT_SECRET || "super_secret_jwt_key";
const OPENAI = new OpenAI({ apiKey: process.env.OPENAI_API_KEY || "" });

const AGORA_APP_ID = process.env.AGORA_APP_ID;
const AGORA_APP_CERTIFICATE = process.env.AGORA_APP_CERTIFICATE;

const BAN_HOURS = 750;
const UNBAN_PRICE = 5.99;

// Coinbase Commerce Client
const { Client, resources } = CoinbaseCommerce;
const { Charge } = resources;
Client.init(process.env.COINBASE_COMMERCE_API_KEY);

// ------------------- SESSION & PASSPORT -------------------
const pgSession = pgSessionImport(session);
const pgSessionStore = pgSession(session);

app.use(
  session({
    store: new pgSessionStore({
      pool: pool,
      tableName: "user_sessions",
    }),
    secret: process.env.SESSION_SECRET || "session_secret_omevo",
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 14 * 24 * 60 * 60 * 1000 },
  })
);

app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
  try {
    const { rows } = await pool.query("SELECT * FROM users WHERE id=$1", [id]);
    done(null, rows[0] || null);
  } catch (err) {
    done(err, null);
  }
});

// ------------------- PASSPORT STRATEGIES -------------------
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: process.env.GOOGLE_CALLBACK_URL,
}, async (accessToken, refreshToken, profile, done) => {
  try {
    const email = profile.emails?.[0]?.value || null;
    const providerId = profile.id;
    const text = `
      INSERT INTO users (username, email, provider, provider_id, created_at, updated_at)
      VALUES ($1,$2,'google',$3,NOW(),NOW())
      ON CONFLICT (email) DO UPDATE SET provider='google', provider_id=$3, username=EXCLUDED.username, updated_at=NOW()
      RETURNING *`;
    const values = [profile.displayName || profile.username || email, email, providerId];
    const result = await pool.query(text, values);
    done(null, result.rows[0]);
  } catch (err) { done(err, null); }
}));

passport.use(new DiscordStrategy({
  clientID: process.env.DISCORD_CLIENT_ID,
  clientSecret: process.env.DISCORD_CLIENT_SECRET,
  callbackURL: process.env.DISCORD_CALLBACK_URL,
  scope: ["identify", "email"],
}, async (accessToken, refreshToken, profile, done) => {
  try {
    const email = profile.email || null;
    const providerId = profile.id;
    const text = `
      INSERT INTO users (username, email, provider, provider_id, created_at, updated_at)
      VALUES ($1,$2,'discord',$3,NOW(),NOW())
      ON CONFLICT (email) DO UPDATE SET provider='discord', provider_id=$3, username=EXCLUDED.username, updated_at=NOW()
      RETURNING *`;
    const values = [profile.username || profile.displayName, email, providerId];
    const result = await pool.query(text, values);
    done(null, result.rows[0]);
  } catch (err) { done(err, null); }
}));

passport.use(new FacebookStrategy({
  clientID: process.env.FACEBOOK_APP_ID,
  clientSecret: process.env.FACEBOOK_APP_SECRET,
  callbackURL: process.env.FACEBOOK_CALLBACK_URL,
  profileFields: ["id", "displayName", "emails"],
}, async (accessToken, refreshToken, profile, done) => {
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
  } catch (err) { done(err, null); }
}));

// ------------------- JWT HELPER -------------------
function signJwtForUser(user) {
  const payload = { id: user.id, email: user.email, provider: user.provider };
  return jwt.sign(payload, JWT_SECRET, { expiresIn: "14d" });
}

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

// ------------------- OAUTH ROUTES -------------------
app.get("/auth/google", passport.authenticate("google", { scope: ["profile", "email"] }));
app.get("/auth/google/callback", passport.authenticate("google", { failureRedirect: "/auth/failure", session: true }), (req, res) => {
  const token = signJwtForUser(req.user);
  res.redirect(`${process.env.FRONTEND_URL || "/"}?token=${token}`);
});

app.get("/auth/discord", passport.authenticate("discord"));
app.get("/auth/discord/callback", passport.authenticate("discord", { failureRedirect: "/auth/failure", session: true }), (req, res) => {
  const token = signJwtForUser(req.user);
  res.redirect(`${process.env.FRONTEND_URL || "/"}?token=${token}`);
});

app.get("/auth/facebook", passport.authenticate("facebook", { scope: ["email"] }));
app.get("/auth/facebook/callback", passport.authenticate("facebook", { failureRedirect: "/auth/failure", session: true }), (req, res) => {
  const token = signJwtForUser(req.user);
  res.redirect(`${process.env.FRONTEND_URL || "/"}?token=${token}`);
});

app.get("/auth/failure", (req, res) => res.status(401).json({ error: "Authentication failed" }));

// ------------------- SOCKET.IO -------------------
const onlineSockets = new Map();

function requireSocketUser(socket) {
  if (!socket.data.userId) {
    socket.disconnect(true);
    return null;
  }
  return socket.data.userId;
}

io.on("connection", (socket) => {
  socket.on("auth", async ({ token }) => {
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      onlineSockets.set(String(decoded.id), socket.id);
      socket.data.userId = String(decoded.id);
      console.log("Socket auth success for user:", decoded.id);
    } catch (err) {
      socket.disconnect(true);
    }
  });

  socket.on("disconnect", () => {
    const uid = socket.data.userId;
    if (uid) onlineSockets.delete(String(uid));
  });

  socket.on("chat_message", async ({ message }) => {
    const uid = requireSocketUser(socket);
    if (!uid) return;
    try {
      const mod = await OPENAI.moderations.create({ model: "omni-moderation-latest", input: message });
      const flagged = mod.results?.[0]?.categories?.sexual || mod.results?.[0]?.flagged;
      if (flagged) {
        await pool.query("UPDATE users SET banned_until = NOW() + INTERVAL '750 hours' WHERE id=$1", [uid]);
        socket.emit("moderation_action", { type: "chat", message, banned: true, duration_hours: BAN_HOURS });
        socket.disconnect(true);
      } else {
        io.emit("chat_message", { uid, message });
      }
    } catch (err) { console.error("Moderation error:", err); }
  });

  let lastFrameModeration = 0;
  socket.on("video_frame", async ({ frameBase64 }) => {
    const uid = requireSocketUser(socket);
    if (!uid) return;
    if (Date.now() - lastFrameModeration < 1000) return;
    lastFrameModeration = Date.now();
    try {
      const mod = await OPENAI.moderations.create({ model: "omni-moderation-latest", input: frameBase64 });
      const flagged = mod.results?.[0]?.categories?.sexual || mod.results?.[0]?.flagged;
      if (flagged) {
        await pool.query("UPDATE users SET banned_until = NOW() + INTERVAL '750 hours' WHERE id=$1", [uid]);
        socket.emit("moderation_action", { type: "video", banned: true, duration_hours: BAN_HOURS });
        socket.disconnect(true);
      }
    } catch (err) { console.error("Video moderation error:", err); }
  });

  socket.on("join_room", ({ room }) => {
    if (!room) return;
    socket.join(room);
    socket.to(room).emit("peer_joined", { socketId: socket.id });
  });

  socket.on("leave_room", ({ room }) => {
    if (!room) return;
    socket.leave(room);
    socket.to(room).emit("peer_left", { socketId: socket.id });
  });

  socket.on("webrtc.offer", ({ room, sdp }) => { if (!room || !sdp) return; socket.to(room).emit("webrtc.offer", { from: socket.id, sdp }); });
  socket.on("webrtc.answer", ({ room, sdp }) => { if (!room || !sdp) return; socket.to(room).emit("webrtc.answer", { from: socket.id, sdp }); });
  socket.on("webrtc.ice", ({ room, candidate }) => { if (!room || !candidate) return; socket.to(room).emit("webrtc.ice", { from: socket.id, candidate }); });
});

// ------------------- MATCHMAKING -------------------
async function tryFindMatch(userId, genderPref, locationPref) {
  const candidateQuery = `
    SELECT q.user_id, q.gender, q.location
    FROM queue q
    WHERE q.user_id <> $1
      AND ($2='any' OR q.gender=$2)
      AND ($3='any' OR q.location=$3)
    ORDER BY joined_at ASC LIMIT 1`;
  const { rows } = await pool.query(candidateQuery, [userId, genderPref, locationPref]);
  if (!rows.length) return null;

  const peerId = rows[0].user_id;
  const channelName = `omevo_${Math.min(Number(userId), Number(peerId))}_${Math.max(Number(userId), Number(peerId))}_${Date.now()}`;

  await pool.query(`INSERT INTO matches (user_a, user_b, channel_name, created_at) VALUES ($1,$2,$3,NOW())`, [userId, peerId, channelName]);
  await pool.query("DELETE FROM queue WHERE user_id = ANY($1::text[])", [[userId, peerId]]).catch(() => {});

  const peerSocketId = onlineSockets.get(String(peerId));
  if (peerSocketId) io.to(peerSocketId).emit("match_found", { peerId: userId, channel: channelName });

  const requesterSocketId = onlineSockets.get(String(userId));
  if (requesterSocketId) io.to(requesterSocketId).emit("match_found", { peerId, channel: channelName });

  return { peerId, channel: channelName };
}

// ------------------- USER PREFERENCES -------------------
app.get("/api/user/preferences", requireAuth, async (req, res) => {
  try {
    const { rows } = await pool.query("SELECT gender, location FROM users WHERE id = $1", [req.user.id]);
    if (!rows.length) return res.status(404).json({ error: "User not found" });
    res.json(rows[0]);
  } catch (err) { console.error(err); res.status(500).json({ error: "Could not fetch preferences" }); }
});

app.post("/api/user/preferences", requireAuth, async (req, res) => {
  try {
    const { gender, location } = req.body;
    await pool.query("UPDATE users SET gender=$1, location=$2, updated_at=NOW() WHERE id=$3", [gender || "any", location || "any", req.user.id]);
    res.json({ ok: true });
  } catch (err) { console.error(err); res.status(500).json({ error: "Could not save preferences" }); }
});

// ------------------- QUEUE HANDLERS -------------------
app.post("/queue/enqueue", requireAuth, async (req, res) => {
  try {
    let { gender = "any", location = "any", interests = "", nickname = "" } = req.body;
    const userId = String(req.user.id);

    if (!location || location === "any") {
      const ip = req.headers["x-forwarded-for"]?.split(",")[0] || req.socket.remoteAddress;
      const geo = geoip.lookup(ip);
      location = geo?.country?.toLowerCase() || "any";
    }

    await pool.query(
      `INSERT INTO queue (user_id, gender, location, interests, nickname, joined_at)
       VALUES ($1,$2,$3,$4,$5,NOW())
       ON CONFLICT (user_id) DO UPDATE SET gender=EXCLUDED.gender,
         location=EXCLUDED.location, interests=EXCLUDED.interests,
         nickname=EXCLUDED.nickname, joined_at=NOW()`,
      [userId, gender, location, interests, nickname]
    );

    const match = await tryFindMatch(userId, gender, location);
    if (match) return res.json({ matched: true, peerId: match.peerId, channel: match.channel });

    return res.json({ matched: false, locationUsed: location });
  } catch (err) { console.error(err); res.status(500).json({ error: "enqueue failed" }); }
});

app.post("/queue/leave", requireAuth, async (req, res) => {
  try { await pool.query("DELETE FROM queue WHERE user_id=$1", [String(req.user.id)]); return res.json({ ok: true }); } 
  catch (err) { console.error(err); res.status(500).json({ error: "leave failed" }); }
});

// ------------------- AGORA TOKEN GENERATION -------------------
const { RtcTokenBuilder, RtcRole, RtmTokenBuilder } = agora;

app.post("/generateToken", requireAuth, async (req, res) => {
  try {
    const { channelName, uid: requestedUid, role = "publisher", expirySeconds = 3600 } = req.body;
    if (!channelName) return res.status(400).json({ error: "channelName required" });

    const uid = requestedUid !== undefined ? String(requestedUid) : String(req.user.id);
    const rtcRole = role === "publisher" ? RtcRole.PUBLISHER : RtcRole.SUBSCRIBER;

    const currentTimestamp = Math.floor(Date.now() / 1000);
    const privilegeExpiredTs = currentTimestamp + Number(expirySeconds);

    const rtcToken = RtcTokenBuilder.buildTokenWithAccount(
      AGORA_APP_ID,
      AGORA_APP_CERTIFICATE,
      channelName,
      uid,
      rtcRole,
      privilegeExpiredTs
    );
    const rtmToken = RtmTokenBuilder.buildToken(AGORA_APP_ID, AGORA_APP_CERTIFICATE, uid, privilegeExpiredTs);

    return res.json({ rtcToken, rtmToken, appID: AGORA_APP_ID, uid });
  } catch (err) { console.error(err); res.status(500).json({ error: "token generation failed" }); }
});

// ------------------- BAN PAYMENT (Coinbase Commerce) -------------------
app.post("/api/pay-unban", async (req, res) => {
  try {
    const { userId } = req.body;
    const chargeData = {
      name: "Ban Removal",
      description: "Remove your account suspension",
      local_price: { amount: UNBAN_PRICE.toFixed(2), currency: "USD" },
      pricing_type: "fixed_price",
      metadata: { userId: String(userId) },
      redirect_url: `${process.env.FRONTEND_URL}/unban-success?userId=${userId}`,
      cancel_url: `${process.env.FRONTEND_URL}/unban-cancel`,
    };
    const charge = await Charge.create(chargeData);
    res.json({ url: charge.hosted_url });
  } catch (err) { console.error(err); res.status(500).json({ error: "Coinbase payment creation failed" }); }
});

// Coinbase Webhook
app.post("/api/coinbase-webhook", express.raw({ type: "application/json" }), async (req, res) => {
  const signature = req.headers["x-cc-webhook-signature"];
  try {
    const event = CoinbaseCommerce.Webhook.verifyEventBody(req.body.toString(), signature, process.env.COINBASE_COMMERCE_WEBHOOK_SECRET);

    if (event.type === "charge:confirmed" || event.type === "charge:resolved") {
      const userId = event.data.metadata?.userId;
      if (userId) {
        await pool.query("UPDATE users SET banned_until=NULL WHERE id=$1", [userId]);
        console.log(`✅ User ${userId} unbanned via Coinbase payment`);
      }
    }

    res.status(200).json({ received: true });
  } catch (err) {
    console.error("Coinbase webhook error:", err);
    res.status(400).send(`Webhook Error: ${err.message}`);
  }
});

// ------------------- MODERATION APPEAL -------------------
app.post("/api/moderation/appeal", requireAuth, async (req, res) => {
  try {
    const { message } = req.body;
    await pool.query(
      "INSERT INTO appeals (user_id, message, created_at) VALUES ($1, $2, NOW())",
      [req.user.id, message || ""]
    );
    res.json({ ok: true, message: "Appeal submitted" });
  } catch (err) {
    console.error("Appeal failed:", err);
    res.status(500).json({ error: "Could not submit appeal" });
  }
});

// ------------------- HEALTH CHECK -------------------
app.get("/health", (req, res) => res.json({ ok: true, env: process.env.NODE_ENV || "dev" }));

// ------------------- START SERVER -------------------
const PORT = process.env.PORT || 5000;
server.listen(PORT, () => console.log(`Server running on port ${PORT}`));
