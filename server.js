// server.js - Complete backend for OmeVo app
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
const { RtcTokenBuilder, RtcRole, RtmTokenBuilder } = agora;

import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import { Strategy as DiscordStrategy } from "passport-discord";
import { Strategy as FacebookStrategy } from "passport-facebook";

import Stripe from "stripe";
import OpenAI from "openai";

dotenv.config();

// ------------------- CONFIG -------------------
const app = express();
app.use(cors({ origin: true }));
app.use(express.json({ limit: "5mb" })); // for messages + frames
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
const STRIPE = new Stripe(process.env.STRIPE_SECRET_KEY || "");
const OPENAI = new OpenAI({ apiKey: process.env.OPENAI_API_KEY || "" });

const AGORA_APP_ID = process.env.AGORA_APP_ID;
const AGORA_APP_CERT = process.env.AGORA_APP_CERTIFICATE;

const BAN_HOURS = 750;
const UNBAN_PRICE = 5.99;

// ------------------- SESSION & PASSPORT -------------------
const pgSession = pgSessionImport(session);

app.use(
  session({
    store: new pgSession({
      pool: pool,                // your PostgreSQL pool
      tableName: "user_sessions" // optional table name
    }),
    secret: process.env.SESSION_SECRET || "session_secret_omevo",
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 14 * 24 * 60 * 60 * 1000 }, // 14 days
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
// Google, Discord, Facebook - upsert user if exists
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

// ------------------- OAuth ROUTES -------------------
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

  // ------------------- AUTOMATED MODERATION -------------------
  socket.on("chat_message", async ({ message }) => {
    const uid = socket.data.userId;
    if (!uid) return;
    try {
      const mod = await OPENAI.moderations.create({ model: "omni-moderation-latest", input: message });
      const flagged = mod.results?.[0]?.categories?.sexual || mod.results?.[0]?.flagged;
      if (flagged) {
        // Ban user 750 hours
        await pool.query("UPDATE users SET banned_until = NOW() + INTERVAL '750 hours' WHERE id=$1", [uid]);
        // Notify client and disconnect
        socket.emit("moderation_action", { type: "chat", message, banned: true, duration_hours: BAN_HOURS });
        socket.disconnect(true);
      } else {
        // Forward message to peers if allowed
        io.emit("chat_message", { uid, message });
      }
    } catch (err) {
      console.error("Moderation error:", err);
    }
  });

  socket.on("video_frame", async ({ frameBase64 }) => {
    const uid = socket.data.userId;
    if (!uid) return;
    try {
      const mod = await OPENAI.moderations.create({ model: "omni-moderation-latest", input: frameBase64 });
      const flagged = mod.results?.[0]?.categories?.sexual || mod.results?.[0]?.flagged;
      if (flagged) {
        await pool.query("UPDATE users SET banned_until = NOW() + INTERVAL '750 hours' WHERE id=$1", [uid]);
        socket.emit("moderation_action", { type: "video", banned: true, duration_hours: BAN_HOURS });
        socket.disconnect(true);
      }
    } catch (err) {
      console.error("Video moderation error:", err);
    }
  });
});

// ------------------- USER PROFILE ENDPOINTS -------------------

// Get user profile
app.get("/api/user/:id", requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const { rows } = await pool.query(
      `SELECT id, username, email, gender, location,
              created_at, updated_at, banned_until
       FROM users WHERE id = $1`,
      [id]
    );
    if (!rows.length) return res.status(404).json({ error: "User not found" });
    res.json(rows[0]);
  } catch (err) {
    console.error("Fetch user failed:", err);
    res.status(500).json({ error: "Could not fetch user" });
  }
});

// Update profile
app.post("/api/user/update", requireAuth, async (req, res) => {
  try {
    const { username, gender, location } = req.body;
    await pool.query(
      "UPDATE users SET username=$1, gender=$2, location=$3, updated_at=NOW() WHERE id=$4",
      [username, gender, location, req.user.id]
    );
    res.json({ ok: true });
  } catch (err) {
    console.error("Update user failed:", err);
    res.status(500).json({ error: "Could not update user" });
  }
});

// Delete account
app.delete("/api/user/delete", requireAuth, async (req, res) => {
  try {
    await pool.query("DELETE FROM users WHERE id=$1", [req.user.id]);
    res.json({ ok: true, deleted: true });
  } catch (err) {
    console.error("Delete user failed:", err);
    res.status(500).json({ error: "Could not delete user" });
  }
});


// ------------------- MATCH HISTORY -------------------

app.get("/api/matches", requireAuth, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT * FROM matches 
       WHERE user_a=$1 OR user_b=$1 
       ORDER BY created_at DESC LIMIT 50`,
      [req.user.id]
    );
    res.json(rows);
  } catch (err) {
    console.error("Fetch matches failed:", err);
    res.status(500).json({ error: "Could not fetch matches" });
  }
});

app.delete("/api/matches/:id", requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    await pool.query(
      "DELETE FROM matches WHERE id=$1 AND (user_a=$2 OR user_b=$2)",
      [id, req.user.id]
    );
    res.json({ ok: true });
  } catch (err) {
    console.error("Delete match failed:", err);
    res.status(500).json({ error: "Could not delete match" });
  }
});


// ------------------- BAN & MODERATION -------------------

// Check if user is banned + remaining time
app.get("/api/user/ban-status", requireAuth, async (req, res) => {
  try {
    const { banned_until } = req.user;
    if (!banned_until)
      return res.json({ banned: false, remaining_hours: 0, can_pay_to_unban: false });

    const now = new Date();
    const banEnd = new Date(banned_until);
    const banned = banEnd > now;
    const remainingHours = Math.max(
      0,
      Math.ceil((banEnd - now) / (1000 * 60 * 60))
    );

    res.json({
      banned,
      banned_until,
      remaining_hours: remainingHours,
      can_pay_to_unban: banned,
      unban_price: 5.99,
    });
  } catch (err) {
    console.error("Check ban failed:", err);
    res.status(500).json({ error: "Could not check ban status" });
  }
});

// Apply a 750-hour ban
app.post("/api/user/ban", requireAuth, async (req, res) => {
  try {
    const adminCheck = await pool.query("SELECT is_admin FROM users WHERE id=$1", [req.user.id]);
    if (!adminCheck.rows[0]?.is_admin)
      return res.status(403).json({ error: "Unauthorized" });

    const { targetUserId } = req.body;
    const banUntil = new Date(Date.now() + 750 * 60 * 60 * 1000); // 750 hours

    await pool.query("UPDATE users SET banned_until=$1 WHERE id=$2", [
      banUntil,
      targetUserId,
    ]);
    res.json({ ok: true, banned_until: banUntil });
  } catch (err) {
    console.error("Apply ban failed:", err);
    res.status(500).json({ error: "Could not apply ban" });
  }
});

// Pay to remove ban ($5.99)
app.post("/api/pay-unban", requireAuth, async (req, res) => {
  try {
    const userId = req.user.id;

    const session = await STRIPE.checkout.sessions.create({
      payment_method_types: ["card"],
      line_items: [
        {
          price_data: {
            currency: "usd",
            product_data: {
              name: "Ban Removal",
              description: "Remove your OmeVo account suspension immediately",
            },
            unit_amount: 599, // $5.99
          },
          quantity: 1,
        },
      ],
      mode: "payment",
      success_url: `${process.env.FRONTEND_URL}/unban-success?userId=${userId}`,
      cancel_url: `${process.env.FRONTEND_URL}/unban-cancel`,
      metadata: { userId },
    });

    res.json({ url: session.url });
  } catch (err) {
    console.error("Stripe unban payment error:", err);
    res.status(500).json({ error: "Failed to create payment session" });
  }
});

// Stripe webhook — automatically unban on successful payment
app.post(
  "/api/stripe-webhook",
  express.raw({ type: "application/json" }),
  async (req, res) => {
    const sig = req.headers["stripe-signature"];
    let event;

    try {
      event = STRIPE.webhooks.constructEvent(
        req.body,
        sig,
        process.env.STRIPE_WEBHOOK_SECRET
      );
    } catch (err) {
      console.error("Webhook signature verification failed:", err);
      return res.status(400).send(`Webhook Error: ${err.message}`);
    }

    if (event.type === "checkout.session.completed") {
      const session = event.data.object;
      const userId = session.metadata?.userId;

      if (userId) {
        try {
          await pool.query("UPDATE users SET banned_until=NULL WHERE id=$1", [userId]);
          console.log(`✅ User ${userId} unbanned after payment`);
        } catch (err) {
          console.error("DB unban error:", err);
        }
      }
    }

    res.status(200).json({ received: true });
  }
);

// Appeal a ban (optional)
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

  // save match record
  await pool.query(
    `INSERT INTO matches (user_a, user_b, channel_name, created_at) VALUES ($1,$2,$3,NOW())`,
    [userId, peerId, channelName]
  );

  // remove both from queue
  await pool.query("DELETE FROM queue WHERE user_id IN ($1,$2)", [userId, peerId]).catch(() => {});

  // notify peer if online
  const peerSocketId = onlineSockets.get(String(peerId));
  if (peerSocketId) io.to(peerSocketId).emit("match_found", { peerId: userId, channel: channelName });

  // notify requester
  const requesterSocketId = onlineSockets.get(String(userId));
  if (requesterSocketId) io.to(requesterSocketId).emit("match_found", { peerId, channel: channelName });

  return { peerId, channel: channelName };
}

// ------------------- USER PREFERENCES -------------------
app.get("/api/user/preferences", requireAuth, async (req, res) => {
  try {
    const userId = req.user.id;
    const { rows } = await pool.query(
      "SELECT gender, location FROM users WHERE id = $1",
      [userId]
    );
    if (!rows.length) return res.status(404).json({ error: "User not found" });
    res.json(rows[0]);
  } catch (err) {
    console.error("Fetch preferences failed:", err);
    res.status(500).json({ error: "Could not fetch preferences" });
  }
});

app.post("/api/user/preferences", requireAuth, async (req, res) => {
  try {
    const { gender, location } = req.body;
    await pool.query(
      "UPDATE users SET gender=$1, location=$2, updated_at=NOW() WHERE id=$3",
      [gender || "any", location || "any", req.user.id]
    );
    res.json({ ok: true });
  } catch (err) {
    console.error("Save preferences failed:", err);
    res.status(500).json({ error: "Could not save preferences" });
  }
});



app.post("/queue/enqueue", requireAuth, async (req, res) => {
  try {
    let { gender = "any", location = "any", interests = "", nickname = "" } = req.body;
    const userId = String(req.user.id);

    // Auto-detect location from IP if user did not select one
    if (location === "any" || !location) {
      const ip = req.headers["x-forwarded-for"]?.split(",")[0] || req.socket.remoteAddress;
      const geo = geoip.lookup(ip);
      if (geo && geo.country) {
        location = geo.country.toLowerCase(); // e.g. "us", "gb", "ca"
      }
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
    if (match)
      return res.json({ matched: true, peerId: match.peerId, channel: match.channel });

    return res.json({ matched: false, locationUsed: location });
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

// ------------------- AGORA TOKEN GENERATION -------------------
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
      AGORA_APP_CERT,
      channelName,
      uid,
      rtcRole,
      privilegeExpiredTs
    );
    const rtmToken = RtmTokenBuilder.buildToken(AGORA_APP_ID, AGORA_APP_CERT, uid, privilegeExpiredTs);

    return res.json({ rtcToken, rtmToken, appID: AGORA_APP_ID, uid });
  } catch (err) {
    console.error("generateToken error", err);
    res.status(500).json({ error: "token generation failed" });
  }
});

// ------------------- BAN PAYMENT -------------------
app.post("/api/pay-unban", async (req, res) => {
  try {
    const { userId } = req.body;
    const session = await stripe.checkout.sessions.create({
      payment_method_types: ["card"],
      line_items: [
        {
          price_data: {
            currency: "usd",
            product_data: {
              name: "Ban Removal",
              description: "Remove your account suspension",
            },
            unit_amount: 599, // $5.99
          },
          quantity: 1,
        },
      ],
      mode: "payment",
      success_url: `${process.env.FRONTEND_URL}/unban-success?userId=${userId}`,
      cancel_url: `${process.env.FRONTEND_URL}/unban-cancel`,
    });
    res.json({ url: session.url });
  } catch (error) {
    console.error("Stripe error:", error);
    res.status(500).json({ error: "Payment failed" });
  }
});

// Stripe webhook — to confirm payment
app.post("/api/stripe-webhook", express.raw({ type: "application/json" }), (req, res) => {
  const sig = req.headers["stripe-signature"];
  let event;

  try {
    event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    console.error("Webhook signature verification failed:", err);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  // Handle payment success event
  if (event.type === "checkout.session.completed") {
    const session = event.data.object;
    const userId = new URL(session.success_url).searchParams.get("userId");

    // TODO: unban the user in your DB
    console.log(`✅ Unbanned user: ${userId}`);
  }

  res.status(200).json({ received: true });
});

// ------------------- HEALTH CHECK -------------------
app.get("/health", (req, res) => res.json({ ok: true, env: process.env.NODE_ENV || "dev" }));

// ------------------- START SERVER -------------------
const PORT = process.env.PORT || 5000;
server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
