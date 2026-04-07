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
import rateLimit from "express-rate-limit";
import helmet from "helmet";
import NodeCache from "node-cache";
import cron from "node-cron";
import sharp from "sharp";

import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import { Strategy as DiscordStrategy } from "passport-discord";
import { Strategy as FacebookStrategy } from "passport-facebook";

import OpenAI from "openai";

dotenv.config();

// ------------------- CONFIG -------------------
const app = express();
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "'unsafe-inline'", "https://apis.google.com"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", "data:", "https:"],
        connectSrc: ["'self'", "wss:", "https://api.openai.com"],
      },
    },
  })
);

app.set('trust proxy', 1);

app.use(
  cors({
    origin: process.env.FRONTEND_URL,
  })
);

// Rate limiting
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: "Too many requests from this IP, please try again later",
  standardHeaders: true,
  legacyHeaders: false,
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // limit each IP to 5 auth requests per windowMs
  message: "Too many authentication attempts, please try again later",
  skipSuccessfulRequests: true,
});

app.use(express.json({ limit: "5mb" }));
const server = http.createServer(app);
const io = new SocketIOServer(server, {
  cors: {
    origin: process.env.FRONTEND_URL,
  },
  pingTimeout: 60000,
  pingInterval: 25000,
});

const pool = new pg.Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false,
  },
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 2000,
});

const JWT_SECRET = process.env.JWT_SECRET || "super_secret_jwt_key";
const OPENAI = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY || "",
  timeout: 30000,
  maxRetries: 2,
});

const AGORA_APP_ID = process.env.AGORA_APP_ID;
const AGORA_APP_CERTIFICATE = process.env.AGORA_APP_CERTIFICATE;

const BAN_HOURS = 750;
const UNBAN_PRICE = 5.99;
const MAX_INTERESTS = 5;
const MAX_NICKNAME_LENGTH = 20;
const MIN_AGE_FOR_VIDEO = 18; // Minimum age to use video

// Coinbase Commerce Client
const { Client, resources } = CoinbaseCommerce;
const { Charge } = resources;
Client.init(process.env.COINBASE_COMMERCE_API_KEY);

const userCache = new NodeCache({ stdTTL: 300, checkperiod: 120 });

// ------------------- SESSION & PASSPORT -------------------
const PGStore = pgSessionImport(session);

app.use(
  session({
    store: new PGStore({
      pool: pool,
      tableName: "user_sessions",
      createTableIfMissing: true,
    }),
    secret: process.env.SESSION_SECRET || "session_secret_omevo",
    resave: false,
    saveUninitialized: false,
    cookie: {
      maxAge: 14 * 24 * 60 * 60 * 1000,
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
    },
  })
);

app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
  try {
    // Check cache first
    const cachedUser = userCache.get(`user:${id}`);
    if (cachedUser) return done(null, cachedUser);

    const { rows } = await pool.query("SELECT * FROM users WHERE id=$1", [id]);
    if (rows[0]) {
      userCache.set(`user:${id}`, rows[0]);
    }
    done(null, rows[0] || null);
  } catch (err) {
    done(err, null);
  }
});

// ------------------- PASSPORT STRATEGIES -------------------
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: process.env.GOOGLE_CALLBACK_URL,
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        const email = profile.emails?.[0]?.value || null;
        const providerId = profile.id;
        const avatar = profile.photos?.[0]?.value || null;

        // Check if user is already in database
        const { rows } = await pool.query("SELECT * FROM users WHERE email=$1", [email]);

        if (rows.length > 0) {
          // Update existing user with Google info
          const updateQuery = `
          UPDATE users 
          SET provider='google', provider_id=$1, username=$2, avatar=$3, updated_at=NOW()
          WHERE id=$4
          RETURNING *`;
          const values = [providerId, profile.displayName || profile.username || email, avatar, rows[0].id];
          const result = await pool.query(updateQuery, values);
          return done(null, result.rows[0]);
        }

        // Create new user
        const text = `
        INSERT INTO users (username, email, provider, provider_id, avatar, created_at, updated_at)
        VALUES ($1,$2,'google',$3,$4,NOW(),NOW())
        RETURNING *`;
        const values = [profile.displayName || profile.username || email, email, providerId, avatar];
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
        const email = profile.email || null;
        const providerId = profile.id;
        const avatar = profile.avatar
          ? `https://cdn.discordapp.com/avatars/${profile.id}/${profile.avatar}.png`
          : null;

        // Check if user is already in database
        const { rows } = await pool.query("SELECT * FROM users WHERE email=$1", [email]);

        if (rows.length > 0) {
          // Update existing user with Discord info
          const updateQuery = `
          UPDATE users 
          SET provider='discord', provider_id=$1, username=$2, avatar=$3, updated_at=NOW()
          WHERE id=$4
          RETURNING *`;
          const values = [providerId, profile.username || profile.displayName, avatar, rows[0].id];
          const result = await pool.query(updateQuery, values);
          return done(null, result.rows[0]);
        }

        // Create new user
        const text = `
        INSERT INTO users (username, email, provider, provider_id, avatar, created_at, updated_at)
        VALUES ($1,$2,'discord',$3,$4,NOW(),NOW())
        RETURNING *`;
        const values = [profile.username || profile.displayName, email, providerId, avatar];
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
      profileFields: ["id", "displayName", "emails", "photos"],
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        const email = profile.emails?.[0]?.value || null;
        const providerId = profile.id;
        const avatar = profile.photos?.[0]?.value || null;

        // Check if user is already in database
        const { rows } = await pool.query("SELECT * FROM users WHERE email=$1", [email]);

        if (rows.length > 0) {
          // Update existing user with Facebook info
          const updateQuery = `
          UPDATE users 
          SET provider='facebook', provider_id=$1, username=$2, avatar=$3, updated_at=NOW()
          WHERE id=$4
          RETURNING *`;
          const values = [providerId, profile.displayName || profile.username, avatar, rows[0].id];
          const result = await pool.query(updateQuery, values);
          return done(null, result.rows[0]);
        }

        // Create new user
        const text = `
        INSERT INTO users (username, email, provider, provider_id, avatar, created_at, updated_at)
        VALUES ($1,$2,'facebook',$3,$4,NOW(),NOW())
        RETURNING *`;
        const values = [profile.displayName || profile.username || email, email, providerId, avatar];
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
  const payload = {
    id: user.id,
    email: user.email,
    provider: user.provider,
    iat: Math.floor(Date.now() / 1000),
  };
  return jwt.sign(payload, JWT_SECRET, { expiresIn: "14d" });
}

async function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization || req.body.token || req.query.token;
  if (!authHeader) return res.status(401).json({ error: "Missing token" });
  const token = authHeader.replace(/^Bearer\s*/i, "");
  try {
    const decoded = jwt.verify(token, JWT_SECRET);

    // Check cache first
    const cachedUser = userCache.get(`user:${decoded.id}`);
    if (cachedUser) {
      req.user = cachedUser;
      return next();
    }

    const { rows } = await pool.query("SELECT * FROM users WHERE id=$1", [decoded.id]);
    if (!rows[0]) return res.status(401).json({ error: "User not found" });

    // Cache the user
    userCache.set(`user:${decoded.id}`, rows[0]);
    req.user = rows[0];
    next();
  } catch (err) {
    return res.status(401).json({ error: "Invalid token" });
  }
}

// ------------------- OAUTH ROUTES -------------------
app.get("/auth/google", authLimiter, passport.authenticate("google", { scope: ["profile", "email"] }));
app.get(
  "/auth/google/achat",
  authLimiter,
  passport.authenticate("google", { failureRedirect: "/auth/failure", session: true }),
  (req, res) => {
    const token = signJwtForUser(req.user);
    res.redirect(`${process.env.FRONTEND_URL || "/achat"}?token=${token}`);
  }
);

app.get("/auth/discord", authLimiter, passport.authenticate("discord"));
app.get(
  "/auth/discord/achat",
  authLimiter,
  passport.authenticate("discord", { failureRedirect: "/auth/failure", session: true }),
  (req, res) => {
    const token = signJwtForUser(req.user);
    res.redirect(`${process.env.FRONTEND_URL || "/achat"}?token=${token}`);
  }
);

app.get("/auth/facebook", authLimiter, passport.authenticate("facebook", { scope: ["email"] }));
app.get(
  "/auth/facebook/callback",
  authLimiter,
  passport.authenticate("facebook", { failureRedirect: "/auth/failure", session: true }),
  (req, res) => {
    const token = signJwtForUser(req.user);
    res.redirect(`${process.env.FRONTEND_URL || "https://omevo.online"}/achat.html?token=${token}`);
  }
);

app.get("/auth/me", async (req, res) => {
  try {
    await requireAuth(req, res, async () => {
      return res.json({
        authenticated: true,
        user: req.user,
      });
    });
  } catch {
    res.json({ authenticated: false });
  }
});

app.get("/auth/failure", (req, res) => res.status(401).json({ error: "Authentication failed" }));

// ------------------- SOCKET.IO -------------------
const onlineSockets = new Map();
const userRooms = new Map(); // Track which room each user is in
const roomParticipants = new Map(); // Track participants in each room

function requireSocketUser(socket) {
  if (!socket.data.userId) {
    return null;
  }
  return socket.data.userId;
}

// Function to detect and report suspicious behavior
async function detectSuspiciousBehavior(userId, action, metadata = {}) {
  try {
    // Log the activity
    await pool.query("INSERT INTO user_activity (user_id, action, metadata, created_at) VALUES ($1, $2, $3, NOW())", [
      userId,
      action,
      JSON.stringify(metadata),
    ]);

    // Check for patterns of suspicious behavior
    const { rows } = await pool.query(
      `SELECT COUNT(*) as count FROM user_activity 
       WHERE user_id=$1 AND action=$2 AND created_at > NOW() - INTERVAL '1 hour'`,
      [userId, action]
    );

    // If user has performed the same action more than 50 times in an hour, flag for review
    if (parseInt(rows[0].count) > 50) {
      await pool.query("INSERT INTO flagged_users (user_id, reason, created_at) VALUES ($1, $2, NOW())", [
        userId,
        `Suspicious activity: ${action} performed ${rows[0].count} times in an hour`,
      ]);
    }
  } catch (err) {
    console.error("Error detecting suspicious behavior:", err);
  }
}

io.on("connection", (socket) => {
  console.log("User connected:", socket.id);

  // Frontend emits 'auth' event with token. We handle it here.
  socket.on("auth", async ({ token }) => {
    try {
      if (!token) {
        return socket.emit("error", { message: "Authentication token required" });
      }

      const decoded = jwt.verify(token, JWT_SECRET);
      
      // Fetch user from DB or Cache
      let user = userCache.get(`user:${decoded.id}`);
      if (!user) {
        const { rows } = await pool.query("SELECT * FROM users WHERE id=$1", [decoded.id]);
        if (rows[0]) {
            user = rows[0];
            userCache.set(`user:${decoded.id}`, user);
        } else {
            throw new Error("User not found");
        }
      }

      // Attach user info to socket
      socket.data.userId = user.id;
      socket.data.user = user;
      
      // Register in online sockets map
      onlineSockets.set(String(user.id), socket.id);
      
      console.log(`User ${user.username} authenticated on socket ${socket.id}`);
      
      // Notify client they are authenticated
      socket.emit("authenticated", { userId: user.id });

    } catch (err) {
      console.error("Socket auth error:", err.message);
      socket.emit("error", { message: "Authentication failed" });
    }
  });

  // JOIN ROOM (Basic)
  socket.on("join", async ({ room, uid, name }) => {
    socket.join(room);
    console.log(`${name || uid} joined room ${room}`);
    socket.to(room).emit("message", {
      username: "System",
      text: `${name || uid} joined the chat`,
    });
  });

  // TYPING
  socket.on("typing", ({ room }) => {
    socket.to(room).emit("typing");
  });

  // DISCONNECT
  socket.on("disconnect", () => {
    console.log("User disconnected:", socket.id);
    
    // Remove user from onlineSockets map
    if (socket.data.userId) {
        onlineSockets.delete(String(socket.data.userId));
        
        // Optional: Leave queue on disconnect
        pool.query("DELETE FROM queue WHERE user_id=$1", [String(socket.data.userId)]).catch(() => {});
    }
  });

  // Detailed Message Handler
  socket.on("message", async ({ room, text }) => {
    const uid = requireSocketUser(socket);
    if (!uid) return socket.emit("error", { message: "Not authenticated" });

    try {
      // Check if user is in a room
      const userRoom = userRooms.get(uid);
      if (!userRoom || (room && !userRoom.includes(room))) {
        socket.emit("error", { message: "You're not in this room" });
        return;
      }

      // Check message length
      if (text.length > 500) {
        socket.emit("error", { message: "Message too long" });
        return;
      }

      // Detect suspicious behavior
      await detectSuspiciousBehavior(uid, "chat_message", { length: text.length });

      // Moderate the message
      const mod = await OPENAI.moderations.create({
        model: "omni-moderation-latest",
        input: text,
      });

      const flagged =
        mod.results?.[0]?.categories?.sexual ||
        mod.results?.[0]?.categories?.hate ||
        mod.results?.[0]?.categories?.violence ||
        mod.results?.[0]?.flagged;

      if (flagged) {
        const banReason = `Inappropriate message: ${mod.results[0].category_scores}`;
        await pool.query("UPDATE users SET banned_until = NOW() + INTERVAL '750 hours', ban_reason=$1 WHERE id=$2", [
          banReason,
          uid,
        ]);

        socket.emit("moderation_action", {
          type: "chat",
          text,
          banned: true,
          duration_hours: BAN_HOURS,
          reason: banReason,
        });

        // Log the ban
        await pool.query("INSERT INTO moderation_logs (user_id, action, reason, created_at) VALUES ($1, $2, $3, NOW())", [
          uid,
          "auto_ban",
          banReason,
        ]);

        socket.disconnect(true);
        return;
      }

      // Save message to database
      const { rows } = await pool.query(
        "INSERT INTO chat_messages (user_id, room_id, message, created_at) VALUES ($1, $2, $3, NOW()) RETURNING *",
        [uid, room || userRoom[0], text]
      );

      // Broadcast to room
      const messageData = {
        id: rows[0].id,
        uid,
        text,
        timestamp: rows[0].created_at,
        username: socket.data.user.username,
      };

      if (room) {
        io.to(room).emit("message", messageData);
      } else {
        io.to(userRoom[0]).emit("message", messageData);
      }
    } catch (err) {
      console.error("Chat message error:", err);
      socket.emit("error", { message: "Failed to send message" });
    }
  });

  socket.on("name-update", async ({ room, name }) => {
    const uid = requireSocketUser(socket);
    if (!uid) return;

    try {
      // Check if user is in a room
      const userRoom = userRooms.get(uid);
      if (!userRoom || (room && !userRoom.includes(room))) {
        return;
      }

      // Update username in database
      await pool.query("UPDATE users SET username=$1, updated_at=NOW() WHERE id=$2", [name, uid]);

      // Update cache
      const updatedUser = { ...socket.data.user, username: name };
      userCache.set(`user:${uid}`, updatedUser);
      socket.data.user = updatedUser;

      // Broadcast to room
      if (room) {
        io.to(room).emit("name-update", { name, uid });
      } else {
        io.to(userRoom[0]).emit("name-update", { name, uid });
      }
    } catch (err) {
      console.error("Name update error:", err);
    }
  });

  // Video Frame Logic
  let lastFrameModeration = 0;

  socket.on("video_frame", async ({ frameBase64, roomId }) => {
    const uid = requireSocketUser(socket);
    if (!uid) return;

    // Rate limit frame moderation
    if (Date.now() - lastFrameModeration < 1000) return;
    lastFrameModeration = Date.now();

    try {
      // Check if user is in a room
      const userRoom = userRooms.get(uid);
      if (!userRoom || (roomId && !userRoom.includes(roomId))) {
        return;
      }

      // Detect suspicious behavior
      await detectSuspiciousBehavior(uid, "video_frame");

      // Process image with sharp
      const buffer = Buffer.from(frameBase64.split(",")[1], "base64");

      const processedImage = await sharp(buffer)
        .resize({ width: 320, height: 240, fit: "inside" })
        .jpeg({ quality: 70 })
        .toBuffer();

      const processedBase64 = `data:image/jpeg;base64,${processedImage.toString("base64")}`;

      // Moderation
      const mod = await OPENAI.moderations.create({
        model: "omni-moderation-latest",
        input: processedBase64,
      });

      const result = mod.results?.[0];

      const flagged =
        result?.flagged || result?.categories?.sexual || result?.categories?.violence || result?.categories?.hate;

      // ONLY RUN BAN LOGIC IF FLAGGED
      if (flagged) {
        const banReason = `Inappropriate content detected`;

        await pool.query("UPDATE users SET banned_until = NOW() + INTERVAL '750 hours', ban_reason=$1 WHERE id=$2", [
          banReason,
          uid,
        ]);

        await pool.query(
          "INSERT INTO moderation_logs (user_id, action, reason, created_at) VALUES ($1, $2, $3, NOW())",
          [uid, "auto_ban", banReason]
        );

        socket.emit("moderation_action", {
          type: "video",
          banned: true,
          duration_hours: BAN_HOURS,
          reason: banReason,
        });

        socket.disconnect(true);
        return;
      }

      // Forward frame to the other user
      const targetRoom = roomId || userRoom[0];
      const participants = roomParticipants.get(targetRoom) || [];

      const otherUserId = participants.find((id) => id !== uid);

      if (otherUserId) {
        const otherSocketId = onlineSockets.get(String(otherUserId));

        if (otherSocketId) {
          io.to(otherSocketId).emit("video_frame", {
            frameBase64: processedBase64,
            from: uid,
          });
        }
      }
    } catch (err) {
      console.error("Video moderation error:", err);
    }
  });

  socket.on("join_room", async ({ room }) => {
    if (!room) return;

    const uid = requireSocketUser(socket);
    if (!uid) return;

    try {
      // Check if user is already in a room
      const currentRooms = userRooms.get(uid) || [];
      if (currentRooms.length > 0) {
        // Leave current rooms
        currentRooms.forEach((r) => {
          socket.leave(r);
          socket.to(r).emit("peer_left", { socketId: socket.id, userId: uid });

          // Update room participants
          const participants = roomParticipants.get(r);
          if (participants) {
            const index = participants.indexOf(uid);
            if (index > -1) {
              participants.splice(index, 1);
              roomParticipants.set(r, participants);
            }
          }
        });
      }

      // Join new room
      socket.join(room);

      // Update user rooms
      userRooms.set(uid, [room]);

      // Update room participants
      const participants = roomParticipants.get(room) || [];
      participants.push(uid);
      roomParticipants.set(room, participants);

      // Notify other participants
      socket.to(room).emit("peer_joined", {
        socketId: socket.id,
        userId: uid,
        username: socket.data.user.username,
      });

      // Get existing messages for this room
      const { rows } = await pool.query("SELECT * FROM chat_messages WHERE room_id=$1 ORDER BY created_at DESC LIMIT 50", [
        room,
      ]);

      // Send recent messages to the user
      socket.emit("room_history", {
        messages: rows.reverse().map((msg) => ({
          id: msg.id,
          uid: msg.user_id,
          message: msg.message,
          timestamp: msg.created_at,
        })),
      });

      // Log room join
      await pool.query("INSERT INTO room_activity (user_id, room_id, action, created_at) VALUES ($1, $2, $3, NOW())", [
        uid,
        room,
        "join",
      ]);
    } catch (err) {
      console.error("Error joining room:", err);
      socket.emit("error", { message: "Failed to join room" });
    }
  });

  socket.on("leave_room", async ({ room }) => {
    if (!room) return;

    const uid = requireSocketUser(socket);
    if (!uid) return;

    try {
      socket.leave(room);

      // Update user rooms
      const currentRooms = userRooms.get(uid) || [];
      const index = currentRooms.indexOf(room);
      if (index > -1) {
        currentRooms.splice(index, 1);
        userRooms.set(uid, currentRooms);
      }

      // Update room participants
      const participants = roomParticipants.get(room) || [];
      const participantIndex = participants.indexOf(uid);
      if (participantIndex > -1) {
        participants.splice(participantIndex, 1);
        roomParticipants.set(room, participants);
      }

      // Notify other participants
      socket.to(room).emit("peer_left", { socketId: socket.id, userId: uid });

      // Log room leave
      await pool.query("INSERT INTO room_activity (user_id, room_id, action, created_at) VALUES ($1, $2, $3, NOW())", [
        uid,
        room,
        "leave",
      ]);
    } catch (err) {
      console.error("Error leaving room:", err);
      socket.emit("error", { message: "Failed to leave room" });
    }
  });

  socket.on("report_user", async ({ reportedUserId, reason, roomId }) => {
    const uid = requireSocketUser(socket);
    if (!uid) return;

    try {
      // Validate reason
      if (!reason || reason.length < 10 || reason.length > 200) {
        socket.emit("error", { message: "Invalid report reason" });
        return;
      }

      // Check if user is in a room with the reported user
      const userRoom = userRooms.get(uid);
      const reportedUserRoom = userRooms.get(reportedUserId);

      if (!userRoom || !reportedUserRoom || !userRoom.some((r) => reportedUserRoom.includes(r))) {
        socket.emit("error", { message: "You can only report users in the same room" });
        return;
      }

      // Check if user already reported this user in the last 24 hours
      const { rows } = await pool.query(
        `SELECT COUNT(*) as count FROM user_reports 
         WHERE reporter_id=$1 AND reported_id=$2 AND created_at > NOW() - INTERVAL '24 hours'`,
        [uid, reportedUserId]
      );

      if (parseInt(rows[0].count) > 0) {
        socket.emit("error", { message: "You already reported this user recently" });
        return;
      }

      // Save report
      await pool.query("INSERT INTO user_reports (reporter_id, reported_id, reason, room_id, created_at) VALUES ($1, $2, $3, $4, NOW())", [
        uid,
        reportedUserId,
        reason,
        roomId,
      ]);

      // Check if user has been reported multiple times
      const {
        rows: reportCount,
      } = await pool.query(
        `SELECT COUNT(*) as count FROM user_reports 
         WHERE reported_id=$1 AND created_at > NOW() - INTERVAL '24 hours'`,
        [reportedUserId]
      );

      // If user has been reported 3+ times in 24 hours, auto-ban
      if (parseInt(reportCount[0].count) >= 3) {
        await pool.query("UPDATE users SET banned_until = NOW() + INTERVAL '168 hours', ban_reason=$1 WHERE id=$2", [
          "Multiple user reports",
          reportedUserId,
        ]);

        // Notify the reported user
        const reportedSocketId = onlineSockets.get(String(reportedUserId));
        if (reportedSocketId) {
          io.to(reportedSocketId).emit("banned", {
            reason: "Multiple user reports",
            until: new Date(Date.now() + 168 * 60 * 60 * 1000),
            canAppeal: true,
          });

          // Disconnect the user
          io.sockets.sockets.get(reportedSocketId)?.disconnect(true);
        }
      }

      socket.emit("report_submitted", { message: "Report submitted successfully" });
    } catch (err) {
      console.error("Error reporting user:", err);
      socket.emit("error", { message: "Failed to submit report" });
    }
  });
});

// ------------------- API ROUTES -------------------

// Create Stripe Checkout Session
app.post("/api/create-checkout-session", requireAuth, async (req, res) => {
  try {
    const { coins, price } = req.body;

    // Use Environment Variable instead of hardcoded key
    const stripe = require("stripe")(process.env.STRIPE_SECRET_KEY); 

    const session = await stripe.checkout.sessions.create({
      payment_method_types: ["card"],
      line_items: [
        {
          price_data: {
            currency: "usd",
            product_data: {
              name: `${coins} ChatVibe Coins`,
              description: `Purchase ${coins} coins for sending virtual gifts`,
              // Ensure you have a valid image URL or remove this line
              images: ["https://your-domain.com/coins-image.png"], 
            },
            unit_amount: Math.round(price * 100), // Convert to cents
          },
          quantity: 1,
        },
      ],
      mode: "payment",
      success_url: `${process.env.FRONTEND_URL}?payment=success&session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${process.env.FRONTEND_URL}?payment=cancelled`,
      customer_email: req.user.email,
      metadata: {
        userId: req.user.id,
        coins: coins.toString(),
      },
    });

    res.json({ sessionId: session.id });
  } catch (error) {
    console.error("Error creating checkout session:", error);
    res.status(500).json({ error: "Failed to create payment session" });
  }
});

// Verify Payment and Update Coins
app.post("/api/verify-payment", requireAuth, async (req, res) => {
  try {
    const { sessionId } = req.body;

    // Initialize Stripe
    const stripe = require("stripe")(process.env.STRIPE_SECRET_KEY);

    // Retrieve the session
    const session = await stripe.checkout.sessions.retrieve(sessionId);

    if (session.payment_status === "paid") {
      const coins = parseInt(session.metadata.coins);
      const userId = session.metadata.userId;

      // Update user's coin balance
      await pool.query("UPDATE users SET coins = coins + $1, updated_at = NOW() WHERE id = $2", [coins, userId]);

      // Get updated user data
      const { rows } = await pool.query("SELECT coins FROM users WHERE id = $1", [userId]);

      // Log transaction
      await pool.query(
        "INSERT INTO coin_transactions (user_id, coins, amount, transaction_id, created_at) VALUES ($1, $2, $3, $4, NOW())",
        [userId, coins, session.amount_total / 100, sessionId]
      );

      // Invalidate cache for user
      userCache.del(`user:${userId}`);

      res.json({
        success: true,
        coins: rows[0].coins,
      });
    } else {
      res.json({ success: false });
    }
  } catch (error) {
    console.error("Error verifying payment:", error);
    res.status(500).json({ error: "Failed to verify payment" });
  }
});

// Add coins column to users table if not exists
async function ensureCoinsColumn() {
  try {
    await pool.query(`
      ALTER TABLE users 
      ADD COLUMN IF NOT EXISTS coins INTEGER DEFAULT 0
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS coin_transactions (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        coins INTEGER NOT NULL,
        amount DECIMAL(10,2) NOT NULL,
        transaction_id VARCHAR(255),
        created_at TIMESTAMP DEFAULT NOW()
      )
    `);
  } catch (error) {
    console.error("Error ensuring coins column:", error);
  }
}

// Call this when server starts
ensureCoinsColumn();

// Spend coins endpoint
app.post("/api/user/spend-coins", requireAuth, async (req, res) => {
  try {
    const { coins, type, giftType, recipientId } = req.body;

    // Check if user has enough coins
    const { rows } = await pool.query("SELECT coins FROM users WHERE id = $1", [req.user.id]);

    if (rows[0].coins < coins) {
      return res.status(400).json({ error: "Insufficient coins" });
    }

    // Deduct coins
    await pool.query("UPDATE users SET coins = coins - $1, updated_at = NOW() WHERE id = $2", [coins, req.user.id]);

    // Log transaction
    await pool.query(
      "INSERT INTO coin_transactions (user_id, coins, amount, transaction_type, gift_type, recipient_id, created_at) VALUES ($1, $2, $3, $4, $5, $6, NOW())",
      [req.user.id, -coins, 0, type, giftType, recipientId]
    );
    
    // Invalidate cache
    userCache.del(`user:${req.user.id}`);

    res.json({ success: true });
  } catch (error) {
    console.error("Error spending coins:", error);
    res.status(500).json({ error: "Failed to spend coins" });
  }
});

// ------------------- MATCHMAKING -------------------
async function tryFindMatch(userId, genderPref, locationPref, interests = []) {
  const candidateQuery = `
    SELECT q.user_id, q.gender, q.location, q.interests, q.nickname, u.username, u.avatar
    FROM queue q
    JOIN users u ON q.user_id = u.id
    WHERE q.user_id <> $1
      AND ($2='any' OR q.gender=$2)
      AND ($3='any' OR q.location=$3)
      AND (u.banned_until IS NULL OR u.banned_until < NOW())
    ORDER BY 
      CASE WHEN $4::text[] && q.interests THEN 1 ELSE 2 END,
      joined_at ASC 
    LIMIT 1`;

  const { rows } = await pool.query(candidateQuery, [userId, genderPref, locationPref, interests]);
  if (!rows.length) return null;

  const peerId = rows[0].user_id;
  const channelName = `omevo_${Math.min(Number(userId), Number(peerId))}_${Math.max(Number(userId), Number(peerId))}_${Date.now()}`;

  // 1. Insert match record
  await pool.query(`INSERT INTO matches (user_a, user_b, channel_name, created_at) VALUES ($1,$2,$3,NOW())`, [
    userId,
    peerId,
    channelName,
  ]);

  // 2. Fetch requester info BEFORE deleting from queue
  const { rows: requesterRows } = await pool.query(
    "SELECT username, nickname, avatar, gender, location, interests FROM users WHERE id = $1",
    [userId]
  );

  // 3. Delete from queue
  await pool.query("DELETE FROM queue WHERE user_id = ANY($1::text[])", [[userId, peerId]]).catch(() => {});

  // 4. Emit to Peer
  const peerSocketId = onlineSockets.get(String(peerId));
  if (peerSocketId) {
    io.to(peerSocketId).emit("match_found", {
      peerId: userId,
      channel: channelName,
      peerInfo: {
        username: requesterRows[0]?.username,
        nickname: requesterRows[0]?.nickname,
        avatar: requesterRows[0]?.avatar,
        gender: requesterRows[0]?.gender,
        location: requesterRows[0]?.location,
        interests: requesterRows[0]?.interests,
      },
    });
  }

  // 5. Emit to Requester
  const requesterSocketId = onlineSockets.get(String(userId));
  if (requesterSocketId) {
    io.to(requesterSocketId).emit("match_found", {
      peerId,
      channel: channelName,
      peerInfo: {
        username: rows[0].username,
        nickname: rows[0].nickname,
        avatar: rows[0].avatar,
        gender: rows[0].gender,
        location: rows[0].location,
        interests: rows[0].interests,
      },
    });
  }

  return { peerId, channel: channelName };
}

// ------------------- USER PREFERENCES -------------------
app.get("/api/user/preferences", requireAuth, async (req, res) => {
  try {
    const { rows } = await pool.query("SELECT gender, location, interests, age_verified FROM users WHERE id = $1", [
      req.user.id,
    ]);
    if (!rows.length) return res.status(404).json({ error: "User not found" });
    res.json(rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Could not fetch preferences" });
  }
});

app.post("/api/user/preferences", requireAuth, async (req, res) => {
  try {
    let { gender = "any", location = "any", interests = [], nickname = "" } = req.body;

    // Validate inputs
    if (nickname && (nickname.length > MAX_NICKNAME_LENGTH || nickname.length < 1)) {
      return res.status(400).json({ error: `Nickname must be between 1 and ${MAX_NICKNAME_LENGTH} characters` });
    }

    if (!Array.isArray(interests) || interests.length > MAX_INTERESTS) {
      return res.status(400).json({ error: `You can have up to ${MAX_INTERESTS} interests` });
    }

    // Filter out invalid interests
    interests = interests.filter((interest) => typeof interest === "string" && interest.length > 0 && interest.length <= 30);

    const userId = String(req.user.id);

    if (!location || location === "any") {
      const ip = req.headers["x-forwarded-for"]?.split(",")[0] || req.socket.remoteAddress;
      const geo = geoip.lookup(ip);
      location = geo?.country?.toLowerCase() || "any";
    }

    if (req.user.banned_until && new Date(req.user.banned_until) > new Date()) {
      return res.status(403).json({ error: "Account banned" });
    }

    await pool.query(
      `UPDATE users 
       SET gender=$1, location=$2, interests=$3, nickname=$4, updated_at=NOW()
       WHERE id=$5`,
      [gender || "any", location || "any", interests, nickname || "", userId]
    );

    // Update cache
    const updatedUser = { ...req.user, gender, location, interests, nickname };
    userCache.set(`user:${userId}`, updatedUser);

    res.json({ ok: true, locationUsed: location });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Could not save preferences" });
  }
});

// ------------------- AGE VERIFICATION -------------------
app.post("/api/user/verify-age", requireAuth, async (req, res) => {
  try {
    const { age } = req.body;

    if (!age || isNaN(age)) {
      return res.status(400).json({ error: "Valid age required" });
    }

    if (age < MIN_AGE_FOR_VIDEO) {
      return res.status(400).json({ error: `You must be at least ${MIN_AGE_FOR_VIDEO} to use video features` });
    }

    await pool.query("UPDATE users SET age_verified=$1, updated_at=NOW() WHERE id=$2", [true, req.user.id]);

    // Update cache
    const updatedUser = { ...req.user, age_verified: true };
    userCache.set(`user:${req.user.id}`, updatedUser);

    res.json({ ok: true });
  } catch (err) {
    console.error("Age verification failed:", err);
    res.status(500).json({ error: "Could not verify age" });
  }
});

// ------------------- QUEUE HANDLERS -------------------
app.post("/queue/enqueue", requireAuth, async (req, res) => {
  try {
    let { gender = "any", location = "any", interests = [], nickname = "" } = req.body;
    const userId = String(req.user.id);

    // Check if user is already in a match
    const { rows: activeMatch } = await pool.query("SELECT * FROM matches WHERE (user_a=$1 OR user_b=$1) AND ended_at IS NULL", [
      userId,
    ]);

    if (activeMatch.length > 0) {
      return res.status(400).json({ error: "You're already in a match" });
    }

    if (!location || location === "any") {
      const ip = req.headers["x-forwarded-for"]?.split(",")[0] || req.socket.remoteAddress;
      const geo = geoip.lookup(ip);
      location = geo?.country?.toLowerCase() || "any";
    }

    if (req.user.banned_until && new Date(req.user.banned_until) > new Date()) {
      return res.status(403).json({ error: "Account banned" });
    }

    // Check if user is age verified for video
    if (!req.user.age_verified) {
      return res.status(403).json({ error: "Age verification required for video features" });
    }

    // Validate inputs
    if (nickname && (nickname.length > MAX_NICKNAME_LENGTH || nickname.length < 1)) {
      return res.status(400).json({ error: `Nickname must be between 1 and ${MAX_NICKNAME_LENGTH} characters` });
    }

    if (!Array.isArray(interests) || interests.length > MAX_INTERESTS) {
      return res.status(400).json({ error: `You can have up to ${MAX_INTERESTS} interests` });
    }

    // Filter out invalid interests
    interests = interests.filter((interest) => typeof interest === "string" && interest.length > 0 && interest.length <= 30);

    await pool.query(
      `INSERT INTO queue (user_id, gender, location, interests, nickname, joined_at)
       VALUES ($1,$2,$3,$4,$5,NOW())
       ON CONFLICT (user_id) DO UPDATE SET gender=EXCLUDED.gender,
         location=EXCLUDED.location, interests=EXCLUDED.interests,
         nickname=EXCLUDED.nickname, joined_at=NOW()`,
      [userId, gender || "any", location || "any", interests, nickname]
    );

    const match = await tryFindMatch(userId, gender || "any", location || "any", interests);
    if (match) return res.json({ matched: true, peerId: match.peerId, channel: match.channel });

    return res.json({ matched: false, locationUsed: location });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "enqueue failed" });
  }
});

// QUEUE CHECK ENDPOINT
app.get("/queue/check", requireAuth, async (req, res) => {
  try {
    const userId = String(req.user.id);
    
    // Check if user has been matched in the database
    const { rows } = await pool.query(
      "SELECT * FROM matches WHERE (user_a=$1 OR user_b=$1) AND created_at > NOW() - INTERVAL '30 seconds' AND ended_at IS NULL LIMIT 1",
      [userId]
    );

    if (rows.length > 0) {
      const match = rows[0];
      const peerId = match.user_a === userId ? match.user_b : match.user_a;
      
      // Fetch peer info
      const { rows: peerRows } = await pool.query("SELECT username, nickname, avatar, gender, location, interests FROM users WHERE id=$1", [peerId]);
      
      return res.json({ 
        matched: true, 
        peerId, 
        channel: match.channel_name,
        peerInfo: peerRows[0]
      });
    }
    
    return res.json({ matched: false });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "queue check failed" });
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
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "token generation failed" });
  }
});

app.post("/user/display-name", requireAuth, async (req, res) => {
  try {
    const { display_name } = req.body;

    if (!display_name || display_name.length > MAX_NICKNAME_LENGTH) {
      return res.status(400).json({ error: `Display name must be between 1 and ${MAX_NICKNAME_LENGTH} characters` });
    }

    // Check for profanity
    const mod = await OPENAI.moderations.create({
      model: "omni-moderation-latest",
      input: display_name,
    });

    if (mod.results?.[0]?.flagged) {
      return res.status(400).json({ error: "Display name contains inappropriate content" });
    }

    await pool.query("UPDATE users SET username=$1, updated_at=NOW() WHERE id=$2", [display_name, req.user.id]);

    // Update cache
    const updatedUser = { ...req.user, username: display_name };
    userCache.set(`user:${req.user.id}`, updatedUser);

    res.json({ ok: true });
  } catch (err) {
    console.error("Display name update failed:", err);
    res.status(500).json({ error: "Could not update name" });
  }
});

app.get("/user/profile", requireAuth, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT id, username, email, provider, avatar, gender, location,
       interests, nickname, age_verified, created_at, updated_at, coins
       FROM users WHERE id=$1`,
      [req.user.id]
    );

    if (!rows.length) return res.status(404).json({ error: "User not found" });

    const user = rows[0]; 

    // FIX: Use userCache instead of undefined redis
    userCache.set(`user:${user.id}`, user);

    res.json({
      ...user,
      display_name: user.username,
      is_admin: user.role === "admin",
    });
  } catch (err) {
    res.status(500).json({ error: "Could not fetch profile" });
  }
});

// ------------------- AVATAR UPLOAD -------------------
app.post("/api/user/avatar", requireAuth, async (req, res) => {
  try {
    const { avatarBase64 } = req.body;

    if (!avatarBase64) {
      return res.status(400).json({ error: "Avatar image required" });
    }

    // Process and validate image
    const buffer = Buffer.from(avatarBase64.split(",")[1], "base64");
    const metadata = await sharp(buffer).metadata();

    // Check image size and format
    if (metadata.width > 500 || metadata.height > 500) {
      return res.status(400).json({ error: "Avatar must be at most 500x500 pixels" });
    }

    if (!["jpeg", "jpg", "png", "webp"].includes(metadata.format)) {
      return res.status(400).json({ error: "Avatar must be in JPEG, PNG, or WebP format" });
    }

    // Moderate the avatar
    const mod = await OPENAI.moderations.create({
      model: "omni-moderation-latest",
      input: avatarBase64,
    });

    if (mod.results?.[0]?.flagged) {
      return res.status(400).json({ error: "Avatar contains inappropriate content" });
    }

    // Resize and optimize the image
    const processedImage = await sharp(buffer)
      .resize({ width: 200, height: 200, fit: "cover" })
      .jpeg({ quality: 80 })
      .toBuffer();

    // Convert to base64
    const processedBase64 = `data:image/jpeg;base64,${processedImage.toString("base64")}`;

    // Generate a unique filename
    const filename = `avatar_${req.user.id}_${Date.now()}.jpg`;

    // Update user avatar in database
    await pool.query("UPDATE users SET avatar=$1, updated_at=NOW() WHERE id=$2", [processedBase64, req.user.id]);

    // Update cache
    const updatedUser = { ...req.user, avatar: processedBase64 };
    userCache.set(`user:${req.user.id}`, updatedUser);

    res.json({ ok: true, avatar: processedBase64 });
  } catch (err) {
    console.error("Avatar upload failed:", err);
    res.status(500).json({ error: "Could not upload avatar" });
  }
});

// ------------------- BAN PAYMENT (Coinbase Commerce) -------------------
app.post("/api/pay-unban", async (req, res) => {
  try {
    const { userId } = req.body;

    // Validate user exists and is banned
    const { rows } = await pool.query("SELECT * FROM users WHERE id=$1 AND banned_until > NOW()", [userId]);

    if (!rows.length) {
      return res.status(400).json({ error: "User not found or not banned" });
    }

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
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Coinbase payment creation failed" });
  }
});

// Coinbase Webhook
app.post("/api/coinbase-webhook", express.raw({ type: "application/json" }), async (req, res) => {
  const signature = req.headers["x-cc-webhook-signature"];
  try {
    const event = CoinbaseCommerce.Webhook.verifyEventBody(
      req.body.toString(),
      signature,
      process.env.COINBASE_COMMERCE_WEBHOOK_SECRET
    );

    if (event.type === "charge:confirmed" || event.type === "charge:resolved") {
      const userId = event.data.metadata?.userId;
      if (userId) {
        await pool.query("UPDATE users SET banned_until=NULL, ban_reason=NULL WHERE id=$1", [userId]);

        // Log the unban
        await pool.query("INSERT INTO moderation_logs (user_id, action, reason, created_at) VALUES ($1, $2, $3, NOW())", [
          userId,
          "paid_unban",
          "User paid for unban",
        ]);

        console.log(`✅ User ${userId} unbanned via Coinbase payment`);

        // Invalidate cache
        userCache.del(`user:${userId}`);
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

    if (!message || message.length < 10 || message.length > 500) {
      return res.status(400).json({ error: "Appeal message must be between 10 and 500 characters" });
    }

    // Check if user already has a pending appeal
    const { rows } = await pool.query("SELECT * FROM appeals WHERE user_id=$1 AND status='pending'", [req.user.id]);

    if (rows.length > 0) {
      return res.status(400).json({ error: "You already have a pending appeal" });
    }

    await pool.query("INSERT INTO appeals (user_id, message, status, created_at) VALUES ($1, $2, 'pending', NOW())", [
      req.user.id,
      message,
    ]);

    res.json({ ok: true, message: "Appeal submitted successfully" });
  } catch (err) {
    console.error("Appeal failed:", err);
    res.status(500).json({ error: "Could not submit appeal" });
  }
});

// ------------------- ADMIN APPEALS -------------------
app.get("/api/admin/appeals", requireAuth, async (req, res) => {
  try {
    // Check if user is admin
    if (req.user.role !== "admin") {
      return res.status(403).json({ error: "Admin access required" });
    }

    const { rows } = await pool.query(
      `SELECT a.*, u.username, u.email 
       FROM appeals a 
       JOIN users u ON a.user_id = u.id 
       WHERE a.status='pending' 
       ORDER BY a.created_at DESC`
    );

    res.json(rows);
  } catch (err) {
    console.error("Failed to fetch appeals:", err);
    res.status(500).json({ error: "Could not fetch appeals" });
  }
});

app.post("/api/admin/appeals/:id/respond", requireAuth, async (req, res) => {
  try {
    // Check if user is admin
    if (req.user.role !== "admin") {
      return res.status(403).json({ error: "Admin access required" });
    }

    const { id } = req.params;
    const { approved, response } = req.body;

    if (approved === undefined) {
      return res.status(400).json({ error: "Approval status required" });
    }

    // Get appeal details
    const { rows } = await pool.query("SELECT * FROM appeals WHERE id=$1", [id]);

    if (!rows.length) {
      return res.status(404).json({ error: "Appeal not found" });
    }

    const appeal = rows[0];

    // Update appeal status
    await pool.query("UPDATE appeals SET status=$1, admin_response=$2, admin_id=$3, reviewed_at=NOW() WHERE id=$4", [
      approved ? "approved" : "rejected",
      response,
      req.user.id,
      id,
    ]);

    // If approved, unban the user
    if (approved) {
      await pool.query("UPDATE users SET banned_until=NULL, ban_reason=NULL WHERE id=$1", [appeal.user_id]);

      // Log the unban
      await pool.query("INSERT INTO moderation_logs (user_id, action, reason, created_at) VALUES ($1, $2, $3, NOW())", [
        appeal.user_id,
        "appeal_approved",
        "Appeal approved by admin",
      ]);

      // Invalidate cache
      userCache.del(`user:${appeal.user_id}`);
    }

    res.json({ ok: true });
  } catch (err) {
    console.error("Failed to respond to appeal:", err);
    res.status(500).json({ error: "Could not respond to appeal" });
  }
});

// ------------------- ADMIN USER MANAGEMENT -------------------
app.get("/api/admin/users", requireAuth, async (req, res) => {
  try {
    // Check if user is admin
    if (req.user.role !== "admin") {
      return res.status(403).json({ error: "Admin access required" });
    }

    const { query } = req.query;
    if (!query) {
      return res.status(400).json({ error: "Search query required" });
    }

    const { rows } = await pool.query(
      `SELECT id, username, email, banned_until, ban_reason 
       FROM users 
       WHERE username ILIKE $1 OR email ILIKE $1
       LIMIT 20`,
      [`%${query}%`]
    );

    res.json({ users: rows });
  } catch (err) {
    console.error("Failed to search users:", err);
    res.status(500).json({ error: "Could not search users" });
  }
});

app.post("/api/admin/ban", requireAuth, async (req, res) => {
  try {
    // Check if user is admin
    if (req.user.role !== "admin") {
      return res.status(403).json({ error: "Admin access required" });
    }

    const { userId } = req.body;
    if (!userId) {
      return res.status(400).json({ error: "User ID required" });
    }

    // Ban user for 30 days
    const banUntil = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);

    await pool.query("UPDATE users SET banned_until=$1, ban_reason=$2, updated_at=NOW() WHERE id=$3", [
      banUntil,
      "Banned by admin",
      userId,
    ]);

    // Log the ban
    await pool.query("INSERT INTO moderation_logs (user_id, action, reason, created_at) VALUES ($1, $2, $3, NOW())", [
      userId,
      "admin_ban",
      "Banned by admin",
    ]);

    // Invalidate cache
    userCache.del(`user:${userId}`);

    // Disconnect user if online
    const socketId = onlineSockets.get(String(userId));
    if (socketId) {
      io.sockets.sockets.get(socketId)?.emit("banned", {
        reason: "Banned by admin",
        until: banUntil,
        canAppeal: true,
      });
      io.sockets.sockets.get(socketId)?.disconnect(true);
    }

    res.json({ ok: true });
  } catch (err) {
    console.error("Failed to ban user:", err);
    res.status(500).json({ error: "Could not ban user" });
  }
});

app.post("/api/admin/unban", requireAuth, async (req, res) => {
  try {
    // Check if user is admin
    if (req.user.role !== "admin") {
      return res.status(403).json({ error: "Admin access required" });
    }

    const { userId } = req.body;
    if (!userId) {
      return res.status(400).json({ error: "User ID required" });
    }

    await pool.query("UPDATE users SET banned_until=NULL, ban_reason=NULL, updated_at=NOW() WHERE id=$1", [userId]);

    // Log the unban
    await pool.query("INSERT INTO moderation_logs (user_id, action, reason, created_at) VALUES ($1, $2, $3, NOW())", [
      userId,
      "admin_unban",
      "Unbanned by admin",
    ]);

    // Invalidate cache
    userCache.del(`user:${userId}`);

    res.json({ ok: true });
  } catch (err) {
    console.error("Failed to unban user:", err);
    res.status(500).json({ error: "Could not unban user" });
  }
});

// ------------------- MATCH HISTORY -------------------
app.get("/api/user/match-history", requireAuth, async (req, res) => {
  try {
    const { page = 1, limit = 10 } = req.query;
    const offset = (page - 1) * limit;

    const { rows } = await pool.query(
      `SELECT m.*, 
       CASE WHEN m.user_a = $1 THEN m.user_b ELSE m.user_a END as partner_id,
       u.username as partner_username,
       u.avatar as partner_avatar
       FROM matches m
       JOIN users u ON (CASE WHEN m.user_a = $1 THEN m.user_b ELSE m.user_a END) = u.id
       WHERE (m.user_a = $1 OR m.user_b = $1)
       ORDER BY m.created_at DESC
       LIMIT $2 OFFSET $3`,
      [req.user.id, limit, offset]
    );

    // Get total count for pagination
    const { rows: countRows } = await pool.query("SELECT COUNT(*) as total FROM matches WHERE user_a = $1 OR user_b = $1", [
      req.user.id,
    ]);

    res.json({
      matches: rows,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total: parseInt(countRows[0].total),
        pages: Math.ceil(countRows[0].total / limit),
      },
    });
  } catch (err) {
    console.error("Failed to fetch match history:", err);
    res.status(500).json({ error: "Could not fetch match history" });
  }
});

// ------------------- HEALTH CHECK -------------------
app.get("/health", (req, res) => {
  res.json({
    ok: true,
    env: process.env.NODE_ENV || "dev",
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
  });
});

// ------------------- SCHEDULED TASKS -------------------
// Clean up old data daily at 3 AM
cron.schedule("0 3 * * *", async () => {
  try {
    console.log("Running daily cleanup task");

    // Delete old chat messages (older than 30 days)
    await pool.query("DELETE FROM chat_messages WHERE created_at < NOW() - INTERVAL '30 days'");

    // Delete old user activity logs (older than 90 days)
    await pool.query("DELETE FROM user_activity WHERE created_at < NOW() - INTERVAL '90 days'");

    // Delete resolved appeals (older than 180 days)
    await pool.query(
      "DELETE FROM appeals WHERE status IN ('approved', 'rejected') AND reviewed_at < NOW() - INTERVAL '180 days'"
    );

    console.log("Daily cleanup task completed");
  } catch (err) {
    console.error("Error in daily cleanup task:", err);
  }
});

// ------------------- START SERVER -------------------
const PORT = process.env.PORT || 5000;
server.listen(PORT, () => console.log(`Server running on port ${PORT}`));
