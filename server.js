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
import CoinbaseCommerce from "coinbase-commerce-node";
import rateLimit from "express-rate-limit";
import helmet from "helmet";
import NodeCache from "node-cache";
import cron from "node-cron";
import sharp from "sharp";
import Stripe from "stripe";
import os from "os";
import { AwaitQueue } from "await-queue";
import * as mediasoup from "mediasoup";
import mediasoupPrebuilt from "mediasoup-prebuilt";

import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import { Strategy as DiscordStrategy } from "passport-discord";
import { Strategy as FacebookStrategy } from "passport-facebook";

import OpenAI from "openai";

dotenv.config();

// ============================================================
// 🎬 MEDIASOUP CONFIGURATION
// ============================================================

const MEDIASOUP_CONFIG = {
  worker: {
    rtcMinPort: parseInt(process.env.MEDIASOUP_WORKER_RTC_MIN_PORT) || 40000,
    rtcMaxPort: parseInt(process.env.MEDIASOUP_WORKER_RTC_MAX_PORT) || 49999,
    logLevel: "warn",
    logTags: ["info", "ice", "dtls", "rtp", "srtp", "rtcp", "rtx", "bwe", "score", "simulcast", "svc"],
  },
  router: {
    mediaCodecs: [
      {
        kind: "audio",
        mimeType: "audio/opus",
        clockRate: 48000,
        channels: 2,
        parameters: {
          useinbandfec: 1,
          usedtx: 1,
        },
      },
      {
        kind: "video",
        mimeType: "video/VP8",
        clockRate: 90000,
        parameters: {
          "x-google-start-bitrate": 1000,
        },
      },
      {
        kind: "video",
        mimeType: "video/VP9",
        clockRate: 90000,
        parameters: {
          "x-google-start-bitrate": 1000,
          profileId: 2,
        },
      },
      {
        kind: "video",
        mimeType: "video/H264",
        clockRate: 90000,
        parameters: {
          "packetization-mode": 1,
          "profile-level-id": "4d0032",
          "x-google-start-bitrate": 1000,
        },
      },
    ],
  },
  webRtcTransport: {
    listenIps: [
      {
        ip: "0.0.0.0",
        announcedIp: process.env.MEDIASOUP_ANNOUNCED_IP || undefined,
      },
    ],
    initialAvailableOutgoingBitrate: 1000000,
    minimumAvailableOutgoingBitrate: 600000,
    maxSctpMessageSize: 262144,
    enableUdp: true,
    enableTcp: true,
    preferUdp: true,
  },
  plainTransport: {
    listenIp: {
      ip: "0.0.0.0",
      announcedIp: process.env.MEDIASOUP_ANNOUNCED_IP || undefined,
    },
  },
};

// ============================================================
// 🏠 MEDIASOUP ROOM & PEER MANAGEMENT
// ============================================================

class MediaSoupRoom {
  constructor(roomId, router) {
    this.roomId = roomId;
    this.router = router;
    this.peers = new Map(); // peerId -> Peer
    this.createdAt = Date.now();
    this.closed = false;
  }

  addPeer(peer) {
    this.peers.set(peer.id, peer);
  }

  removePeer(peerId) {
    const peer = this.peers.get(peerId);
    if (peer) {
      peer.close();
      this.peers.delete(peerId);
    }
  }

  getPeer(peerId) {
    return this.peers.get(peerId);
  }

  getPeers() {
    return Array.from(this.peers.values());
  }

  close() {
    this.closed = true;
    for (const peer of this.peers.values()) {
      peer.close();
    }
    this.peers.clear();
    this.router.close().catch(() => {});
  }
}

class MediaSoupPeer {
  constructor({ id, socket, room, user }) {
    this.id = id;
    this.socket = socket;
    this.room = room;
    this.user = user;
    this.sendTransport = null;
    this.recvTransport = null;
    this.producers = new Map(); // producerId -> Producer
    this.consumers = new Map(); // consumerId -> Consumer
    this.dataProducers = new Map();
    this.dataConsumers = new Map();
    this.closed = false;
  }

  close() {
    this.closed = true;
    
    for (const producer of this.producers.values()) {
      producer.close().catch(() => {});
    }
    this.producers.clear();

    for (const consumer of this.consumers.values()) {
      consumer.close().catch(() => {});
    }
    this.consumers.clear();

    for (const dataProducer of this.dataProducers.values()) {
      dataProducer.close().catch(() => {});
    }
    this.dataProducers.clear();

    for (const dataConsumer of this.dataConsumers.values()) {
      dataConsumer.close().catch(() => {});
    }
    this.dataConsumers.clear();

    if (this.sendTransport) {
      this.sendTransport.close().catch(() => {});
    }
    if (this.recvTransport) {
      this.recvTransport.close().catch(() => {});
    }
  }

  getJson() {
    return {
      id: this.id,
      userId: this.user?.id,
      username: this.user?.username || "User",
      nickname: this.user?.nickname || "",
      avatar: this.user?.avatar || "",
      gender: this.user?.gender || "any",
      location: this.user?.location || "any",
      interests: this.user?.interests || [],
      producers: Array.from(this.producers.keys()),
      consumers: Array.from(this.consumers.keys()),
    };
  }
}

// ============================================================
// 🚀 GLOBAL MEDIASOUP STATE
// ============================================================

let mediasoupWorker = null;
let mediasoupWorkers = [];
let nextWorkerIndex = 0;
const rooms = new Map(); // roomId -> MediaSoupRoom
const peerQueues = new Map(); // peerId -> AwaitQueue (prevents race conditions)

function getPeerQueue(peerId) {
  if (!peerQueues.has(peerId)) {
    peerQueues.set(peerId, new AwaitQueue());
  }
  return peerQueues.get(peerId);
}

function removePeerQueue(peerId) {
  const queue = peerQueues.get(peerId);
  if (queue) {
    queue.close().catch(() => {});
    peerQueues.delete(peerId);
  }
}

// ============================================================
// 🏭 MEDIASOUP WORKER SETUP
// ============================================================

async function createMediasoupWorkers() {
  const numWorkers = Math.min(os.cpus().length, 4);
  console.log(`🎬 Creating ${numWorkers} mediasoup worker(s)...`);

  for (let i = 0; i < numWorkers; i++) {
    try {
      const worker = await mediasoup.createWorker({
        logLevel: MEDIASOUP_CONFIG.worker.logLevel,
        logTags: MEDIASOUP_CONFIG.worker.logTags,
        rtcMinPort: MEDIASOUP_CONFIG.worker.rtcMinPort,
        rtcMaxPort: MEDIASOUP_CONFIG.worker.rtcMaxPort,
      });

      worker.on("died", () => {
        console.error(`❌ Mediasoup worker ${worker.pid} died!`);
        process.exit(1);
      });

      mediasoupWorkers.push(worker);
      console.log(`✅ Mediasoup worker ${i + 1} created (pid: ${worker.pid})`);
    } catch (err) {
      console.error(`❌ Failed to create mediasoup worker ${i + 1}:`, err.message);
    }
  }

  if (mediasoupWorkers.length === 0) {
    throw new Error("Failed to create any mediasoup workers");
  }

  mediasoupWorker = mediasoupWorkers[0];
  console.log(`🎬 Mediasoup initialized with ${mediasoupWorkers.length} worker(s)`);
}

async function getMediasoupWorker() {
  const worker = mediasoupWorkers[nextWorkerIndex];
  nextWorkerIndex = (nextWorkerIndex + 1) % mediasoupWorkers.length;
  return worker;
}

async function createRoom(roomId) {
  if (rooms.has(roomId)) {
    return rooms.get(roomId);
  }

  const worker = await getMediasoupWorker();
  const router = await worker.createRouter({
    mediaCodecs: MEDIASOUP_CONFIG.router.mediaCodecs,
  });

  const room = new MediaSoupRoom(roomId, router);
  rooms.set(roomId, room);

  // Audio levels observer for active speaker detection
  room.audioLevelObserver = await router.createAudioLevelObserver({
    maxEntries: 1,
    threshold: -80,
    interval: 1000,
  });

  room.audioLevelObserver.on("volumes", (volumes) => {
    for (const { producer, volume } of volumes) {
      const peerId = producer.appData.peerId;
      const peer = room.getPeer(peerId);
      if (peer && !peer.closed) {
        peer.socket.emit("audio-level", { 
          peerId, 
          volume: Math.round(volume) 
        });
      }
    }
  });

  console.log(`🎬 Room created: ${roomId} (workers: ${mediasoupWorkers.length})`);
  return room;
}

async function closeRoom(roomId) {
  const room = rooms.get(roomId);
  if (room) {
    room.close();
    rooms.delete(roomId);
    console.log(`🎬 Room closed: ${roomId}`);
  }
}

// ============================================================
// 🎬 MEDIASOUP TRANSPORT & PRODUCER/CONSUMER HELPERS
// ============================================================

async function createWebRtcTransport(router, peerSocket) {
  const transport = await router.createWebRtcTransport(MEDIASOUP_CONFIG.webRtcTransport);

  transport.on("dtlsstatechange", (dtlsState) => {
    if (dtlsState === "closed" || dtlsState === "failed") {
      transport.close().catch(() => {});
    }
  });

  transport.on("icestatechange", (iceState) => {
    if (iceState === "failed" || iceState === "disconnected") {
      // Don't immediately close - ICE can recover
      peerSocket.emit("ice-state-change", { iceState });
    }
  });

  return {
    transport,
    params: {
      id: transport.id,
      iceParameters: transport.iceParameters,
      iceCandidates: transport.iceCandidates,
      dtlsParameters: transport.dtlsParameters,
      sctpParameters: transport.sctpParameters,
    },
  };
}

async function createProducer(peer, { kind, rtpParameters, appData = {} }) {
  const producer = await peer.sendTransport.produce({
    kind,
    rtpParameters,
    appData: { ...appData, peerId: peer.id },
  });

  producer.on("score", (score) => {
    peer.socket.emit("producer-score", { producerId: producer.id, score });
  });

  producer.on("videoorientationchange", (videoOrientation) => {
    peer.socket.emit("video-orientation", { producerId: producer.id, videoOrientation });
  });

  peer.producers.set(producer.id, producer);

  // If audio producer, observe it for active speaker
  if (kind === "audio" && peer.room.audioLevelObserver) {
    try {
      await peer.room.audioLevelObserver.addProducer({ producerId: producer.id });
    } catch (err) {
      console.error("Failed to add producer to audio level observer:", err.message);
    }
  }

  return producer;
}

async function consume({ peer, producer, rtpCapabilities }) {
  if (!peer.room.router.canConsume({ producerId: producer.id, rtpCapabilities })) {
    throw new Error("Cannot consume this producer");
  }

  const consumer = await peer.recvTransport.consume({
    producerId: producer.id,
    rtpCapabilities,
    paused: true, // Start paused, resume after client ack
  });

  consumer.on("score", (score) => {
    peer.socket.emit("consumer-score", { consumerId: consumer.id, score });
  });

  consumer.on("layerschange", (layers) => {
    peer.socket.emit("consumer-layers-change", { consumerId: consumer.id, layers });
  });

  peer.consumers.set(consumer.id, consumer);

  return {
    consumer,
    params: {
      id: consumer.id,
      producerId: producer.id,
      kind: consumer.kind,
      rtpParameters: consumer.rtpParameters,
      type: consumer.type,
      producerPaused: consumer.producerPaused,
    },
  };
}

async function createDataProducer(peer, { label, protocol, appData = {}, sctpStreamParameters }) {
  const dataProducer = await peer.sendTransport.produceData({
    label,
    protocol,
    sctpStreamParameters,
    appData: { ...appData, peerId: peer.id },
  });

  peer.dataProducers.set(dataProducer.id, dataProducer);
  return dataProducer;
}

async function consumeData({ peer, dataProducer }) {
  const dataConsumer = await peer.recvTransport.consumeData({
    dataProducerId: dataProducer.id,
  });

  peer.dataConsumers.set(dataConsumer.id, dataConsumer);
  
  dataConsumer.on("message", (message, ppid) => {
    peer.socket.emit("data-message", {
      fromPeerId: dataProducer.appData.peerId,
      label: dataConsumer.label,
      message,
      ppid,
    });
  });

  return {
    dataConsumer,
    params: {
      id: dataConsumer.id,
      dataProducerId: dataProducer.id,
      label: dataConsumer.label,
      protocol: dataConsumer.protocol,
      sctpStreamParameters: dataConsumer.sctpStreamParameters,
    },
  };
}

// ============================================================
// 📡 BROADCAST HELPERS
// ============================================================

async function broadcastNewPeer(room, newPeer) {
  const peerInfo = newPeer.getJson();
  for (const peer of room.getPeers()) {
    if (peer.id !== newPeer.id && !peer.closed) {
      peer.socket.emit("new-peer", { peer: peerInfo });
    }
  }
}

async function closePeerAndNotify(peer) {
  const room = peer.room;
  const peerInfo = peer.getJson();

  // Close all consumers of this peer
  for (const consumer of peer.consumers.values()) {
    consumer.close().catch(() => {});
  }
  peer.consumers.clear();

  // Close all data consumers
  for (const dataConsumer of peer.dataConsumers.values()) {
    dataConsumer.close().catch(() => {});
  }
  peer.dataConsumers.clear();

  // Close transports
  if (peer.sendTransport) peer.sendTransport.close().catch(() => {});
  if (peer.recvTransport) peer.recvTransport.close().catch(() => {});

  // Notify other peers
  for (const otherPeer of room.getPeers()) {
    if (otherPeer.id !== peer.id && !otherPeer.closed) {
      // Close all consumers that were consuming this peer's producers
      for (const consumer of otherPeer.consumers.values()) {
        if (consumer.appData?.peerId === peer.id) {
          otherPeer.socket.emit("consumer-closed", { consumerId: consumer.id });
          consumer.close().catch(() => {});
        }
      }

      // Close data consumers
      for (const dataConsumer of otherPeer.dataConsumers.values()) {
        if (dataConsumer.appData?.peerId === peer.id) {
          otherPeer.socket.emit("data-consumer-closed", { dataConsumerId: dataConsumer.id });
          dataConsumer.close().catch(() => {});
        }
      }

      otherPeer.consumers.delete(peer.id);
      otherPeer.socket.emit("peer-left", { peerId: peer.id, peer: peerInfo });
    }
  }

  // Remove peer from room
  room.removePeer(peer.id);
  removePeerQueue(peer.id);
}

// ============================================================
// 🚀 REST OF YOUR APP CONFIG
// ============================================================

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
        mediaSrc: ["'self'", "blob:"],
      },
    },
  })
);

app.set("trust proxy", 1);

app.use(
  cors({
    origin: process.env.FRONTEND_URL,
  })
);

const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: "Too many requests from this IP, please try again later",
  standardHeaders: true,
  legacyHeaders: false,
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
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
  maxPayload: 10 * 1024 * 1024,
});

const pool = new pg.Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000,
});

const JWT_SECRET = process.env.JWT_SECRET || "super_secret_jwt_key";

const IS_MODERATION_ENABLED = process.env.OPENAI_API_KEY && 
                               !process.env.OPENAI_API_KEY.includes('sk-xxxx') &&
                               !process.env.OPENAI_API_KEY.includes('sk-test');

const OPENAI = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY || "",
  timeout: 30000,
  maxRetries: 2,
});

const BAN_HOURS = 750;
const UNBAN_PRICE = 5.99;
const MAX_INTERESTS = 5;
const MAX_NICKNAME_LENGTH = 20;
const MIN_AGE_FOR_VIDEO = 18;

const MATCH_WEIGHTS = { location: 40, interests: 30, freshness: 20, gender: 10 };
const ANTI_REPEAT_WINDOW_HOURS = 2;
const MAX_CANDIDATES_TO_SCAN = 100;
const MATCH_LOCK_TTL = 5;

const GIFT_COIN_COSTS = {
  rose: 10, heart: 25, star: 50, diamond: 100, crown: 200, rocket: 500
};

const stripe = process.env.STRIPE_SECRET_KEY ? new Stripe(process.env.STRIPE_SECRET_KEY) : null;

let ChargeResource = null;
if (process.env.COINBASE_COMMERCE_API_KEY) {
  try {
    const { Client, resources } = CoinbaseCommerce;
    Client.init(process.env.COINBASE_COMMERCE_API_KEY);
    ChargeResource = resources.Charge;
  } catch (err) {
    console.error("Coinbase Commerce init failed:", err.message);
  }
}

const userCache = new NodeCache({ stdTTL: 300, checkperiod: 120 });

// ============================================================
// 🔄 REDIS & ADAPTER
// ============================================================

let redisClient = null;
let useRedisForMatching = false;

async function initRedis() {
  if (!process.env.REDIS_URL) {
    console.log("⚠️  No REDIS_URL — running in single-instance mode");
    return;
  }
  try {
    const { createClient } = await import("redis");
    const { createAdapter } = await import("@socket.io/redis-adapter");
    const pubClient = createClient({ url: process.env.REDIS_URL });
    const subClient = pubClient.duplicate();
    await pubClient.connect();
    await subClient.connect();
    redisClient = pubClient;
    io.adapter(createAdapter(pubClient, subClient));
    useRedisForMatching = true;
    console.log("✅ Socket.IO Redis adapter connected");
  } catch (err) {
    console.warn("⚠️  Redis adapter failed:", err.message);
  }
}

// ============================================================
// 👤 ONLINE TRACKING
// ============================================================

const onlineSockets = new Map();

async function setUserOnline(userId, socketId) {
  onlineSockets.set(String(userId), socketId);
  if (redisClient) {
    try { await redisClient.set(`socket:online:${userId}`, socketId, { EX: 3600 }); } catch {}
  }
}

async function getUserSocketId(userId) {
  if (redisClient) {
    try {
      const sid = await redisClient.get(`socket:online:${userId}`);
      if (sid) return sid;
    } catch {}
  }
  return onlineSockets.get(String(userId));
}

async function setUserOffline(userId) {
  onlineSockets.delete(String(userId));
  if (redisClient) {
    try { await redisClient.del(`socket:online:${userId}`); } catch {}
  }
}

// ============================================================
// 🏠 ROOM HELPERS
// ============================================================

function getSocketRooms(socket) {
  const rooms = [];
  for (const room of socket.rooms) {
    if (room !== socket.id) rooms.push(room);
  }
  return rooms;
}

function isInRoom(socket, room) {
  return socket.rooms.has(room);
}

// ============================================================
// 🚀 MATCHMAKING ENGINE
// ============================================================

const localMatchQueue = new Map();

async function redisQueueAdd(entry) {
  if (!redisClient) return false;
  try {
    const key = `matchq:${entry.userId}`;
    await redisClient.hSet(key, {
      userId: String(entry.userId),
      socketId: entry.socketId,
      gender: entry.gender || "any",
      looking_for: entry.looking_for || "any",
      location: entry.location || "any",
      interests: JSON.stringify(entry.interests || []),
      nickname: entry.nickname || "",
      username: entry.username || "",
      avatar: entry.avatar || "",
      ts: String(entry.ts),
    });
    await redisClient.zAdd("match_queue", { score: entry.ts, value: String(entry.userId) });
    await redisClient.expire(key, 3600);
    return true;
  } catch (err) {
    console.error("Redis queue add error:", err.message);
    return false;
  }
}

async function redisQueueRemove(userId) {
  if (!redisClient) return false;
  try {
    await redisClient.zRem("match_queue", String(userId));
    await redisClient.del(`matchq:${userId}`);
    return true;
  } catch (err) {
    console.error("Redis queue remove error:", err.message);
    return false;
  }
}

async function redisQueueGetAll() {
  if (!redisClient) return [];
  try {
    const userIds = await redisClient.zRange("match_queue", 0, -1);
    const entries = [];
    for (const uid of userIds) {
      const data = await redisClient.hGetAll(`matchq:${uid}`);
      if (data && data.userId) {
        entries.push({
          ...data,
          interests: JSON.parse(data.interests || "[]"),
          ts: parseInt(data.ts),
        });
      }
    }
    return entries;
  } catch (err) {
    console.error("Redis queue get error:", err.message);
    return [];
  }
}

async function redisQueueGetCount() {
  if (!redisClient) return 0;
  try { return await redisClient.zCard("match_queue"); } catch { return 0; }
}

async function acquireMatchLock(userId) {
  if (!redisClient) return true;
  try {
    const result = await redisClient.set(`lock:match:${userId}`, "1", { NX: true, EX: MATCH_LOCK_TTL });
    return result === "OK";
  } catch (err) { return false; }
}

async function releaseMatchLock(userId) {
  if (!redisClient) return;
  try { await redisClient.del(`lock:match:${userId}`); } catch {}
}

async function getRecentMatchPartners(userId, limit = 20) {
  try {
    const { rows } = await pool.query(
      `SELECT CASE WHEN user_a = $1 THEN user_b ELSE user_a END as partner_id
       FROM matches WHERE (user_a = $1 OR user_b = $1)
       AND created_at > NOW() - INTERVAL '${ANTI_REPEAT_WINDOW_HOURS} hours'
       ORDER BY created_at DESC LIMIT $2`,
      [userId, limit]
    );
    return new Set(rows.map(r => String(r.partner_id)));
  } catch (err) {
    return new Set();
  }
}

function calculateMatchScore(a, b, aWaitTime, bWaitTime) {
  let score = 0;
  if (a.location === b.location && a.location !== "any") score += MATCH_WEIGHTS.location;
  else if (a.location === "any" || b.location === "any") score += MATCH_WEIGHTS.location * 0.5;

  const aInterests = new Set(a.interests || []);
  const bInterests = new Set(b.interests || []);
  let overlapCount = 0;
  for (const interest of aInterests) { if (bInterests.has(interest)) overlapCount++; }
  const maxInterests = Math.max(aInterests.size, bInterests.size, 1);
  score += MATCH_WEIGHTS.interests * (overlapCount / maxInterests);

  const maxWait = Math.max(aWaitTime, bWaitTime, 1000);
  score += MATCH_WEIGHTS.freshness * ((aWaitTime + bWaitTime) / 2) / maxWait;

  const aWantsB = a.looking_for === "any" || a.looking_for === b.gender;
  const bWantsA = b.looking_for === "any" || b.looking_for === a.gender;
  if (aWantsB && bWantsA) score += MATCH_WEIGHTS.gender;
  else if (aWantsB || bWantsA) score += MATCH_WEIGHTS.gender * 0.5;

  return score;
}

async function tryMatchForUser(requesterUserId) {
  const now = Date.now();
  const lockAcquired = await acquireMatchLock(requesterUserId);
  if (!lockAcquired) return null;

  try {
    let allEntries = useRedisForMatching ? await redisQueueGetAll() : Array.from(localMatchQueue.values());
    const requester = allEntries.find(e => String(e.userId) === String(requesterUserId));
    if (!requester) return null;

    const recentPartners = await getRecentMatchPartners(requesterUserId);
    let bestCandidate = null;
    let bestScore = -1;
    let candidatesEvaluated = 0;

    for (const candidate of allEntries) {
      if (String(candidate.userId) === String(requesterUserId)) continue;
      if (recentPartners.has(String(candidate.userId))) continue;
      if (candidatesEvaluated >= MAX_CANDIDATES_TO_SCAN) break;

      const requesterWantsCandidate = requester.looking_for === "any" || requester.looking_for === candidate.gender;
      const candidateWantsRequester = candidate.looking_for === "any" || candidate.looking_for === requester.gender;
      if (!requesterWantsCandidate || !candidateWantsRequester) continue;

      const score = calculateMatchScore(requester, candidate, now - (requester.ts || now), now - (candidate.ts || now));
      if (score > bestScore) { bestScore = score; bestCandidate = candidate; }
      candidatesEvaluated++;
    }

    if (!bestCandidate || bestScore < 20) return null;

    const requesterSocketId = await getUserSocketId(String(requesterUserId));
    const candidateSocketId = await getUserSocketId(String(bestCandidate.userId));
    if (!requesterSocketId || !candidateSocketId) {
      if (!requesterSocketId) await removeFromQueue(requesterUserId);
      if (!candidateSocketId) await removeFromQueue(bestCandidate.userId);
      return null;
    }

    const candidateLockAcquired = await acquireMatchLock(bestCandidate.userId);
    if (!candidateLockAcquired) return null;

    try {
      await removeFromQueue(requesterUserId);
      await removeFromQueue(bestCandidate.userId);

      const roomId = `room_${Math.min(Number(requesterUserId), Number(bestCandidate.userId))}_${Math.max(Number(requesterUserId), Number(bestCandidate.userId))}_${Date.now()}`;
      
      await pool.query(
        `INSERT INTO matches (user_a, user_b, channel_name, created_at) VALUES ($1, $2, $3, NOW())`,
        [requesterUserId, bestCandidate.userId, roomId]
      );

      // Create mediasoup room
      await createRoom(roomId);

      const requesterInfo = {
        username: requester.username || "User", nickname: requester.nickname || "",
        avatar: requester.avatar || "", gender: requester.gender || "any",
        location: requester.location || "any", interests: requester.interests || [],
      };

      const candidateInfo = {
        username: bestCandidate.username || "User", nickname: bestCandidate.nickname || "",
        avatar: bestCandidate.avatar || "", gender: bestCandidate.gender || "any",
        location: bestCandidate.location || "any", interests: bestCandidate.interests || [],
      };

      io.to(requesterSocketId).emit("match_found", {
        peerId: bestCandidate.userId,
        roomId,
        peerInfo: candidateInfo,
        score: Math.round(bestScore),
        signaling: "mediasoup",
      });

      io.to(candidateSocketId).emit("match_found", {
        peerId: requesterUserId,
        roomId,
        peerInfo: requesterInfo,
        score: Math.round(bestScore),
        signaling: "mediasoup",
      });

      console.log(`✅ Matched ${requesterUserId} ↔ ${bestCandidate.userId} (room: ${roomId})`);
      return { peerId: bestCandidate.userId, roomId };
    } finally {
      await releaseMatchLock(bestCandidate.userId);
    }
  } finally {
    await releaseMatchLock(requesterUserId);
  }
}

async function removeFromQueue(userId) {
  const uid = String(userId);
  localMatchQueue.delete(uid);
  if (useRedisForMatching) await redisQueueRemove(uid);
  await pool.query("DELETE FROM queue WHERE user_id=$1", [uid]).catch(() => {});
}

async function getQueueCount() {
  return useRedisForMatching ? await redisQueueGetCount() : localMatchQueue.size;
}

// ============================================================
// 🔐 SESSION & PASSPORT (unchanged)
// ============================================================

const PGStore = pgSessionImport(session);

app.use(session({
  store: new PGStore({ pool, tableName: "user_sessions", createTableIfMissing: true }),
  secret: process.env.SESSION_SECRET || "session_secret_omevo",
  resave: false, saveUninitialized: false,
  cookie: { maxAge: 14 * 24 * 60 * 60 * 1000, httpOnly: true, secure: process.env.NODE_ENV === "production", sameSite: "lax" },
}));

app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
  try {
    const cachedUser = userCache.get(`user:${id}`);
    if (cachedUser) return done(null, cachedUser);
    const { rows } = await pool.query("SELECT * FROM users WHERE id=$1", [id]);
    if (rows[0]) userCache.set(`user:${id}`, rows[0]);
    done(null, rows[0] || null);
  } catch (err) { done(err, null); }
});

// Passport strategies (same as before)
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID, clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: process.env.GOOGLE_CALLBACK_URL,
}, async (accessToken, refreshToken, profile, done) => {
  try {
    const email = profile.emails?.[0]?.value || null;
    const { rows } = await pool.query("SELECT * FROM users WHERE email=$1", [email]);
    if (rows.length > 0) {
      const result = await pool.query(`UPDATE users SET provider='google', provider_id=$1, username=$2, avatar=$3, updated_at=NOW() WHERE id=$4 RETURNING *`,
        [profile.id, profile.displayName || email, profile.photos?.[0]?.value, rows[0].id]);
      return done(null, result.rows[0]);
    }
    const result = await pool.query(`INSERT INTO users (username, email, provider, provider_id, avatar, created_at, updated_at) VALUES ($1,$2,'google',$3,$4,NOW(),NOW()) RETURNING *`,
      [profile.displayName || email, email, profile.id, profile.photos?.[0]?.value]);
    done(null, result.rows[0]);
  } catch (err) { done(err, null); }
}));

passport.use(new DiscordStrategy({
  clientID: process.env.DISCORD_CLIENT_ID, clientSecret: process.env.DISCORD_CLIENT_SECRET,
  callbackURL: process.env.DISCORD_CALLBACK_URL, scope: ["identify", "email"],
}, async (accessToken, refreshToken, profile, done) => {
  try {
    const email = profile.email || null;
    const avatar = profile.avatar ? `https://cdn.discordapp.com/avatars/${profile.id}/${profile.avatar}.png` : null;
    const { rows } = await pool.query("SELECT * FROM users WHERE email=$1", [email]);
    if (rows.length > 0) {
      const result = await pool.query(`UPDATE users SET provider='discord', provider_id=$1, username=$2, avatar=$3, updated_at=NOW() WHERE id=$4 RETURNING *`,
        [profile.id, profile.username, avatar, rows[0].id]);
      return done(null, result.rows[0]);
    }
    const result = await pool.query(`INSERT INTO users (username, email, provider, provider_id, avatar, created_at, updated_at) VALUES ($1,$2,'discord',$3,$4,NOW(),NOW()) RETURNING *`,
      [profile.username, email, profile.id, avatar]);
    done(null, result.rows[0]);
  } catch (err) { done(err, null); }
}));

passport.use(new FacebookStrategy({
  clientID: process.env.FACEBOOK_APP_ID, clientSecret: process.env.FACEBOOK_APP_SECRET,
  callbackURL: process.env.FACEBOOK_CALLBACK_URL, profileFields: ["id", "displayName", "emails", "photos"],
}, async (accessToken, refreshToken, profile, done) => {
  try {
    const email = profile.emails?.[0]?.value || null;
    const { rows } = await pool.query("SELECT * FROM users WHERE email=$1", [email]);
    if (rows.length > 0) {
      const result = await pool.query(`UPDATE users SET provider='facebook', provider_id=$1, username=$2, avatar=$3, updated_at=NOW() WHERE id=$4 RETURNING *`,
        [profile.id, profile.displayName, profile.photos?.[0]?.value, rows[0].id]);
      return done(null, result.rows[0]);
    }
    const result = await pool.query(`INSERT INTO users (username, email, provider, provider_id, avatar, created_at, updated_at) VALUES ($1,$2,'facebook',$3,$4,NOW(),NOW()) RETURNING *`,
      [profile.displayName, email, profile.id, profile.photos?.[0]?.value]);
    done(null, result.rows[0]);
  } catch (err) { done(err, null); }
}));

function signJwtForUser(user) {
  return jwt.sign({ id: user.id, email: user.email, provider: user.provider }, JWT_SECRET, { expiresIn: "14d" });
}

async function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization || req.body.token || req.query.token;
  if (!authHeader) return res.status(401).json({ error: "Missing token" });
  const token = authHeader.replace(/^Bearer\s*/i, "");
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const cachedUser = userCache.get(`user:${decoded.id}`);
    if (cachedUser) { req.user = cachedUser; return next(); }
    const { rows } = await pool.query("SELECT * FROM users WHERE id=$1", [decoded.id]);
    if (!rows[0]) return res.status(401).json({ error: "User not found" });
    userCache.set(`user:${decoded.id}`, rows[0]);
    req.user = rows[0];
    next();
  } catch (err) { return res.status(401).json({ error: "Invalid token" }); }
}

// ============================================================
// 🏠 ROOT ROUTE
// ============================================================

app.get("/", (req, res) => {
  res.status(200).send(`
    <h1>🚀 Omevo Backend (Mediasoup) is Running</h1>
    <p>Status: <strong>Online</strong></p>
    <p>Time: ${new Date().toISOString()}</p>
    <hr>
    <p><strong>Configuration Status:</strong></p>
    <ul>
      <li>Database: ✅ Connected</li>
      <li>Redis: ${redisClient ? "✅ Connected" : "⚠️ Not Configured"}</li>
      <li>Mediasoup Workers: ${mediasoupWorkers.length}</li>
      <li>Active Rooms: ${rooms.size}</li>
      <li>Announced IP: ${process.env.MEDIASOUP_ANNOUNCED_IP || "Auto-detect"}</li>
      <li>Stripe: ${stripe ? "✅" : "⚠️"}</li>
      <li>Coinbase: ${ChargeResource ? "✅" : "⚠️"}</li>
    </ul>
    <p><a href="/auth/google">Login with Google</a></p>
  `);
});

// ============================================================
// 🔐 OAUTH ROUTES (unchanged)
// ============================================================

app.get("/auth/google", authLimiter, passport.authenticate("google", { scope: ["profile", "email"] }));
app.get("/auth/google/callback", authLimiter, passport.authenticate("google", { failureRedirect: "/auth/failure", session: true }),
  (req, res) => res.redirect(`${process.env.FRONTEND_URL}/auth/callback?token=${signJwtForUser(req.user)}`));

app.get("/auth/discord", authLimiter, passport.authenticate("discord"));
app.get("/auth/discord/callback", authLimiter, passport.authenticate("discord", { failureRedirect: "/auth/failure", session: true }),
  (req, res) => res.redirect(`${process.env.FRONTEND_URL}/auth/callback?token=${signJwtForUser(req.user)}`));

app.get("/auth/facebook", authLimiter, passport.authenticate("facebook", { scope: ["email"] }));
app.get("/auth/callback/facebook", authLimiter, passport.authenticate("facebook", { failureRedirect: "/auth/failure", session: true }),
  (req, res) => res.redirect(`${process.env.FRONTEND_URL}/auth/callback?token=${signJwtForUser(req.user)}`));

app.get("/auth/me", requireAuth, async (req, res) => {
  try {
    const { rows } = await pool.query(`SELECT *, GREATEST(1, FLOOR(EXTRACT(EPOCH FROM (NOW() - created_at)) / 3600)) as level FROM users WHERE id=$1`, [req.user.id]);
    let user = rows[0];
    if (!user.location || user.location === 'any') {
      const ip = req.headers["x-forwarded-for"]?.split(",")[0] || req.socket.remoteAddress;
      const geo = geoip.lookup(ip);
      const loc = geo?.country?.toLowerCase() || "any";
      await pool.query("UPDATE users SET location=$1 WHERE id=$2", [loc, req.user.id]);
      user.location = loc;
    }
    userCache.set(`user:${req.user.id}`, user);
    res.json({ authenticated: true, user });
  } catch (err) { res.status(500).json({ error: "Auth check failed" }); }
});

app.get("/auth/failure", (req, res) => res.status(401).json({ error: "Authentication failed", details: req.query.error }));

// ============================================================
// 🎬 MEDIASOUP ROUTER CAPABILITIES ENDPOINT
// ============================================================

app.get("/api/mediasoup/router-rtp-capabilities", requireAuth, async (req, res) => {
  try {
    // Return default capabilities (will be updated when user joins a room)
    const worker = mediasoupWorkers[0];
    const router = await worker.createRouter({ mediaCodecs: MEDIASOUP_CONFIG.router.mediaCodecs });
    const rtpCapabilities = router.rtpCapabilities;
    await router.close();
    res.json({ rtpCapabilities });
  } catch (err) {
    console.error("Error getting RTP capabilities:", err);
    res.status(500).json({ error: "Failed to get router capabilities" });
  }
});

// ============================================================
// 🎬 SOCKET.IO MIDDLEWARE
// ============================================================

io.use(async (socket, next) => {
  try {
    const token = socket.handshake.auth.token || socket.handshake.query.token;
    if (!token) return next(new Error("Authentication token required"));

    const decoded = jwt.verify(token, JWT_SECRET);
    let user = userCache.get(`user:${decoded.id}`);
    if (!user) {
      const { rows } = await pool.query("SELECT * FROM users WHERE id=$1", [decoded.id]);
      if (!rows[0]) return next(new Error("User not found"));
      user = rows[0];
      userCache.set(`user:${decoded.id}`, user);
    }

    if (user.banned_until && new Date(user.banned_until) > new Date()) {
      return next(new Error("Account is banned"));
    }

    socket.data.userId = user.id;
    socket.data.user = user;
    socket.data.lastFrameModeration = 0;
    socket.data.inQueue = false;
    socket.data.currentRoom = null;
    socket.data.mediasoupPeer = null;
    next();
  } catch (err) {
    console.error("Socket auth middleware rejected:", err.message);
    next(new Error("Unauthorized"));
  }
});

// ============================================================
// 🎬 SOCKET.IO HANDLERS
// ============================================================

async function detectSuspiciousBehavior(userId, action, metadata = {}) {
  try {
    await pool.query("INSERT INTO user_activity (user_id, action, metadata, created_at) VALUES ($1, $2, $3, NOW())", [userId, action, JSON.stringify(metadata)]);
    const { rows } = await pool.query(`SELECT COUNT(*) as count FROM user_activity WHERE user_id=$1 AND action=$2 AND created_at > NOW() - INTERVAL '1 hour'`, [userId, action]);
    if (parseInt(rows[0].count) > 50) {
      await pool.query("INSERT INTO flagged_users (user_id, reason, created_at) VALUES ($1, $2, NOW())", [userId, `Suspicious: ${action} ${rows[0].count}x/hour`]);
    }
  } catch (err) { console.error("Error detecting suspicious behavior:", err); }
}

io.on("connection", (socket) => {
  const userId = socket.data.userId;
  const user = socket.data.user;

  console.log(`✅ User ${user.username} connected: ${socket.id}`);
  setUserOnline(String(userId), socket.id);
  socket.emit("authenticated", { userId });

  // ==================== MEDIASOUP HANDLERS ====================

  /**
   * Join a mediasoup room - creates/get router, peer, and returns RTP capabilities
   */
  socket.on("mediasoup-join-room", async ({ roomId }, callback) => {
    if (!userId) return callback?.({ error: "Not authenticated" });

    const queue = getPeerQueue(socket.id);
    await queue.push(async () => {
      try {
        // Create or get room
        const room = await createRoom(roomId);
        
        // Check if peer already exists in this room
        if (room.getPeer(socket.id)) {
          return callback?.({ error: "Already in this room" });
        }

        // Create peer
        const peer = new MediaSoupPeer({
          id: socket.id,
          socket,
          room,
          user,
        });

        room.addPeer(peer);
        socket.data.currentRoom = roomId;
        socket.data.mediasoupPeer = peer;

        // Send router RTP capabilities
        callback?.({
          rtpCapabilities: room.router.rtpCapabilities,
          peerId: socket.id,
        });

        // Notify other peers
        await broadcastNewPeer(room, peer);

        // Send existing peers to new peer
        const existingPeers = room.getPeers().filter(p => p.id !== socket.id && !p.closed);
        socket.emit("existing-peers", {
          peers: existingPeers.map(p => p.getJson()),
        });

        console.log(`🎬 Peer ${user.username} joined room ${roomId}`);
      } catch (err) {
        console.error("Join room error:", err);
        callback?.({ error: err.message });
      }
    });
  });

  /**
   * Create WebRTC send transport (for sending media)
   */
  socket.on("mediasoup-create-send-transport", async ({ roomId }, callback) => {
    const queue = getPeerQueue(socket.id);
    await queue.push(async () => {
      try {
        const room = rooms.get(roomId);
        if (!room) return callback?.({ error: "Room not found" });

        const peer = room.getPeer(socket.id);
        if (!peer) return callback?.({ error: "Not in room" });

        const { transport, params } = await createWebRtcTransport(room.router, socket);
        peer.sendTransport = transport;

        transport.on("connect", ({ dtlsParameters }, connectCallback) => {
          transport.connect({ dtlsParameters })
            .then(() => connectCallback())
            .catch(connectCallback);
        });

        transport.on("produce", async ({ kind, rtpParameters, appData }, produceCallback) => {
          try {
            const producer = await createProducer(peer, { kind, rtpParameters, appData });
            produceCallback({ id: producer.id });

            // Notify other peers about new producer
            for (const otherPeer of room.getPeers()) {
              if (otherPeer.id !== peer.id && !otherPeer.closed) {
                otherPeer.socket.emit("new-producer", {
                  producerId: producer.id,
                  peerId: peer.id,
                  kind,
                  appData: producer.appData,
                });
              }
            }
          } catch (err) {
            produceCallback({ error: err.message });
          }
        });

        transport.on("producedata", async ({ sctpStreamParameters, label, protocol, appData }, produceCallback) => {
          try {
            const dataProducer = await createDataProducer(peer, { sctpStreamParameters, label, protocol, appData });
            produceCallback({ id: dataProducer.id });

            for (const otherPeer of room.getPeers()) {
              if (otherPeer.id !== peer.id && !otherPeer.closed) {
                otherPeer.socket.emit("new-data-producer", {
                  dataProducerId: dataProducer.id,
                  peerId: peer.id,
                  label,
                  protocol,
                });
              }
            }
          } catch (err) {
            produceCallback({ error: err.message });
          }
        });

        callback?.(params);
      } catch (err) {
        console.error("Create send transport error:", err);
        callback?.({ error: err.message });
      }
    });
  });

  /**
   * Create WebRTC receive transport (for receiving media)
   */
  socket.on("mediasoup-create-recv-transport", async ({ roomId }, callback) => {
    const queue = getPeerQueue(socket.id);
    await queue.push(async () => {
      try {
        const room = rooms.get(roomId);
        if (!room) return callback?.({ error: "Room not found" });

        const peer = room.getPeer(socket.id);
        if (!peer) return callback?.({ error: "Not in room" });

        const { transport, params } = await createWebRtcTransport(room.router, socket);
        peer.recvTransport = transport;

        transport.on("connect", ({ dtlsParameters }, connectCallback) => {
          transport.connect({ dtlsParameters })
            .then(() => connectCallback())
            .catch(connectCallback);
        });

        callback?.(params);
      } catch (err) {
        console.error("Create recv transport error:", err);
        callback?.({ error: err.message });
      }
    });
  });

  /**
   * Connect send transport
   */
  socket.on("mediasoup-connect-send-transport", async ({ dtlsParameters }, callback) => {
    try {
      const peer = socket.data.mediasoupPeer;
      if (!peer?.sendTransport) return callback?.({ error: "No send transport" });
      await peer.sendTransport.connect({ dtlsParameters });
      callback?.();
    } catch (err) {
      console.error("Connect send transport error:", err);
      callback?.({ error: err.message });
    }
  });

  /**
   * Connect receive transport
   */
  socket.on("mediasoup-connect-recv-transport", async ({ dtlsParameters }, callback) => {
    try {
      const peer = socket.data.mediasoupPeer;
      if (!peer?.recvTransport) return callback?.({ error: "No recv transport" });
      await peer.recvTransport.connect({ dtlsParameters });
      callback?.();
    } catch (err) {
      console.error("Connect recv transport error:", err);
      callback?.({ error: err.message });
    }
  });

  /**
   * Produce (send) media
   */
  socket.on("mediasoup-produce", async ({ kind, rtpParameters, appData }, callback) => {
    const queue = getPeerQueue(socket.id);
    await queue.push(async () => {
      try {
        const peer = socket.data.mediasoupPeer;
        if (!peer?.sendTransport) return callback?.({ error: "No send transport" });

        const producer = await createProducer(peer, { kind, rtpParameters, appData });
        callback?.({ id: producer.id });

        // Notify other peers
        for (const otherPeer of peer.room.getPeers()) {
          if (otherPeer.id !== peer.id && !otherPeer.closed) {
            otherPeer.socket.emit("new-producer", {
              producerId: producer.id,
              peerId: peer.id,
              kind,
              appData: producer.appData,
            });
          }
        }
      } catch (err) {
        console.error("Produce error:", err);
        callback?.({ error: err.message });
      }
    });
  });

  /**
   * Consume (receive) a producer
   */
  socket.on("mediasoup-consume", async ({ producerId, rtpCapabilities }, callback) => {
    const queue = getPeerQueue(socket.id);
    await queue.push(async () => {
      try {
        const peer = socket.data.mediasoupPeer;
        if (!peer?.recvTransport) return callback?.({ error: "No recv transport" });

        const room = peer.room;
        const producerPeerId = producerId.split("-")[0]; // Extract peer ID from producer ID
        const producerPeer = room.getPeer(producerPeerId);
        
        let producer;
        if (producerPeer) {
          producer = producerPeer.producers.get(producerId);
        }

        // Fallback: search all peers
        if (!producer) {
          for (const p of room.getPeers()) {
            const found = p.producers.get(producerId);
            if (found) { producer = found; break; }
          }
        }

        if (!producer) return callback?.({ error: "Producer not found" });

        const { consumer, params } = await consume({ peer, producer, rtpCapabilities });
        callback?.(params);
      } catch (err) {
        console.error("Consume error:", err);
        callback?.({ error: err.message });
      }
    });
  });

  /**
   * Resume a paused consumer
   */
  socket.on("mediasoup-resume-consumer", async ({ consumerId }, callback) => {
    try {
      const peer = socket.data.mediasoupPeer;
      const consumer = peer?.consumers.get(consumerId);
      if (!consumer) return callback?.({ error: "Consumer not found" });
      await consumer.resume();
      callback?.();
    } catch (err) {
      console.error("Resume consumer error:", err);
      callback?.({ error: err.message });
    }
  });

  /**
   * Pause a producer
   */
  socket.on("mediasoup-pause-producer", async ({ producerId }, callback) => {
    try {
      const peer = socket.data.mediasoupPeer;
      const producer = peer?.producers.get(producerId);
      if (!producer) return callback?.({ error: "Producer not found" });
      await producer.pause();
      callback?.();
    } catch (err) {
      callback?.({ error: err.message });
    }
  });

  /**
   * Resume a producer
   */
  socket.on("mediasoup-resume-producer", async ({ producerId }, callback) => {
    try {
      const peer = socket.data.mediasoupPeer;
      const producer = peer?.producers.get(producerId);
      if (!producer) return callback?.({ error: "Producer not found" });
      await producer.resume();
      callback?.();
    } catch (err) {
      callback?.({ error: err.message });
    }
  });

  /**
   * Close a producer
   */
  socket.on("mediasoup-close-producer", async ({ producerId }, callback) => {
    try {
      const peer = socket.data.mediasoupPeer;
      const producer = peer?.producers.get(producerId);
      if (!producer) return callback?.({ error: "Producer not found" });
      await producer.close();
      peer.producers.delete(producerId);

      // Notify other peers
      for (const otherPeer of peer.room.getPeers()) {
        if (otherPeer.id !== peer.id && !otherPeer.closed) {
          otherPeer.socket.emit("producer-closed", { producerId, peerId: peer.id });
        }
      }
      callback?.();
    } catch (err) {
      callback?.({ error: err.message });
    }
  });

  /**
   * Close a consumer
   */
  socket.on("mediasoup-close-consumer", async ({ consumerId }, callback) => {
    try {
      const peer = socket.data.mediasoupPeer;
      const consumer = peer?.consumers.get(consumerId);
      if (!consumer) return callback?.({ error: "Consumer not found" });
      await consumer.close();
      peer.consumers.delete(consumerId);
      callback?.();
    } catch (err) {
      callback?.({ error: err.message });
    }
  });

  /**
   * Restart ICE for a transport (reconnection)
   */
  socket.on("mediasoup-restart-ice", async ({ transportId }, callback) => {
    try {
      const peer = socket.data.mediasoupPeer;
      let transport = peer?.sendTransport?.id === transportId ? peer.sendTransport
                    : peer?.recvTransport?.id === transportId ? peer.recvTransport
                    : null;
      
      if (!transport) return callback?.({ error: "Transport not found" });

      const iceParameters = await transport.restartIce();
      callback?.({ iceParameters });
    } catch (err) {
      console.error("Restart ICE error:", err);
      callback?.({ error: err.message });
    }
  });

  /**
   * Get transport stats
   */
  socket.on("mediasoup-get-transport-stats", async ({ transportId }, callback) => {
    try {
      const peer = socket.data.mediasoupPeer;
      let transport = peer?.sendTransport?.id === transportId ? peer.sendTransport
                    : peer?.recvTransport?.id === transportId ? peer.recvTransport
                    : null;
      
      if (!transport) return callback?.({ error: "Transport not found" });
      const stats = await transport.getStats();
      callback?.(stats);
    } catch (err) {
      callback?.({ error: err.message });
    }
  });

  /**
   * Get producer stats
   */
  socket.on("mediasoup-get-producer-stats", async ({ producerId }, callback) => {
    try {
      const peer = socket.data.mediasoupPeer;
      const producer = peer?.producers.get(producerId);
      if (!producer) return callback?.({ error: "Producer not found" });
      const stats = await producer.getStats();
      callback?.(stats);
    } catch (err) {
      callback?.({ error: err.message });
    }
  });

  /**
   * Change video layers (simulcast/SVC)
   */
  socket.on("mediasoup-set-consumer-preferred-layers", async ({ consumerId, spatialLayer, temporalLayer }, callback) => {
    try {
      const peer = socket.data.mediasoupPeer;
      const consumer = peer?.consumers.get(consumerId);
      if (!consumer) return callback?.({ error: "Consumer not found" });
      await consumer.setPreferredLayers({ spatialLayer, temporalLayer });
      callback?.();
    } catch (err) {
      callback?.({ error: err.message });
    }
  });

  /**
   * Request key frame
   */
  socket.on("mediasoup-request-key-frame", async ({ consumerId }, callback) => {
    try {
      const peer = socket.data.mediasoupPeer;
      const consumer = peer?.consumers.get(consumerId);
      if (!consumer) return callback?.({ error: "Consumer not found" });
      await consumer.requestKeyFrame();
      callback?.();
    } catch (err) {
      callback?.({ error: err.message });
    }
  });

  // ==================== END MEDIASOUP HANDLERS ====================

  socket.on("join_queue", async (data = {}) => {
    if (!userId) return socket.emit("error", { message: "Not authenticated" });
    
    try {
      const { rows: activeMatch } = await pool.query("SELECT * FROM matches WHERE (user_a=$1 OR user_b=$1) AND ended_at IS NULL", [userId]);
      if (activeMatch.length > 0) return socket.emit("error", { message: "You're already in a match" });
      if (user.banned_until && new Date(user.banned_until) > new Date()) return socket.emit("error", { message: "Account is banned" });
      if (!user.age_verified) return socket.emit("error", { message: "Age verification required" });

      const nickname = data.nickname || user.nickname || "";
      if (nickname && (nickname.length > MAX_NICKNAME_LENGTH || nickname.length < 1)) {
        return socket.emit("error", { message: `Nickname must be 1-${MAX_NICKNAME_LENGTH} characters` });
      }

      let interests = data.interests || user.interests || [];
      if (!Array.isArray(interests) || interests.length > MAX_INTERESTS) {
        return socket.emit("error", { message: `Max ${MAX_INTERESTS} interests` });
      }
      interests = interests.filter(i => typeof i === "string" && i.length > 0 && i.length <= 30);

      let location = data.location || user.location || "any";
      if (!location || location === "any") {
        const ip = socket.handshake.headers["x-forwarded-for"]?.split(",")[0] || socket.handshake.address;
        const geo = geoip.lookup(ip);
        location = geo?.country?.toLowerCase() || "any";
      }

      const queueEntry = {
        userId: String(userId), socketId: socket.id,
        gender: data.gender || user.gender || "any",
        looking_for: data.looking_for || user.looking_for || "any",
        location, interests, nickname,
        username: user.username || "User", avatar: user.avatar || "",
        ts: Date.now(),
      };

      if (useRedisForMatching) await redisQueueAdd(queueEntry);
      localMatchQueue.set(String(userId), queueEntry);
      socket.data.inQueue = true;

      await pool.query(
        `INSERT INTO queue (user_id, gender, looking_for, location, interests, nickname, joined_at) 
         VALUES ($1,$2,$3,$4,$5,$6,NOW()) 
         ON CONFLICT (user_id) DO UPDATE SET gender=EXCLUDED.gender, looking_for=EXCLUDED.looking_for, 
         location=EXCLUDED.location, interests=EXCLUDED.interests, nickname=EXCLUDED.nickname, joined_at=NOW()`,
        [queueEntry.userId, queueEntry.gender, queueEntry.looking_for, queueEntry.location, queueEntry.interests, queueEntry.nickname]
      );

      await pool.query(`UPDATE users SET gender=$1, looking_for=$2, location=$3, interests=$4, nickname=$5, updated_at=NOW() WHERE id=$6`,
        [queueEntry.gender, queueEntry.looking_for, queueEntry.location, queueEntry.interests, queueEntry.nickname, userId]);

      const queueCount = await getQueueCount();
      socket.emit("queue_joined", { position: queueCount, locationUsed: location, estimatedWait: queueCount > 1 ? "Searching..." : "Waiting..." });

      const match = await tryMatchForUser(userId);
      if (!match) {
        socket.emit("queue_waiting", { position: await getQueueCount(), message: "Looking for someone..." });
      }
    } catch (err) {
      console.error("Join queue error:", err);
      socket.emit("error", { message: "Failed to join queue" });
    }
  });

  socket.on("leave_queue", async () => {
    if (!userId) return;
    try {
      await removeFromQueue(userId);
      socket.data.inQueue = false;
      socket.emit("queue_left", { message: "Left the queue" });
    } catch (err) { console.error("Leave queue error:", err); }
  });

  socket.on("queue_status", async () => {
    if (!userId) return;
    try {
      socket.emit("queue_status", { inQueue: socket.data.inQueue || localMatchQueue.has(String(userId)), position: await getQueueCount() });
    } catch (err) { console.error("Queue status error:", err); }
  });

  socket.on("typing", ({ room }) => {
    if (!room || !isInRoom(socket, room)) return;
    socket.to(room).emit("typing", { uid: userId });
  });

  socket.on("disconnect", async (reason) => {
    console.log(`❌ User ${user.username} disconnected: ${socket.id} (${reason})`);

    try {
      await setUserOffline(String(userId));
      
      // End matches
      await pool.query(`UPDATE matches SET ended_at = NOW() WHERE (user_a = $1 OR user_b = $1) AND ended_at IS NULL`, [userId]);
      
      // Close mediasoup peer
      const peer = socket.data.mediasoupPeer;
      if (peer && !peer.closed) {
        await closePeerAndNotify(peer);
        
        // Close room if empty
        const room = rooms.get(socket.data.currentRoom);
        if (room && room.peers.size === 0) {
          await closeRoom(socket.data.currentRoom);
        }
      }
      
      await removeFromQueue(userId);
      socket.data.inQueue = false;

      const roomsList = getSocketRooms(socket);
      for (const room of roomsList) {
        socket.to(room).emit("peer_left", { socketId: socket.id, userId });
      }

      await pool.query("DELETE FROM queue WHERE user_id=$1", [String(userId)]).catch(() => {});
    } catch (err) { console.error("Disconnect cleanup error:", err); }
  });

  socket.on("message", async ({ room, text }) => {
    if (!userId) return socket.emit("error", { message: "Not authenticated" });
    try {
      const userRooms = getSocketRooms(socket);
      let targetRoom = room || userRooms[0];
      if (!targetRoom) return socket.emit("error", { message: "Not in any room" });
      if (room && !isInRoom(socket, targetRoom)) return socket.emit("error", { message: "Not in this room" });
      if (!text || text.length > 500) return socket.emit("error", { message: "Message too long" });

      await detectSuspiciousBehavior(userId, "chat_message", { length: text.length });

      if (IS_MODERATION_ENABLED) {
        const mod = await OPENAI.moderations.create({ model: "omni-moderation-latest", input: text });
        if (mod.results?.[0]?.flagged) {
          const banReason = `Inappropriate message`;
          await pool.query("UPDATE users SET banned_until = NOW() + INTERVAL '750 hours', ban_reason=$1 WHERE id=$2", [banReason, userId]);
          socket.emit("moderation_action", { type: "chat", text, banned: true, duration_hours: BAN_HOURS, reason: banReason });
          userCache.del(`user:${userId}`);
          socket.disconnect(true);
          return;
        }
      }

      const { rows } = await pool.query("INSERT INTO chat_messages (user_id, room_id, message, created_at) VALUES ($1, $2, $3, NOW()) RETURNING *", [userId, targetRoom, text]);
      const messageData = { id: rows[0].id, uid: userId, text, timestamp: rows[0].created_at, username: user?.username || "User" };
      socket.to(targetRoom).emit("message", messageData);
      socket.emit("message", messageData);
    } catch (err) { socket.emit("error", { message: "Failed to send message" }); }
  });

  socket.on("video_frame", async ({ frameBase64, roomId }) => {
    if (!userId) return;
    const now = Date.now();
    if (now - socket.data.lastFrameModeration < 1000) return;
    socket.data.lastFrameModeration = now;

    try {
      await detectSuspiciousBehavior(userId, "video_frame");
      const buffer = Buffer.from(frameBase64.split(",")[1], "base64");
      const processedImage = await sharp(buffer).resize({ width: 320, height: 240, fit: "inside" }).jpeg({ quality: 70 }).toBuffer();
      const processedBase64 = `data:image/jpeg;base64,${processedImage.toString("base64")}`;

      if (IS_MODERATION_ENABLED) {
        const mod = await OPENAI.moderations.create({ model: "omni-moderation-latest", input: processedBase64 });
        if (mod.results?.[0]?.flagged) {
          const banReason = `Inappropriate content detected`;
          await pool.query("UPDATE users SET banned_until = NOW() + INTERVAL '750 hours', ban_reason=$1 WHERE id=$2", [banReason, userId]);
          socket.emit("moderation_action", { type: "video", banned: true, duration_hours: BAN_HOURS, reason: banReason });
          userCache.del(`user:${userId}`);
          socket.disconnect(true);
          return;
        }
      }

      // Send to peer via mediasoup data channel or socket
      const peer = socket.data.mediasoupPeer;
      if (peer?.room) {
        for (const otherPeer of peer.room.getPeers()) {
          if (otherPeer.id !== socket.id && !otherPeer.closed) {
            otherPeer.socket.emit("video_frame", { frameBase64: processedBase64, from: userId });
          }
        }
      }
    } catch (err) { console.error("Video moderation error:", err); }
  });

  socket.on("next", async () => {
    if (!userId) return;
    
    try {
      await pool.query(`UPDATE matches SET ended_at = NOW() WHERE (user_a = $1 OR user_b = $1) AND ended_at IS NULL`, [userId]);

      // Close mediasoup peer
      const peer = socket.data.mediasoupPeer;
      if (peer && !peer.closed) {
        await closePeerAndNotify(peer);
        
        const room = rooms.get(socket.data.currentRoom);
        if (room && room.peers.size === 0) {
          await closeRoom(socket.data.currentRoom);
        }
      }

      const cachedEntry = localMatchQueue.get(String(userId));
      const data = cachedEntry ? {
        gender: cachedEntry.gender, looking_for: cachedEntry.looking_for,
        location: cachedEntry.location, interests: cachedEntry.interests, nickname: cachedEntry.nickname,
      } : {};

      socket.emit("next_ready");
      socket.emit("auto_requeue", { preferences: data });
    } catch (err) {
      console.error("Next error:", err);
      socket.emit("error", { message: "Failed to find next match" });
    }
  });

  socket.on("report_user", async ({ reportedUserId, reason }) => {
    if (!userId) return;
    try {
      if (!reason || reason.length < 10 || reason.length > 200) return socket.emit("error", { message: "Invalid report reason" });
      const { rows } = await pool.query(`SELECT COUNT(*) as count FROM user_reports WHERE reporter_id=$1 AND reported_id=$2 AND created_at > NOW() - INTERVAL '24 hours'`, [userId, reportedUserId]);
      if (parseInt(rows[0].count) > 0) return socket.emit("error", { message: "Already reported recently" });
      await pool.query("INSERT INTO user_reports (reporter_id, reported_id, reason, created_at) VALUES ($1, $2, $3, NOW())", [userId, reportedUserId, reason]);
      const { rows: reportCount } = await pool.query(`SELECT COUNT(*) as count FROM user_reports WHERE reported_id=$1 AND created_at > NOW() - INTERVAL '24 hours'`, [reportedUserId]);
      if (parseInt(reportCount[0].count) >= 3) {
        await pool.query("UPDATE users SET banned_until = NOW() + INTERVAL '168 hours', ban_reason=$1 WHERE id=$2", ["Multiple reports", reportedUserId]);
        userCache.del(`user:${reportedUserId}`);
      }
      socket.emit("report_submitted", { message: "Report submitted" });
    } catch (err) { socket.emit("error", { message: "Failed to submit report" }); }
  });

  socket.on("reaction", async ({ type, room }) => {
    if (!userId) return;
    let targetRoom = room;
    if (!targetRoom) {
      const roomsList = getSocketRooms(socket);
      if (roomsList.length === 0) return;
      targetRoom = roomsList[0];
    }
    socket.to(targetRoom).emit("reaction", { type, uid: userId, username: user?.username || "User" });
  });
});

// ============================================================
// 📊 API ROUTES (unchanged - payments, profile, admin, etc.)
// ============================================================

app.post("/api/create-checkout-session", requireAuth, async (req, res) => {
  try {
    if (!stripe) return res.status(503).json({ error: "Payment unavailable" });
    const { coins, price } = req.body;
    const session = await stripe.checkout.sessions.create({
      payment_method_types: ["card"],
      line_items: [{ price_data: { currency: "usd", product_data: { name: `${coins} Omevo Coins` }, unit_amount: Math.round(price * 100) }, quantity: 1 }],
      mode: "payment",
      success_url: `${process.env.FRONTEND_URL}?payment=success&session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${process.env.FRONTEND_URL}?payment=cancelled`,
      customer_email: req.user.email,
      metadata: { userId: String(req.user.id), coins: coins.toString() },
    });
    res.json({ sessionId: session.id });
  } catch (error) { res.status(500).json({ error: "Failed to create payment" }); }
});

app.post("/api/verify-payment", requireAuth, async (req, res) => {
  try {
    if (!stripe) return res.status(503).json({ error: "Payment unavailable" });
    const { sessionId } = req.body;
    const session = await stripe.checkout.sessions.retrieve(sessionId);
    if (session.payment_status === "paid") {
      const coins = parseInt(session.metadata.coins);
      const userId = session.metadata.userId;
      await pool.query("UPDATE users SET coins = coins + $1, updated_at = NOW() WHERE id = $2", [coins, userId]);
      const { rows } = await pool.query("SELECT coins FROM users WHERE id = $1", [userId]);
      await pool.query("INSERT INTO coin_transactions (user_id, coins, amount, transaction_type, transaction_id, created_at) VALUES ($1, $2, $3, $4, $5, NOW())", [userId, coins, session.amount_total / 100, "purchase", sessionId]);
      userCache.del(`user:${userId}`);
      res.json({ success: true, coins: rows[0].coins });
    } else { res.json({ success: false }); }
  } catch (error) { res.status(500).json({ error: "Failed to verify payment" }); }
});

async function ensureColumns() {
  try {
    await pool.query(`CREATE TABLE IF NOT EXISTS appeals (id SERIAL PRIMARY KEY, user_id INTEGER REFERENCES users(id), message TEXT NOT NULL, status VARCHAR(20) DEFAULT 'pending', admin_response TEXT, admin_id INTEGER, created_at TIMESTAMP DEFAULT NOW(), reviewed_at TIMESTAMP)`);
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS coins INTEGER DEFAULT 0`);
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS looking_for VARCHAR(20) DEFAULT 'any'`);
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS role VARCHAR(20) DEFAULT 'user'`);
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS age_verified BOOLEAN DEFAULT FALSE`);
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS banned_until TIMESTAMP`);
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS ban_reason TEXT`);
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS nickname VARCHAR(20)`);
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS interests TEXT[] DEFAULT '{}'`);
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS gender VARCHAR(20) DEFAULT 'any'`);
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS location VARCHAR(50) DEFAULT 'any'`);
    await pool.query(`ALTER TABLE queue ADD COLUMN IF NOT EXISTS looking_for VARCHAR(20) DEFAULT 'any'`);
    await pool.query(`ALTER TABLE queue ADD COLUMN IF NOT EXISTS gender VARCHAR(20) DEFAULT 'any'`);
    await pool.query(`ALTER TABLE queue ADD COLUMN IF NOT EXISTS location VARCHAR(50) DEFAULT 'any'`);
    await pool.query(`ALTER TABLE queue ADD COLUMN IF NOT EXISTS interests TEXT[] DEFAULT '{}'`);
    await pool.query(`CREATE TABLE IF NOT EXISTS coin_transactions (id SERIAL PRIMARY KEY, user_id INTEGER REFERENCES users(id), coins INTEGER NOT NULL, amount DECIMAL(10,2), transaction_type VARCHAR(30), gift_type VARCHAR(30), recipient_id VARCHAR(50), transaction_id VARCHAR(255), created_at TIMESTAMP DEFAULT NOW())`);
    console.log("Database columns ensured");
  } catch (error) { console.error("Error ensuring columns:", error); }
}

app.post("/api/user/spend-coins", requireAuth, async (req, res) => {
  try {
    const { coins, type, giftType, recipientId } = req.body;
    if (!coins || coins <= 0) return res.status(400).json({ error: "Invalid coin amount" });
    const { rows } = await pool.query("SELECT coins FROM users WHERE id = $1", [req.user.id]);
    if (rows[0].coins < coins) return res.status(400).json({ error: "Insufficient coins" });
    await pool.query("UPDATE users SET coins = coins - $1 WHERE id = $2", [coins, req.user.id]);
    await pool.query("INSERT INTO coin_transactions (user_id, coins, transaction_type, gift_type, recipient_id, created_at) VALUES ($1, $2, $3, $4, $5, NOW())", [req.user.id, -coins, type || "spend", giftType, recipientId]);
    userCache.del(`user:${req.user.id}`);
    res.json({ success: true });
  } catch (error) { res.status(500).json({ error: "Failed to spend coins" }); }
});

app.post("/api/user/preferences", requireAuth, async (req, res) => {
  try {
    let { gender = "any", looking_for = "any", location = "any", interests = [], nickname = "" } = req.body;
    if (nickname && (nickname.length > MAX_NICKNAME_LENGTH || nickname.length < 1)) return res.status(400).json({ error: `Nickname: 1-${MAX_NICKNAME_LENGTH} chars` });
    if (!Array.isArray(interests) || interests.length > MAX_INTERESTS) return res.status(400).json({ error: `Max ${MAX_INTERESTS} interests` });
    interests = interests.filter(i => typeof i === "string" && i.length > 0 && i.length <= 30);
    if (!location || location === "any") { const ip = req.headers["x-forwarded-for"]?.split(",")[0] || req.socket.remoteAddress; const geo = geoip.lookup(ip); location = geo?.country?.toLowerCase() || "any"; }
    await pool.query(`UPDATE users SET gender=$1, looking_for=$2, location=$3, interests=$4, nickname=$5, updated_at=NOW() WHERE id=$6`, [gender, looking_for, location, interests, nickname, req.user.id]);
    userCache.set(`user:${req.user.id}`, { ...req.user, gender, looking_for, location, interests, nickname });
    res.json({ ok: true, locationUsed: location });
  } catch (err) { res.status(500).json({ error: "Could not save preferences" }); }
});

app.post("/api/user/verify-age", requireAuth, async (req, res) => {
  try {
    const { age } = req.body;
    if (!age || isNaN(age) || age < MIN_AGE_FOR_VIDEO) return res.status(400).json({ error: `Must be ${MIN_AGE_FOR_VIDEO}+` });
    await pool.query("UPDATE users SET age_verified=$1 WHERE id=$2", [true, req.user.id]);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: "Could not verify age" }); }
});

app.post("/api/user/avatar", requireAuth, async (req, res) => {
  try {
    const { avatarBase64 } = req.body;
    if (!avatarBase64) return res.status(400).json({ error: "Avatar required" });
    const buffer = Buffer.from(avatarBase64.split(",")[1], "base64");
    const processedImage = await sharp(buffer).resize({ width: 200, height: 200, fit: "cover" }).jpeg({ quality: 80 }).toBuffer();
    const processedBase64 = `data:image/jpeg;base64,${processedImage.toString("base64")}`;
    await pool.query("UPDATE users SET avatar=$1 WHERE id=$2", [processedBase64, req.user.id]);
    userCache.set(`user:${req.user.id}`, { ...req.user, avatar: processedBase64 });
    res.json({ ok: true, avatar: processedBase64 });
  } catch (err) { res.status(500).json({ error: "Could not upload avatar" }); }
});

app.get("/user/profile", requireAuth, async (req, res) => {
  try {
    const { rows } = await pool.query(`SELECT id, username, email, avatar, gender, looking_for, location, interests, nickname, age_verified, coins, role, GREATEST(1, FLOOR(EXTRACT(EPOCH FROM (NOW() - created_at)) / 3600)) as level FROM users WHERE id=$1`, [req.user.id]);
    if (!rows.length) return res.status(404).json({ error: "User not found" });
    res.json({ ...rows[0], is_admin: rows[0].role === "admin" });
  } catch (err) { res.status(500).json({ error: "Could not fetch profile" }); }
});

app.post("/api/create-gift-checkout", requireAuth, async (req, res) => {
  try {
    const { giftType, recipientId } = req.body;
    const cost = GIFT_COIN_COSTS[giftType];
    if (!cost) return res.status(400).json({ error: "Invalid gift type" });
    if (req.user.coins < cost) return res.status(400).json({ error: "Insufficient coins", code: "INSUFFICIENT_FUNDS" });
    await pool.query("UPDATE users SET coins = coins - $1 WHERE id = $2", [cost, req.user.id]);
    await pool.query("INSERT INTO coin_transactions (user_id, coins, transaction_type, gift_type, recipient_id, created_at) VALUES ($1, $2, $3, $4, $5, NOW())", [req.user.id, -cost, "gift_sent", giftType, recipientId]);
    const recipientSocketId = await getUserSocketId(String(recipientId));
    if (recipientSocketId) io.to(recipientSocketId).emit("gift_received", { giftType, senderId: req.user.id, senderName: req.user.username });
    res.json({ success: true, newBalance: req.user.coins - cost });
  } catch (error) { res.status(500).json({ error: "Failed to send gift" }); }
});

app.post("/api/moderation/appeal", requireAuth, async (req, res) => {
  try {
    const { message } = req.body;
    if (!message || message.length < 10 || message.length > 500) return res.status(400).json({ error: "Appeal: 10-500 chars" });
    const { rows } = await pool.query("SELECT * FROM appeals WHERE user_id=$1 AND status='pending'", [req.user.id]);
    if (rows.length > 0) return res.status(400).json({ error: "Already have pending appeal" });
    await pool.query("INSERT INTO appeals (user_id, message, status, created_at) VALUES ($1, $2, 'pending', NOW())", [req.user.id, message]);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: "Could not submit appeal" }); }
});

// Admin routes
app.get("/api/admin/appeals", requireAuth, async (req, res) => {
  if (req.user.role !== "admin") return res.status(403).json({ error: "Admin required" });
  const { rows } = await pool.query(`SELECT a.*, u.username FROM appeals a JOIN users u ON a.user_id = u.id WHERE a.status='pending' ORDER BY a.created_at DESC`);
  res.json(rows);
});

app.post("/api/admin/appeals/:id/respond", requireAuth, async (req, res) => {
  if (req.user.role !== "admin") return res.status(403).json({ error: "Admin required" });
  const { approved, response } = req.body;
  const { rows } = await pool.query("SELECT * FROM appeals WHERE id=$1", [req.params.id]);
  if (!rows.length) return res.status(404).json({ error: "Appeal not found" });
  await pool.query("UPDATE appeals SET status=$1, admin_response=$2, admin_id=$3, reviewed_at=NOW() WHERE id=$4", [approved ? "approved" : "rejected", response, req.user.id, req.params.id]);
  if (approved) await pool.query("UPDATE users SET banned_until=NULL, ban_reason=NULL WHERE id=$1", [rows[0].user_id]);
  res.json({ ok: true });
});

app.post("/api/admin/ban", requireAuth, async (req, res) => {
  if (req.user.role !== "admin") return res.status(403).json({ error: "Admin required" });
  await pool.query("UPDATE users SET banned_until=$1, ban_reason='Banned by admin' WHERE id=$2", [new Date(Date.now() + 30*24*60*60*1000), req.body.userId]);
  userCache.del(`user:${req.body.userId}`);
  await removeFromQueue(req.body.userId);
  res.json({ ok: true });
});

app.post("/api/admin/unban", requireAuth, async (req, res) => {
  if (req.user.role !== "admin") return res.status(403).json({ error: "Admin required" });
  await pool.query("UPDATE users SET banned_until=NULL, ban_reason=NULL WHERE id=$1", [req.body.userId]);
  userCache.del(`user:${req.body.userId}`);
  res.json({ ok: true });
});

app.get("/api/admin/queue-stats", requireAuth, async (req, res) => {
  if (req.user.role !== "admin") return res.status(403).json({ error: "Admin required" });
  res.json({
    queueSize: await getQueueCount(),
    activeRooms: rooms.size,
    totalWorkers: mediasoupWorkers.length,
    mediasoupRooms: Array.from(rooms.entries()).map(([id, room]) => ({
      id,
      peers: room.peers.size,
      createdAt: room.createdAt,
    })),
  });
});

app.get("/health", (req, res) => {
  res.json({
    ok: true,
    env: process.env.NODE_ENV || "dev",
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    redis: redisClient ? "connected" : "not_configured",
    mediasoup: {
      workers: mediasoupWorkers.length,
      activeRooms: rooms.size,
      totalPeers: Array.from(rooms.values()).reduce((sum, room) => sum + room.peers.size, 0),
    },
  });
});

// ============================================================
// 🧹 CLEANUP JOBS
// ============================================================

cron.schedule("*/5 * * * *", async () => {
  try {
    // Clean stale queue entries
    const fiveMinutesAgo = Date.now() - 5 * 60 * 1000;
    for (const [userId, entry] of localMatchQueue) {
      if (entry.ts < fiveMinutesAgo && !await getUserSocketId(userId)) {
        localMatchQueue.delete(userId);
        if (useRedisForMatching) await redisQueueRemove(userId);
      }
    }

    // Clean empty mediasoup rooms (older than 10 seconds)
    for (const [roomId, room] of rooms) {
      if (room.peers.size === 0 && Date.now() - room.createdAt > 10000) {
        await closeRoom(roomId);
        console.log(`🧹 Cleaned empty room: ${roomId}`);
      }
    }
  } catch (err) {
    console.error("Cleanup error:", err.message);
  }
});

cron.schedule("0 3 * * *", async () => {
  try {
    await pool.query("DELETE FROM chat_messages WHERE created_at < NOW() - INTERVAL '30 days'");
    await pool.query("DELETE FROM user_activity WHERE created_at < NOW() - INTERVAL '90 days'");
    console.log("Daily cleanup completed");
  } catch (err) { console.error("Daily cleanup error:", err); }
});

// ============================================================
// 🚀 START SERVER
// ============================================================

const PORT = process.env.PORT || 5000;

async function startServer() {
  try {
    // Initialize mediasoup
    await createMediasoupWorkers();
    
    // Initialize Redis
    await initRedis();
    
    // Ensure DB columns
    await ensureColumns();
    
    server.listen(PORT, () => {
      console.log(`\n🚀 Server running on port ${PORT}\n`);
      console.log(`🎬 Mediasoup: ${mediasoupWorkers.length} worker(s)`);
      console.log(`   RTC Port Range: ${MEDIASOUP_CONFIG.worker.rtcMinPort}-${MEDIASOUP_CONFIG.worker.rtcMaxPort}`);
      console.log(`   Announced IP: ${process.env.MEDIASOUP_ANNOUNCED_IP || "Auto-detect"}`);
      console.log(`   Codecs: Opus, VP8, VP9, H264`);
      console.log(`\n📱 Mediasoup Socket Events:`);
      console.log(`   • mediasoup-join-room          - Join room, get RTP caps`);
      console.log(`   • mediasoup-create-send-transport - Create send transport`);
      console.log(`   • mediasoup-create-recv-transport - Create receive transport`);
      console.log(`   • mediasoup-connect-send-transport - Connect send transport`);
      console.log(`   • mediasoup-connect-recv-transport - Connect recv transport`);
      console.log(`   • mediasoup-produce             - Send media (audio/video)`);
      console.log(`   • mediasoup-consume             - Receive media`);
      console.log(`   • mediasoup-resume-consumer     - Resume paused consumer`);
      console.log(`   • mediasoup-pause-producer      - Pause sending`);
      console.log(`   • mediasoup-resume-producer     - Resume sending`);
      console.log(`   • mediasoup-close-producer      - Stop sending`);
      console.log(`   • mediasoup-close-consumer      - Stop receiving`);
      console.log(`   • mediasoup-restart-ice         - Reconnect ICE`);
      console.log(`   • mediasoup-get-transport-stats - Get transport stats`);
      console.log(`   • mediasoup-get-producer-stats  - Get producer stats`);
      console.log(`   • mediasoup-set-consumer-preferred-layers - Change quality`);
      console.log(`   • mediasoup-request-key-frame   - Request key frame`);
      console.log(`\n📡 Client Events Received:`);
      console.log(`   • new-peer                      - New peer joined`);
      console.log(`   • existing-peers                - List of existing peers`);
      console.log(`   • new-producer                  - New media available`);
      console.log(`   • producer-closed               - Producer stopped`);
      console.log(`   • consumer-closed               - Consumer stopped`);
      console.log(`   • peer-left                     - Peer disconnected`);
      console.log(`   • audio-level                   - Speaker volume level`);
      console.log(`   • producer-score                - Quality score`);
      console.log(`   • consumer-score                - Quality score`);
      console.log(`   • ice-state-change              - ICE connection state`);
    });
  } catch (err) {
    console.error("Failed to start server:", err);
    process.exit(1);
  }
}

startServer();
