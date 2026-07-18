import { Server as SocketIOServer } from 'socket.io';
import { env, config } from '../config/index.js';
import { pubClient, subClient, isRedisConnected } from '../services/redisService.js';
import { socketAuthMiddleware } from '../middleware/auth.js';
import logger from '../utils/logger.js';
import { registerMatchmakingHandlers } from './matchmaking.js';
import { registerChatHandlers } from './chat.js';
import { registerVideoHandlers } from './video.js';
import { registerReportHandlers } from './reports.js';

let io = null;

// Online socket tracking
const onlineSockets = new Map();

export function initSocketIO(server) {
  io = new SocketIOServer(server, {
    cors: {
      origin: env.FRONTEND_URL,
    },
    pingTimeout: 60000,
    pingInterval: 25000,
  });

  // Setup Redis adapter if available
  if (isRedisConnected()) {
    try {
      const { createAdapter } = require('@socket.io/redis-adapter');
      io.adapter(createAdapter(pubClient, subClient));
      logger.info({ event: 'socket_redis_adapter' }, 'Socket.IO Redis adapter connected');
    } catch (err) {
      logger.warn({ err, event: 'socket_adapter_failed' }, 'Failed to setup Redis adapter');
    }
  }

  // Auth middleware
  io.use(socketAuthMiddleware);

  // Connection handler
  io.on('connection', (socket) => {
    const userId = socket.data.userId;
    const user = socket.data.user;

    logger.info({ userId, username: user?.username, socketId: socket.id, event: 'socket_connected' }, 'User connected');
    
    setOnline(userId, socket.id);
    socket.emit('authenticated', { userId });

    // Register all event handlers
    registerMatchmakingHandlers(io, socket);
    registerChatHandlers(io, socket);
    registerVideoHandlers(io, socket);
    registerReportHandlers(io, socket);

    // Room management
    socket.on('join_room', async ({ room }) => {
      if (!room || !userId) return;
      
      try {
        // Leave all current rooms first
        for (const r of getSocketRooms(socket)) {
          socket.leave(r);
          socket.to(r).emit('peer_left', { socketId: socket.id, userId });
        }
        
        socket.join(room);
        socket.to(room).emit('peer_joined', { 
          socketId: socket.id, 
          userId, 
          username: user?.username || 'User' 
        });
        
        // Send room history
        const { query } = await import('../database/pool.js');
        const { rows } = await query(
          'SELECT * FROM chat_messages WHERE room_id = $1 ORDER BY created_at DESC LIMIT 50',
          [room]
        );
        socket.emit('room_history', {
          messages: rows.reverse().map(msg => ({
            id: msg.id,
            uid: msg.user_id,
            message: msg.message,
            timestamp: msg.created_at,
          })),
        });
        
        await query(
          'INSERT INTO room_activity (user_id, room_id, action, created_at) VALUES ($1, $2, $3, NOW())',
          [userId, room, 'join']
        );
      } catch (err) {
        logger.error({ err, userId, room, event: 'join_room_error' }, 'Failed to join room');
        socket.emit('error', { message: 'Failed to join room' });
      }
    });

    socket.on('leave_room', async ({ room }) => {
      if (!room || !userId || !socket.rooms.has(room)) return;
      
      try {
        socket.leave(room);
        socket.to(room).emit('peer_left', { socketId: socket.id, userId });
        
        const { query } = await import('../database/pool.js');
        await query(
          'INSERT INTO room_activity (user_id, room_id, action, created_at) VALUES ($1, $2, $3, NOW())',
          [userId, room, 'leave']
        );
      } catch (err) {
        logger.error({ err, userId, room, event: 'leave_room_error' }, 'Failed to leave room');
      }
    });

    socket.on('typing', ({ room }) => {
      if (!room || !socket.rooms.has(room)) return;
      socket.to(room).emit('typing', { uid: userId });
    });

    socket.on('reaction', ({ type, room }) => {
      let targetRoom = room;
      if (!targetRoom || !socket.rooms.has(targetRoom)) {
        const rooms = getSocketRooms(socket);
        if (rooms.length === 0) return;
        targetRoom = rooms[0];
      }
      socket.to(targetRoom).emit('reaction', { type, uid: userId, username: user?.username });
    });

    socket.on('name-update', async ({ room, name }) => {
      if (!userId) return;
      
      let targetRoom = room;
      if (!targetRoom || !socket.rooms.has(targetRoom)) {
        const rooms = getSocketRooms(socket);
        if (rooms.length === 0) return;
        targetRoom = rooms[0];
      }

      try {
        const { query } = await import('../database/pool.js');
        const { cacheService } = await import('../services/cacheService.js');
        
        await query('UPDATE users SET username = $1, updated_at = NOW() WHERE id = $2', [name, userId]);
        const updatedUser = { ...user, username: name };
        await cacheService.set(`user:${userId}`, updatedUser);
        socket.data.user = updatedUser;
        
        io.to(targetRoom).emit('name-update', { name, uid: userId });
      } catch (err) {
        logger.error({ err, userId, event: 'name_update_error' }, 'Name update failed');
      }
    });

    // Disconnect handler
    socket.on('disconnect', async (reason) => {
      logger.info({ userId, socketId: socket.id, reason, event: 'socket_disconnected' }, 'User disconnected');
      
      try {
        setOffline(userId);
        
        const { query } = await import('../database/pool.js');
        const { matchService, queueService } = await import('../services/index.js');
        
        await matchService.endMatch(userId);
        await queueService.remove(userId);
        socket.data.inQueue = false;

        for (const room of getSocketRooms(socket)) {
          socket.to(room).emit('peer_left', { socketId: socket.id, userId });
        }
      } catch (err) {
        logger.error({ err, userId, event: 'disconnect_error' }, 'Disconnect cleanup failed');
      }
    });
  });

  return io;
}

export function getIO() {
  return io;
}

// Online tracking functions
export function setOnline(userId, socketId) {
  onlineSockets.set(String(userId), socketId);
}

export function setOffline(userId) {
  onlineSockets.delete(String(userId));
}

export async function getOnlineSocketId(userId) {
  const local = onlineSockets.get(String(userId));
  if (local) return local;
  
  // Try Redis if available
  const { redis } = await import('../services/redisService.js');
  const cached = await redis.get(`socket:online:${userId}`);
  return cached || null;
}

export function getSocketRooms(socket) {
  const rooms = [];
  for (const room of socket.rooms) {
    if (room !== socket.id) rooms.push(room);
  }
  return rooms;
}
