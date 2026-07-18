import { randomUUID } from 'crypto';

/**
 * Generate a unique channel name for a match
 */
export function generateChannelName(userId1, userId2) {
  const min = Math.min(Number(userId1), Number(userId2));
  const max = Math.max(Number(userId1), Number(userId2));
  return `omevo_${min}_${max}_${Date.now()}`;
}

/**
 * Extract IP address from request, handling proxies
 */
export function getClientIp(req) {
  return req.headers['x-forwarded-for']?.split(',')[0]?.trim() 
    || req.socket.remoteAddress 
    || '127.0.0.1';
}

/**
 * Delay execution for async operations
 */
export function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Safe JSON parse with fallback
 */
export function safeJsonParse(str, fallback = null) {
  try {
    return JSON.parse(str);
  } catch {
    return fallback;
  }
}

/**
 * Generate a request ID for tracing
 */
export function generateRequestId() {
  return randomUUID().replace(/-/g, '').substring(0, 16);
}

/**
 * Normalize and validate interests array
 */
export function normalizeInterests(interests, maxLength = 5, itemMaxLength = 30) {
  if (!Array.isArray(interests)) return [];
  return interests
    .filter(i => typeof i === 'string' && i.length > 0 && i.length <= itemMaxLength)
    .slice(0, maxLength);
}
