import { z } from 'zod';
import { ValidationError } from '../utils/errors.js';

// Helper: Coerce various input formats to a string array
const stringArray = z.preprocess((val) => {
  if (Array.isArray(val)) return val;
  if (typeof val === 'string') {
    return val.split(',').map(s => s.trim()).filter(Boolean);
  }
  return [];
}, z.array(z.string().max(30)).max(5));

// User schemas
export const preferencesSchema = z.object({
  gender: z.enum(['male', 'female', 'any']).optional().default('any'),
  looking_for: z.enum(['male', 'female', 'any']).optional().default('any'),
  location: z.string().max(50).optional().default('any'),
  interests: stringArray.optional().default([]),
  nickname: z.string().max(20).optional().default(''),
});

export const ageVerificationSchema = z.object({
  age: z.coerce.number().int().min(1).max(120),
});

export const displayNameSchema = z.object({
  display_name: z.string().min(1).max(20),
});

export const avatarSchema = z.object({
  avatarBase64: z.string().min(100),
});

export const spendCoinsSchema = z.object({
  coins: z.coerce.number().positive().int(),
  type: z.string().optional(),
  giftType: z.string().optional(),
  recipientId: z.union([z.string(), z.number()]).optional(),
});

export const giftSchema = z.object({
  giftType: z.enum(['rose', 'heart', 'star', 'diamond', 'crown', 'rocket']),
  recipientId: z.union([z.string(), z.number()]),
});

export const reportUserSchema = z.object({
  reportedUserId: z.union([z.string(), z.number()]),
  reason: z.string().min(10).max(200),
  roomId: z.string().optional(),
});

export const appealSchema = z.object({
  message: z.string().min(10).max(500),
});

export const adminBanSchema = z.object({
  userId: z.union([z.string(), z.number()]),
});

export const adminAppealResponseSchema = z.object({
  approved: z.boolean(),
  response: z.string().optional(),
});

export const paymentVerifySchema = z.object({
  sessionId: z.string(),
});

export const coinCheckoutSchema = z.object({
  coins: z.coerce.number().positive().int(),
  price: z.coerce.number().positive(),
});

export const agoraTokenSchema = z.object({
  channelName: z.string().min(1),
  uid: z.union([z.string(), z.number()]).optional(),
  role: z.enum(['publisher', 'subscriber']).optional().default('publisher'),
  expirySeconds: z.coerce.number().int().positive().optional().default(3600),
});

// Queue schemas (deprecated endpoints)
export const enqueueSchema = z.object({
  gender: z.enum(['male', 'female', 'any']).optional().default('any'),
  looking_for: z.enum(['male', 'female', 'any']).optional().default('any'),
  location: z.string().max(50).optional().default('any'),
  interests: stringArray.optional().default([]),
  nickname: z.string().max(20).optional().default(''),
});

/**
 * Validate request body against a schema
 */
export function validate(schema) {
  return (req, res, next) => {
    try {
      const result = schema.safeParse(req.body);
      
      if (!result.success) {
        const errors = result.error.issues.map(issue => ({
          field: issue.path.join('.'),
          message: issue.message,
          code: issue.code,
        }));
        return next(new ValidationError(errors));
      }
      
      req.validatedBody = result.data;
      next();
    } catch (err) {
      next(err);
    }
  };
}

/**
 * Validate query parameters against a schema
 */
export function validateQuery(schema) {
  return (req, res, next) => {
    try {
      const result = schema.safeParse(req.query);
      
      if (!result.success) {
        const errors = result.error.issues.map(issue => ({
          field: issue.path.join('.'),
          message: issue.message,
        }));
        return next(new ValidationError(errors));
      }
      
      req.validatedQuery = result.data;
      next();
    } catch (err) {
      next(err);
    }
  };
}
