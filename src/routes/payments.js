import { Router } from 'express';
import express from 'express';
import { paymentService } from '../services/paymentService.js';
import { requireAuth } from '../middleware/auth.js';
import { validate } from '../middleware/validator.js';
import { 
  coinCheckoutSchema, 
  paymentVerifySchema, 
  giftSchema 
} from '../middleware/validator.js';
import { getOnlineSocketId, getIO } from '../sockets/index.js';
import { paymentLimiter } from '../middleware/rateLimit.js';
import logger from '../utils/logger.js';

const router = Router();

// Create coin checkout session
router.post('/create-checkout-session', requireAuth, paymentLimiter, validate(coinCheckoutSchema), async (req, res, next) => {
  try {
    const { coins, price } = req.validatedBody;
    const result = await paymentService.createCoinCheckout(req.user.id, req.user.email, coins, price);
    res.json(result);
  } catch (err) {
    next(err);
  }
});

// Verify payment
router.post('/verify-payment', requireAuth, validate(paymentVerifySchema), async (req, res, next) => {
  try {
    const { sessionId } = req.validatedBody;
    const result = await paymentService.verifyStripePayment(sessionId, req.user.id);
    res.json(result);
  } catch (err) {
    next(err);
  }
});

// Send gift
router.post('/create-gift-checkout', requireAuth, validate(giftSchema), async (req, res, next) => {
  try {
    const { giftType, recipientId } = req.validatedBody;
    const result = await paymentService.sendGift(req.user.id, giftType, recipientId);

    // Notify recipient
    const recipientSocketId = await getOnlineSocketId(String(recipientId));
    if (recipientSocketId) {
      const io = getIO();
      if (io) {
        io.to(recipientSocketId).emit('gift_received', {
          giftType,
          senderId: req.user.id,
          senderName: req.user.username || 'Someone',
        });
      }
    }

    res.json(result);
  } catch (err) {
    next(err);
  }
});

// Spend coins (generic)
router.post('/user/spend-coins', requireAuth, async (req, res, next) => {
  try {
    const { coins, type, giftType, recipientId } = req.body;
    
    if (!coins || coins <= 0) {
      return res.status(400).json({ error: 'Invalid coin amount' });
    }

    const result = await paymentService.spendCoins(req.user.id, coins, type || 'spend', { giftType, recipientId });
    res.json(result);
  } catch (err) {
    next(err);
  }
});

// Pay for unban (Coinbase)
router.post('/pay-unban', async (req, res, next) => {
  try {
    const { userId } = req.body;
    const result = await paymentService.createUnbanPayment(userId);
    res.json(result);
  } catch (err) {
    next(err);
  }
});

// Stripe webhook
router.post('/stripe-webhook', express.raw({ type: 'application/json' }), async (req, res, next) => {
  try {
    const signature = req.headers['stripe-signature'];
    const result = await paymentService.handleStripeWebhook(req.body, signature);
    res.json(result);
  } catch (err) {
    logger.error({ err, event: 'stripe_webhook_error' }, 'Stripe webhook failed');
    res.status(400).send(`Webhook Error: ${err.message}`);
  }
});

// Coinbase webhook
router.post('/coinbase-webhook', express.raw({ type: 'application/json' }), async (req, res, next) => {
  try {
    const signature = req.headers['x-cc-webhook-signature'];
    await paymentService.handleCoinbaseWebhook(req.body, signature);
    res.status(200).json({ received: true });
  } catch (err) {
    logger.error({ err, event: 'coinbase_webhook_error' }, 'Coinbase webhook failed');
    res.status(400).send(`Webhook Error: ${err.message}`);
  }
});

export default router;
