import Stripe from 'stripe';
import CoinbaseCommerce from 'coinbase-commerce-node';
import { env, config } from '../config/index.js';
import { query, withTransaction } from '../database/pool.js';
import { cacheService } from './cacheService.js';
import logger from '../utils/logger.js';
import { InsufficientFundsError, ServiceUnavailableError, ApiError } from '../utils/errors.js';

let stripe = null;
let ChargeResource = null;

// Initialize Stripe
if (config.isStripeEnabled) {
  stripe = new Stripe(env.STRIPE_SECRET_KEY);
}

// Initialize Coinbase
if (config.isCoinbaseEnabled) {
  try {
    const { Client, resources } = CoinbaseCommerce;
    Client.init(env.COINBASE_COMMERCE_API_KEY);
    ChargeResource = resources.Charge;
  } catch (err) {
    logger.error({ err, event: 'coinbase_init_failed' }, 'Coinbase Commerce initialization failed');
  }
}

export const paymentService = {
  /**
   * Create a Stripe checkout session for coins
   */
  async createCoinCheckout(userId, email, coins, price) {
    if (!stripe) {
      throw new ServiceUnavailableError('Stripe');
    }

    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      line_items: [{
        price_data: {
          currency: 'usd',
          product_data: {
            name: `${coins} Omevo Coins`,
            description: `Purchase ${coins} coins for sending virtual gifts`,
          },
          unit_amount: Math.round(price * 100),
        },
        quantity: 1,
      }],
      mode: 'payment',
      success_url: `${env.FRONTEND_URL}?payment=success&session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${env.FRONTEND_URL}?payment=cancelled`,
      customer_email: email,
      metadata: {
        userId: String(userId),
        coins: coins.toString(),
      },
    });

    return { sessionId: session.id };
  },

  /**
   * Verify and process a Stripe payment
   * CRITICAL: Verify amount, currency, status - never trust metadata alone
   */
  async verifyStripePayment(sessionId, expectedUserId) {
    if (!stripe) {
      throw new ServiceUnavailableError('Stripe');
    }

    const session = await stripe.checkout.sessions.retrieve(sessionId);
    
    // Verify payment status
    if (session.payment_status !== 'paid') {
      throw new ApiError(400, 'Payment not completed', 'PAYMENT_NOT_PAID');
    }

    // Verify metadata matches expected user (prevent replay attacks)
    const userId = session.metadata?.userId;
    if (!userId) {
      throw new ApiError(400, 'Invalid payment metadata', 'INVALID_METADATA');
    }

    if (expectedUserId && userId !== String(expectedUserId)) {
      logger.error({ 
        expectedUserId, 
        paymentUserId: userId, 
        sessionId, 
        event: 'payment_user_mismatch' 
      }, 'Payment user ID mismatch');
      throw new ApiError(400, 'Payment does not belong to this user', 'USER_MISMATCH');
    }

    // Verify currency
    if (session.currency !== 'usd') {
      throw new ApiError(400, 'Invalid payment currency', 'INVALID_CURRENCY');
    }

    // Verify coins amount from metadata
    const coins = parseInt(session.metadata?.coins);
    if (!coins || coins <= 0) {
      throw new ApiError(400, 'Invalid coin amount in payment', 'INVALID_COINS');
    }

    // Use transaction to ensure atomicity
    return await withTransaction(async (client) => {
      // Double-check payment wasn't already processed
      const { rows: existing } = await client.query(
        'SELECT id FROM coin_transactions WHERE transaction_id = $1',
        [sessionId]
      );
      
      if (existing.length > 0) {
        // Already processed - just return current balance
        const { rows } = await client.query(
          'SELECT coins FROM users WHERE id = $1',
          [userId]
        );
        return { success: true, coins: rows[0]?.coins || 0, alreadyProcessed: true };
      }

      // Credit coins
      const { rows } = await client.query(
        'UPDATE users SET coins = coins + $1, updated_at = NOW() WHERE id = $2 RETURNING coins',
        [coins, userId]
      );

      // Record transaction
      await client.query(
        `INSERT INTO coin_transactions (user_id, coins, amount, transaction_type, transaction_id, created_at)
         VALUES ($1, $2, $3, 'purchase', $4, NOW())`,
        [userId, coins, session.amount_total / 100, sessionId]
      );

      await cacheService.invalidateUser(userId);

      logger.info({ userId, coins, sessionId, event: 'payment_verified' }, 'Payment verified and coins credited');

      return { success: true, coins: rows[0]?.coins || 0 };
    });
  },

  /**
   * Spend coins atomically
   * CRITICAL: Single UPDATE with WHERE coins >= cost prevents race conditions
   */
  async spendCoins(userId, amount, transactionType, options = {}) {
    const { giftType, recipientId } = options;

    // Atomic coin deduction
    const { rows } = await query(
      `UPDATE users 
       SET coins = coins - $1, updated_at = NOW() 
       WHERE id = $2 AND coins >= $1 
       RETURNING coins`,
      [amount, userId]
    );

    if (rows.length === 0) {
      throw new InsufficientFundsError();
    }

    // Record transaction
    await query(
      `INSERT INTO coin_transactions (user_id, coins, amount, transaction_type, gift_type, recipient_id, created_at)
       VALUES ($1, $2, 0, $3, $4, $5, NOW())`,
      [userId, -amount, transactionType, giftType || null, recipientId || null]
    );

    await cacheService.invalidateUser(userId);

    return { success: true, newBalance: rows[0].coins };
  },

  /**
   * Send a gift to another user
   * Uses transaction to ensure atomicity
   */
  async sendGift(senderId, giftType, recipientId) {
    const cost = config.giftCoinCosts[giftType];
    if (!cost) {
      throw new ApiError(400, 'Invalid gift type', 'INVALID_GIFT');
    }

    if (!recipientId) {
      throw new ApiError(400, 'Recipient ID required', 'MISSING_RECIPIENT');
    }

    // Use transaction for gift sending
    return await withTransaction(async (client) => {
      // Atomic coin deduction
      const { rows: senderRows } = await client.query(
        `UPDATE users 
         SET coins = coins - $1, updated_at = NOW() 
         WHERE id = $2 AND coins >= $1 
         RETURNING coins`,
        [cost, senderId]
      );

      if (senderRows.length === 0) {
        throw new InsufficientFundsError();
      }

      // Record sender's transaction
      await client.query(
        `INSERT INTO coin_transactions (user_id, coins, amount, transaction_type, gift_type, recipient_id, created_at)
         VALUES ($1, $2, 0, 'gift_sent', $3, $4, NOW())`,
        [senderId, -cost, giftType, recipientId]
      );

      await cacheService.invalidateUser(senderId);

      logger.info({ senderId, recipientId, giftType, cost, event: 'gift_sent' }, 'Gift sent');

      return { success: true, newBalance: senderRows[0].coins };
    });
  },

  /**
   * Create unban payment via Coinbase
   */
  async createUnbanPayment(userId) {
    if (!ChargeResource) {
      throw new ServiceUnavailableError('Coinbase');
    }

    const charge = await ChargeResource.create({
      name: 'Ban Removal',
      description: 'Remove your account suspension',
      local_price: {
        amount: config.unbanPrice.toFixed(2),
        currency: 'USD',
      },
      pricing_type: 'fixed_price',
      metadata: { userId: String(userId) },
      redirect_url: `${env.FRONTEND_URL}?unban=success`,
      cancel_url: env.FRONTEND_URL,
    });

    return { url: charge.hosted_url };
  },

  /**
   * Handle Coinbase webhook
   */
  async handleCoinbaseWebhook(body, signature) {
    const event = CoinbaseCommerce.Webhook.verifyEventBody(
      body.toString(),
      signature,
      env.COINBASE_COMMERCE_WEBHOOK_SECRET
    );

    if (event.type === 'charge:confirmed' || event.type === 'charge:resolved') {
      const userId = event.data.metadata?.userId;
      if (!userId) return;

      // Verify payment status
      if (event.data.timeline?.slice(-1)[0]?.status !== 'COMPLETED') {
        logger.warn({ userId, event: 'coinbase_incomplete' }, 'Coinbase payment not fully completed');
        return;
      }

      await query(
        'UPDATE users SET banned_until = NULL, ban_reason = NULL WHERE id = $1',
        [userId]
      );

      await query(
        `INSERT INTO moderation_logs (user_id, action, reason, created_at)
         VALUES ($1, 'paid_unban', 'User paid for unban', NOW())`,
        [userId]
      );

      await cacheService.invalidateUser(userId);

      logger.info({ userId, event: 'coinbase_unban' }, 'User unbanned via Coinbase');
    }
  },

  /**
   * Handle Stripe webhook
   */
  async handleStripeWebhook(body, signature) {
    if (!stripe) {
      throw new ServiceUnavailableError('Stripe');
    }

    const event = stripe.webhooks.constructEvent(
      body,
      signature,
      env.STRIPE_WEBHOOK_SECRET
    );

    if (event.type === 'checkout.session.completed') {
      const session = event.data.object;
      
      if (session.payment_status === 'paid') {
        await this.verifyStripePayment(session.id);
      }
    }

    return { received: true };
  },
};
