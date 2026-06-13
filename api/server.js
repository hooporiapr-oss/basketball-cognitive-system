// Reactific API — Auth + Stripe + Leaderboards
// Deploy on Render Web Service
// Product flow: Free 5x5 Practice → Login → Stripe → STROBE™ Arena 5x10 → Leaderboard

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Stripe = require('stripe');

// ── Config ──────────────────────────────────────────────
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'change-me-in-production';
const DATABASE_URL = process.env.DATABASE_URL;
const STRIPE_SECRET = process.env.STRIPE_SECRET_KEY;
const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET;
const STRIPE_PRICE_ID = process.env.STRIPE_PRICE_ID;

const CLIENT_URL = process.env.CLIENT_URL || 'https://reactificgaming.com';
const COMPETE_URL = process.env.COMPETE_URL || `${CLIENT_URL}/compete/strobe-01-compete.html`;
const STRIPE_CANCEL_URL = process.env.STRIPE_CANCEL_URL || `${CLIENT_URL}/compete/com-01.html`;

const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || CLIENT_URL)
  .split(',')
  .map(origin => origin.trim())
  .filter(Boolean);

if (process.env.NODE_ENV === 'production' && JWT_SECRET === 'change-me-in-production') {
  console.warn('WARNING: JWT_SECRET is using the fallback value. Set JWT_SECRET in production.');
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: DATABASE_URL?.includes('render') ? { rejectUnauthorized: false } : false
});

const stripe = STRIPE_SECRET ? new Stripe(STRIPE_SECRET) : null;

const app = express();

// ── Middleware ───────────────────────────────────────────
app.use(helmet());

app.use(cors({
  origin(origin, callback) {
    if (!origin || ALLOWED_ORIGINS.includes(origin)) return callback(null, true);
    return callback(new Error(`CORS blocked origin: ${origin}`));
  },
  credentials: true
}));

// Stripe webhook needs raw body — must come before express.json()
app.post('/api/stripe/webhook', express.raw({ type: 'application/json' }), handleStripeWebhook);

app.use(express.json({ limit: '1mb' }));

const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 120 });
app.use('/api/', limiter);

const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 30 });
app.use('/api/auth/', authLimiter);

// ── Helpers ─────────────────────────────────────────────
function normalizeSpeed(speed) {
  const value = String(speed || '').trim().toLowerCase();

  if (['slow', 'training', '5', '7', '60'].includes(value)) return 'slow';
  if (['med', 'medium', 'tempo', '3', '90'].includes(value)) return 'med';
  if (['fast', 'elite', '2', '120'].includes(value)) return 'fast';

  return null;
}

function makeToken(user) {
  return jwt.sign(
    {
      id: user.id,
      email: user.email,
      username: user.username,
      subscription_status: user.subscription_status
    },
    JWT_SECRET,
    { expiresIn: '30d' }
  );
}

async function getUserById(userId) {
  const result = await pool.query(
    `SELECT id, email, username, subscription_status, stripe_customer_id, created_at
     FROM users
     WHERE id = $1`,
    [userId]
  );
  return result.rows[0] || null;
}

async function userHasActiveSubscription(userId) {
  const user = await getUserById(userId);
  return !!user && user.subscription_status === 'active';
}

// ── Auth Middleware ─────────────────────────────────────
function authRequired(req, res, next) {
  const header = req.headers.authorization;
  if (!header?.startsWith('Bearer ')) return res.status(401).json({ error: 'No token' });

  try {
    req.user = jwt.verify(header.slice(7), JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
}

async function subRequired(req, res, next) {
  try {
    const active = await userHasActiveSubscription(req.user.id);
    if (!active) return res.status(403).json({ error: 'STROBE Arena requires subscription' });
    next();
  } catch (err) {
    console.error('Subscription check error:', err);
    res.status(500).json({ error: 'Server error' });
  }
}

// ── AUTH ENDPOINTS ──────────────────────────────────────

// Register
app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, username, password } = req.body;

    const cleanEmail = String(email || '').toLowerCase().trim();
    const cleanUsername = String(username || '').trim();

    if (!cleanEmail || !cleanUsername || !password) {
      return res.status(400).json({ error: 'Email, username, and password required' });
    }
    if (!/^\S+@\S+\.\S+$/.test(cleanEmail)) {
      return res.status(400).json({ error: 'Valid email required' });
    }
    if (cleanUsername.length < 3 || cleanUsername.length > 20) {
      return res.status(400).json({ error: 'Username must be 3-20 characters' });
    }
    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be 6+ characters' });
    }
    if (!/^[a-zA-Z0-9_]+$/.test(cleanUsername)) {
      return res.status(400).json({ error: 'Username: letters, numbers, underscores only' });
    }

    const hash = await bcrypt.hash(password, 12);
    const result = await pool.query(
      `INSERT INTO users (email, username, password_hash)
       VALUES ($1, $2, $3)
       RETURNING id, email, username, subscription_status, created_at`,
      [cleanEmail, cleanUsername, hash]
    );

    const user = result.rows[0];
    const token = makeToken(user);

    res.status(201).json({ user, token });
  } catch (err) {
    if (err.code === '23505') {
      const field = err.constraint?.includes('email') ? 'Email' : 'Username';
      return res.status(409).json({ error: `${field} already taken` });
    }
    console.error('Register error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const cleanEmail = String(email || '').toLowerCase().trim();

    if (!cleanEmail || !password) {
      return res.status(400).json({ error: 'Email and password required' });
    }

    const result = await pool.query(
      `SELECT id, email, username, password_hash, subscription_status
       FROM users
       WHERE email = $1`,
      [cleanEmail]
    );

    if (!result.rows.length) return res.status(401).json({ error: 'Invalid credentials' });

    const user = result.rows[0];
    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) return res.status(401).json({ error: 'Invalid credentials' });

    const publicUser = {
      id: user.id,
      email: user.email,
      username: user.username,
      subscription_status: user.subscription_status
    };

    const token = makeToken(publicUser);
    res.json({ user: publicUser, token });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get current user
app.get('/api/auth/me', authRequired, async (req, res) => {
  try {
    const user = await getUserById(req.user.id);
    if (!user) return res.status(404).json({ error: 'User not found' });

    res.json({
      user: {
        id: user.id,
        email: user.email,
        username: user.username,
        subscription_status: user.subscription_status,
        created_at: user.created_at
      }
    });
  } catch (err) {
    console.error('Me error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ── SCORES ENDPOINT ─────────────────────────────────────

app.post('/api/scores', authRequired, async (req, res) => {
  try {
    const {
      court = 'full',
      speed,
      level,
      score,
      streak,
      tier,
      targets_found,
      time_remaining_ms
    } = req.body;

    const normalizedSpeed = normalizeSpeed(speed);

    if (!['half', 'full'].includes(court)) return res.status(400).json({ error: 'Invalid court' });
    if (!normalizedSpeed) return res.status(400).json({ error: 'Invalid speed' });

    const safeLevel = Math.max(1, Math.min(parseInt(level, 10) || 1, 10));
    const safeScore = Math.max(0, parseInt(score, 10) || 0);
    const safeStreak = Math.max(0, parseInt(streak, 10) || 0);
    const safeTier = Math.max(1, Math.min(parseInt(tier, 10) || 1, 10));
    const safeTargets = Math.max(0, parseInt(targets_found, 10) || 0);
    const safeTimeRemaining = Math.max(0, parseInt(time_remaining_ms, 10) || 0);

    if (court === 'full') {
      const active = await userHasActiveSubscription(req.user.id);
      if (!active) return res.status(403).json({ error: 'STROBE Arena requires subscription' });
    }

    const result = await pool.query(
      `INSERT INTO scores (user_id, court, speed, level, score, streak, tier, targets_found, time_remaining_ms)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
       RETURNING id, created_at`,
      [
        req.user.id,
        court,
        normalizedSpeed,
        safeLevel,
        safeScore,
        safeStreak,
        safeTier,
        safeTargets,
        safeTimeRemaining
      ]
    );

    const rankResult = await pool.query(
      `SELECT COUNT(*) + 1 AS rank
       FROM (
         SELECT DISTINCT ON (user_id) user_id, score
         FROM scores
         WHERE court = $1 AND speed = $2
         ORDER BY user_id, score DESC, created_at ASC
       ) top
       WHERE top.score > $3`,
      [court, normalizedSpeed, safeScore]
    );

    res.status(201).json({
      id: result.rows[0].id,
      rank: parseInt(rankResult.rows[0].rank, 10),
      speed: normalizedSpeed,
      created_at: result.rows[0].created_at
    });
  } catch (err) {
    console.error('Score error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ── LEADERBOARD ENDPOINTS ───────────────────────────────

async function getLeaderboard(period, speedInput, limitInput) {
  const speed = normalizeSpeed(speedInput) || 'slow';
  const limit = Math.min(parseInt(limitInput, 10) || 50, 100);

  let timeFilter = '';
  if (period === 'daily') timeFilter = `AND s.created_at >= CURRENT_DATE`;
  if (period === 'weekly') timeFilter = `AND s.created_at >= date_trunc('week', CURRENT_DATE)`;

  const result = await pool.query(
    `SELECT DISTINCT ON (s.user_id)
       u.username,
       s.score,
       s.level,
       s.tier,
       s.streak,
       s.created_at
     FROM scores s
     JOIN users u ON u.id = s.user_id
     WHERE s.court = 'full'
       AND s.speed = $1
       ${timeFilter}
     ORDER BY s.user_id, s.score DESC, s.created_at ASC`,
    [speed]
  );

  const entries = result.rows
    .sort((a, b) => b.score - a.score || new Date(a.created_at) - new Date(b.created_at))
    .slice(0, limit)
    .map((row, i) => ({ rank: i + 1, ...row }));

  return { speed, period, entries };
}

// All-time leaderboard
app.get('/api/leaderboard/alltime', async (req, res) => {
  try {
    res.json(await getLeaderboard('alltime', req.query.speed, req.query.limit));
  } catch (err) {
    console.error('Leaderboard error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Daily leaderboard
app.get('/api/leaderboard/daily', async (req, res) => {
  try {
    res.json(await getLeaderboard('daily', req.query.speed, req.query.limit));
  } catch (err) {
    console.error('Daily leaderboard error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Weekly leaderboard
app.get('/api/leaderboard/weekly', async (req, res) => {
  try {
    res.json(await getLeaderboard('weekly', req.query.speed, req.query.limit));
  } catch (err) {
    console.error('Weekly leaderboard error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// My rank
app.get('/api/leaderboard/myrank', authRequired, async (req, res) => {
  try {
    const speed = normalizeSpeed(req.query.speed) || 'slow';

    const best = await pool.query(
      `SELECT score, level, tier, streak, created_at
       FROM scores
       WHERE user_id = $1 AND court = 'full' AND speed = $2
       ORDER BY score DESC, created_at ASC
       LIMIT 1`,
      [req.user.id, speed]
    );

    if (!best.rows.length) return res.json({ rank: null, score: 0, speed });

    const userScore = best.rows[0].score;

    const rankResult = await pool.query(
      `SELECT COUNT(*) + 1 AS rank
       FROM (
         SELECT DISTINCT ON (user_id) user_id, score
         FROM scores
         WHERE court = 'full' AND speed = $1
         ORDER BY user_id, score DESC, created_at ASC
       ) top
       WHERE top.score > $2`,
      [speed, userScore]
    );

    res.json({
      rank: parseInt(rankResult.rows[0].rank, 10),
      speed,
      ...best.rows[0]
    });
  } catch (err) {
    console.error('My rank error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ── STRIPE ENDPOINTS ────────────────────────────────────

// Create checkout session
app.post('/api/stripe/checkout', authRequired, async (req, res) => {
  if (!stripe) return res.status(500).json({ error: 'Stripe not configured' });
  if (!STRIPE_PRICE_ID) return res.status(500).json({ error: 'Stripe price not configured' });

  try {
    let customerId;

    const user = await pool.query(
      `SELECT stripe_customer_id, email FROM users WHERE id = $1`,
      [req.user.id]
    );

    if (!user.rows.length) return res.status(404).json({ error: 'User not found' });

    if (user.rows[0].stripe_customer_id) {
      customerId = user.rows[0].stripe_customer_id;
    } else {
      const customer = await stripe.customers.create({
        email: user.rows[0].email,
        metadata: { user_id: req.user.id }
      });

      customerId = customer.id;

      await pool.query(
        `UPDATE users SET stripe_customer_id = $1, updated_at = NOW() WHERE id = $2`,
        [customerId, req.user.id]
      );
    }

    const session = await stripe.checkout.sessions.create({
      customer: customerId,
      payment_method_types: ['card'],
      line_items: [{ price: STRIPE_PRICE_ID, quantity: 1 }],
      mode: 'subscription',
      success_url: `${COMPETE_URL}?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: STRIPE_CANCEL_URL,
      metadata: { user_id: req.user.id }
    });

    res.json({ url: session.url });
  } catch (err) {
    console.error('Checkout error:', err);
    res.status(500).json({ error: 'Failed to create checkout' });
  }
});

// Customer portal
app.post('/api/stripe/portal', authRequired, async (req, res) => {
  if (!stripe) return res.status(500).json({ error: 'Stripe not configured' });

  try {
    const user = await pool.query(
      `SELECT stripe_customer_id FROM users WHERE id = $1`,
      [req.user.id]
    );

    if (!user.rows[0]?.stripe_customer_id) {
      return res.status(400).json({ error: 'No subscription found' });
    }

    const session = await stripe.billingPortal.sessions.create({
      customer: user.rows[0].stripe_customer_id,
      return_url: CLIENT_URL
    });

    res.json({ url: session.url });
  } catch (err) {
    console.error('Portal error:', err);
    res.status(500).json({ error: 'Failed to create portal session' });
  }
});

// Stripe webhook
async function handleStripeWebhook(req, res) {
  if (!stripe) return res.status(500).send('Stripe not configured');
  if (!STRIPE_WEBHOOK_SECRET) return res.status(500).send('Stripe webhook secret not configured');

  let event;

  try {
    event = stripe.webhooks.constructEvent(
      req.body,
      req.headers['stripe-signature'],
      STRIPE_WEBHOOK_SECRET
    );
  } catch (err) {
    console.error('Webhook signature error:', err.message);
    return res.status(400).send('Invalid signature');
  }

  try {
    switch (event.type) {
      case 'checkout.session.completed': {
        const session = event.data.object;

        if (session.metadata?.user_id) {
          await pool.query(
            `UPDATE users
             SET subscription_status = 'active',
                 stripe_customer_id = $1,
                 updated_at = NOW()
             WHERE id = $2`,
            [session.customer, session.metadata.user_id]
          );
          console.log(`Subscription activated for user ${session.metadata.user_id}`);
        }
        break;
      }

      case 'customer.subscription.created':
      case 'customer.subscription.updated': {
        const sub = event.data.object;
        const status = sub.status === 'active' || sub.status === 'trialing' ? 'active' : 'inactive';

        await pool.query(
          `UPDATE users
           SET subscription_status = $1,
               updated_at = NOW()
           WHERE stripe_customer_id = $2`,
          [status, sub.customer]
        );
        break;
      }

      case 'customer.subscription.deleted': {
        const sub = event.data.object;

        await pool.query(
          `UPDATE users
           SET subscription_status = 'cancelled',
               updated_at = NOW()
           WHERE stripe_customer_id = $1`,
          [sub.customer]
        );
        break;
      }
    }
  } catch (err) {
    console.error('Webhook handler error:', err);
  }

  res.json({ received: true });
}

// ── Health check ────────────────────────────────────────
app.get('/api/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({
      status: 'ok',
      db: 'connected',
      stripe: !!stripe,
      client_url: CLIENT_URL
    });
  } catch {
    res.status(500).json({ status: 'error', db: 'disconnected' });
  }
});

// ── Start ───────────────────────────────────────────────
app.listen(PORT, () => console.log(`Reactific API running on port ${PORT}`));
