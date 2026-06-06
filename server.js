// Reactific API — Auth + Stripe + Leaderboards
// Deploy on Render Web Service

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
const CLIENT_URL = process.env.CLIENT_URL || 'https://reactific.co';

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: DATABASE_URL?.includes('render') ? { rejectUnauthorized: false } : false
});

const stripe = STRIPE_SECRET ? new Stripe(STRIPE_SECRET) : null;

const app = express();

// ── Middleware ───────────────────────────────────────────
app.use(helmet());
app.use(cors({ origin: CLIENT_URL, credentials: true }));

// Stripe webhook needs raw body — must come before express.json()
app.post('/api/stripe/webhook', express.raw({ type: 'application/json' }), handleStripeWebhook);

app.use(express.json());

const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 100 });
app.use('/api/', limiter);

const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 20 });
app.use('/api/auth/', authLimiter);

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

function subRequired(req, res, next) {
  if (req.user.subscription_status !== 'active') {
    return res.status(403).json({ error: 'Full Court requires subscription' });
  }
  next();
}

// ── AUTH ENDPOINTS ──────────────────────────────────────

// Register
app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, username, password } = req.body;
    if (!email || !username || !password) {
      return res.status(400).json({ error: 'Email, username, and password required' });
    }
    if (username.length < 3 || username.length > 20) {
      return res.status(400).json({ error: 'Username must be 3-20 characters' });
    }
    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be 6+ characters' });
    }
    if (!/^[a-zA-Z0-9_]+$/.test(username)) {
      return res.status(400).json({ error: 'Username: letters, numbers, underscores only' });
    }

    const hash = await bcrypt.hash(password, 12);
    const result = await pool.query(
      `INSERT INTO users (email, username, password_hash) VALUES ($1, $2, $3) RETURNING id, email, username, subscription_status, created_at`,
      [email.toLowerCase().trim(), username.trim(), hash]
    );
    const user = result.rows[0];
    const token = jwt.sign(
      { id: user.id, email: user.email, username: user.username, subscription_status: user.subscription_status },
      JWT_SECRET,
      { expiresIn: '30d' }
    );
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
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

    const result = await pool.query(
      `SELECT id, email, username, password_hash, subscription_status FROM users WHERE email = $1`,
      [email.toLowerCase().trim()]
    );
    if (!result.rows.length) return res.status(401).json({ error: 'Invalid credentials' });

    const user = result.rows[0];
    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) return res.status(401).json({ error: 'Invalid credentials' });

    const token = jwt.sign(
      { id: user.id, email: user.email, username: user.username, subscription_status: user.subscription_status },
      JWT_SECRET,
      { expiresIn: '30d' }
    );
    res.json({
      user: { id: user.id, email: user.email, username: user.username, subscription_status: user.subscription_status },
      token
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get current user
app.get('/api/auth/me', authRequired, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, email, username, subscription_status, created_at FROM users WHERE id = $1`,
      [req.user.id]
    );
    if (!result.rows.length) return res.status(404).json({ error: 'User not found' });
    res.json({ user: result.rows[0] });
  } catch (err) {
    console.error('Me error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ── SCORES ENDPOINT ─────────────────────────────────────

app.post('/api/scores', authRequired, async (req, res) => {
  try {
    const { court, speed, level, score, streak, tier, targets_found, time_remaining_ms } = req.body;

    // Validate
    if (!['half', 'full'].includes(court)) return res.status(400).json({ error: 'Invalid court' });
    if (!['slow', 'med', 'fast'].includes(speed)) return res.status(400).json({ error: 'Invalid speed' });
    if (court === 'full' && req.user.subscription_status !== 'active') {
      return res.status(403).json({ error: 'Full Court requires subscription' });
    }

    const result = await pool.query(
      `INSERT INTO scores (user_id, court, speed, level, score, streak, tier, targets_found, time_remaining_ms)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id, created_at`,
      [req.user.id, court, speed, level, score || 0, streak || 0, tier || 1, targets_found || 0, time_remaining_ms || 0]
    );

    // Return their rank on this speed tier
    const rankResult = await pool.query(
      `SELECT COUNT(*) + 1 AS rank FROM (
         SELECT DISTINCT ON (user_id) user_id, score
         FROM scores WHERE court = $1 AND speed = $2
         ORDER BY user_id, score DESC
       ) top WHERE top.score > $3`,
      [court, speed, score || 0]
    );

    res.status(201).json({
      id: result.rows[0].id,
      rank: parseInt(rankResult.rows[0].rank),
      created_at: result.rows[0].created_at
    });
  } catch (err) {
    console.error('Score error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ── LEADERBOARD ENDPOINTS ───────────────────────────────

// All-time leaderboard
app.get('/api/leaderboard/alltime', async (req, res) => {
  try {
    const speed = req.query.speed || 'slow';
    const limit = Math.min(parseInt(req.query.limit) || 50, 100);

    const result = await pool.query(
      `SELECT DISTINCT ON (s.user_id)
         u.username, s.score, s.level, s.tier, s.streak, s.created_at
       FROM scores s
       JOIN users u ON u.id = s.user_id
       WHERE s.court = 'full' AND s.speed = $1
       ORDER BY s.user_id, s.score DESC`,
      [speed]
    );

    // Sort by score descending and limit
    const sorted = result.rows
      .sort((a, b) => b.score - a.score)
      .slice(0, limit)
      .map((row, i) => ({ rank: i + 1, ...row }));

    res.json({ speed, period: 'alltime', entries: sorted });
  } catch (err) {
    console.error('Leaderboard error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Daily leaderboard
app.get('/api/leaderboard/daily', async (req, res) => {
  try {
    const speed = req.query.speed || 'slow';
    const limit = Math.min(parseInt(req.query.limit) || 50, 100);

    const result = await pool.query(
      `SELECT DISTINCT ON (s.user_id)
         u.username, s.score, s.level, s.tier, s.streak, s.created_at
       FROM scores s
       JOIN users u ON u.id = s.user_id
       WHERE s.court = 'full' AND s.speed = $1 AND s.created_at >= CURRENT_DATE
       ORDER BY s.user_id, s.score DESC`,
      [speed]
    );

    const sorted = result.rows
      .sort((a, b) => b.score - a.score)
      .slice(0, limit)
      .map((row, i) => ({ rank: i + 1, ...row }));

    res.json({ speed, period: 'daily', entries: sorted });
  } catch (err) {
    console.error('Daily leaderboard error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Weekly leaderboard
app.get('/api/leaderboard/weekly', async (req, res) => {
  try {
    const speed = req.query.speed || 'slow';
    const limit = Math.min(parseInt(req.query.limit) || 50, 100);

    const result = await pool.query(
      `SELECT DISTINCT ON (s.user_id)
         u.username, s.score, s.level, s.tier, s.streak, s.created_at
       FROM scores s
       JOIN users u ON u.id = s.user_id
       WHERE s.court = 'full' AND s.speed = $1 AND s.created_at >= date_trunc('week', CURRENT_DATE)
       ORDER BY s.user_id, s.score DESC`,
      [speed]
    );

    const sorted = result.rows
      .sort((a, b) => b.score - a.score)
      .slice(0, limit)
      .map((row, i) => ({ rank: i + 1, ...row }));

    res.json({ speed, period: 'weekly', entries: sorted });
  } catch (err) {
    console.error('Weekly leaderboard error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// My rank
app.get('/api/leaderboard/myrank', authRequired, async (req, res) => {
  try {
    const speed = req.query.speed || 'slow';

    // Get user's best score
    const best = await pool.query(
      `SELECT score, level, tier, streak FROM scores
       WHERE user_id = $1 AND court = 'full' AND speed = $2
       ORDER BY score DESC LIMIT 1`,
      [req.user.id, speed]
    );

    if (!best.rows.length) return res.json({ rank: null, score: 0 });

    const userScore = best.rows[0].score;
    const rankResult = await pool.query(
      `SELECT COUNT(*) + 1 AS rank FROM (
         SELECT DISTINCT ON (user_id) user_id, score
         FROM scores WHERE court = 'full' AND speed = $1
         ORDER BY user_id, score DESC
       ) top WHERE top.score > $2`,
      [speed, userScore]
    );

    res.json({
      rank: parseInt(rankResult.rows[0].rank),
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
  try {
    // Get or create Stripe customer
    let customerId;
    const user = await pool.query(`SELECT stripe_customer_id, email FROM users WHERE id = $1`, [req.user.id]);
    
    if (user.rows[0].stripe_customer_id) {
      customerId = user.rows[0].stripe_customer_id;
    } else {
      const customer = await stripe.customers.create({
        email: user.rows[0].email,
        metadata: { user_id: req.user.id }
      });
      customerId = customer.id;
      await pool.query(`UPDATE users SET stripe_customer_id = $1 WHERE id = $2`, [customerId, req.user.id]);
    }

    const session = await stripe.checkout.sessions.create({
      customer: customerId,
      payment_method_types: ['card'],
      line_items: [{ price: STRIPE_PRICE_ID, quantity: 1 }],
      mode: 'subscription',
      success_url: `${CLIENT_URL}/fullcourt?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${CLIENT_URL}`,
      metadata: { user_id: req.user.id }
    });

    res.json({ url: session.url });
  } catch (err) {
    console.error('Checkout error:', err);
    res.status(500).json({ error: 'Failed to create checkout' });
  }
});

// Customer portal (manage subscription)
app.post('/api/stripe/portal', authRequired, async (req, res) => {
  if (!stripe) return res.status(500).json({ error: 'Stripe not configured' });
  try {
    const user = await pool.query(`SELECT stripe_customer_id FROM users WHERE id = $1`, [req.user.id]);
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
  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, req.headers['stripe-signature'], STRIPE_WEBHOOK_SECRET);
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
            `UPDATE users SET subscription_status = 'active', stripe_customer_id = $1, updated_at = NOW() WHERE id = $2`,
            [session.customer, session.metadata.user_id]
          );
          console.log(`Subscription activated for user ${session.metadata.user_id}`);
        }
        break;
      }
      case 'customer.subscription.updated': {
        const sub = event.data.object;
        const status = sub.status === 'active' ? 'active' : 'inactive';
        await pool.query(
          `UPDATE users SET subscription_status = $1, updated_at = NOW() WHERE stripe_customer_id = $2`,
          [status, sub.customer]
        );
        break;
      }
      case 'customer.subscription.deleted': {
        const sub = event.data.object;
        await pool.query(
          `UPDATE users SET subscription_status = 'cancelled', updated_at = NOW() WHERE stripe_customer_id = $1`,
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

// ── One-time DB setup (delete after use) ────────────────
app.get('/api/setup-db', async (req, res) => {
  try {
    await pool.query(`CREATE EXTENSION IF NOT EXISTS "uuid-ossp"`);
    await pool.query(`CREATE TABLE IF NOT EXISTS users (
      id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
      email VARCHAR(255) UNIQUE NOT NULL,
      username VARCHAR(30) UNIQUE NOT NULL,
      password_hash VARCHAR(255) NOT NULL,
      stripe_customer_id VARCHAR(255),
      subscription_status VARCHAR(20) DEFAULT 'free',
      created_at TIMESTAMPTZ DEFAULT NOW(),
      updated_at TIMESTAMPTZ DEFAULT NOW()
    )`);
    await pool.query(`CREATE TABLE IF NOT EXISTS scores (
      id BIGSERIAL PRIMARY KEY,
      user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      court VARCHAR(10) NOT NULL DEFAULT 'full',
      speed VARCHAR(10) NOT NULL,
      level INTEGER NOT NULL,
      score INTEGER NOT NULL,
      streak INTEGER NOT NULL DEFAULT 0,
      tier INTEGER NOT NULL DEFAULT 1,
      targets_found INTEGER NOT NULL DEFAULT 0,
      time_remaining_ms INTEGER DEFAULT 0,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_scores_user ON scores(user_id)`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_scores_created ON scores(created_at DESC)`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_scores_leaderboard ON scores(court, speed, score DESC)`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_scores_daily ON scores(created_at, score DESC)`);
    res.json({ status: 'ok', message: 'Tables created' });
  } catch (err) {
    console.error('Setup error:', err);
    res.status(500).json({ error: err.message });
  }
});
// ── Health check ────────────────────────────────────────
app.get('/api/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ status: 'ok', db: 'connected' });
  } catch {
    res.status(500).json({ status: 'error', db: 'disconnected' });
  }
});

// ── Start ───────────────────────────────────────────────
app.listen(PORT, () => console.log(`Reactific API running on port ${PORT}`));
