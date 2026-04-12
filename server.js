// ============================================================
// VeloCoach AI â Backend Server
// Handles Auth, Strava OAuth, and proxies activity data
// ============================================================

require('dotenv').config({ path: '.secrets/tokens.env' });
const express   = require('express');
const cors      = require('cors');
const crypto    = require('crypto');
const bcrypt    = require('bcryptjs');
const jwt       = require('jsonwebtoken');
const fs        = require('fs');
const path      = require('path');
const { Pool }  = require('pg');
const Anthropic = require('@anthropic-ai/sdk');
const app       = express();
const PORT      = process.env.PORT || 3000;

// ---------- Anthropic ----------
const anthropic = new Anthropic({ apiKey: process.env.CLAUDE_API_KEY });
const COACHING_MODEL      = 'claude-sonnet-4-6';
const RATE_LIMIT_PER_DAY  = parseInt(process.env.RATE_LIMIT_QUERIES_PER_DAY || '50', 10);
const coachingPrompt      = fs.readFileSync(path.join(__dirname, 'coaching-prompt.txt'), 'utf-8');

// ---------- PostgreSQL ----------
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });

async function initSchema() {
  // Core users table
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id            SERIAL PRIMARY KEY,
      email         TEXT UNIQUE NOT NULL,
      name          TEXT NOT NULL DEFAULT 'Athlete',
      password_hash TEXT NOT NULL,
      ftp           INTEGER DEFAULT 300,
      weight        NUMERIC(5,2) DEFAULT 75,
      created_at    TIMESTAMPTZ DEFAULT NOW()
    );
  `);

  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS tcs_accepted_at    TIMESTAMPTZ`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS tcs_version        TEXT`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS strava_athlete_id    BIGINT`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS strava_access_token  TEXT`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS strava_refresh_token TEXT`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS strava_expires_at    INTEGER`);

  // Coaching queries log — rate limiting + analytics
  await pool.query(`
    CREATE TABLE IF NOT EXISTS coaching_queries (
      id         SERIAL PRIMARY KEY,
      user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      query      TEXT,
      response   TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);
  // Index on (user_id, created_at) for daily rate-limit queries — created_at::date is STABLE
  // not IMMUTABLE so can't be used in functional index; plain created_at works fine
  await pool.query(`
    CREATE INDEX IF NOT EXISTS coaching_queries_user_date
      ON coaching_queries (user_id, created_at)
  `);

  console.log('DB schema ready');
}

// ---------- CORS ----------
const ALLOWED_ORIGINS = [
    'https://velocoach-ai.netlify.app',
    'https://app.velocoach-ai.com'
  ];
if (process.env.FRONTEND_URL) ALLOWED_ORIGINS.push(process.env.FRONTEND_URL);

app.use(cors({
    origin: function(origin, callback) {
          if (!origin || ALLOWED_ORIGINS.includes(origin)) {
                  callback(null, true);
          } else {
                  callback(new Error('Not allowed by CORS'));
          }
    },
    credentials: true
}));
app.use(express.json());

// ---------- In-memory stores (Strava + TP only) ----------
const tokenStore   = {};   // Strava tokens  { athleteId: { access_token, refresh_token, expires_at, athlete } }
const tpTokenStore = {};   // TrainingPeaks  { athlete_id: { token, connected_at } }

// ---------- Auth helpers ----------
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) { console.error('FATAL: JWT_SECRET env var not set'); process.exit(1); }

function signToken(userId, email) {
  return jwt.sign({ userId, email }, JWT_SECRET, { expiresIn: '30d' });
}

// Auth middleware
function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  try {
    req.user = jwt.verify(authHeader.slice(7), JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid or expired token' });
  }
}

// ---------- Health check ----------
app.get('/', (req, res) => {
  res.json({
    status: 'ok',
    service: 'VeloCoach Backend',
    endpoints: ['/auth/signup', '/auth/login', '/auth/profile', '/strava/auth', '/strava/callback', '/tp/connect', '/tp/workouts']
  });
});

// ==========================================================
//  AUTH ENDPOINTS
// ==========================================================

// Sign up
app.post('/auth/signup', async (req, res) => {
  const { email, password, name, tcs_accepted, tcs_version } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password are required' });
  if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
  if (!tcs_accepted) return res.status(400).json({ error: 'You must accept the Terms of Service to create an account' });

  const normalizedEmail = email.toLowerCase().trim();
  try {
    const password_hash = await bcrypt.hash(password, 12);
    const { rows } = await pool.query(
      `INSERT INTO users (email, name, password_hash, tcs_accepted_at, tcs_version)
       VALUES ($1, $2, $3, NOW(), $4)
       RETURNING id, email, name`,
      [normalizedEmail, name || 'Athlete', password_hash, tcs_version || '1.0']
    );
    const user = rows[0];
    const token = signToken(user.id, user.email);
    console.log(`New user signed up: ${user.email} (${user.id})`);
    res.json({ token, userId: user.id, email: user.email, name: user.name });
  } catch (e) {
    if (e.code === '23505') return res.status(409).json({ error: 'An account with this email already exists. Try signing in.' });
    console.error('Signup error:', e);
    res.status(500).json({ error: 'Failed to create account' });
  }
});

// Login
app.post('/auth/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password are required' });

  const normalizedEmail = email.toLowerCase().trim();
  try {
    const { rows } = await pool.query(
      `SELECT id, email, name, password_hash, ftp, weight FROM users WHERE email = $1`,
      [normalizedEmail]
    );
    const user = rows[0];
    if (!user) return res.status(401).json({ error: 'Invalid email or password' });

    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) return res.status(401).json({ error: 'Invalid email or password' });

    const token = signToken(user.id, user.email);
    console.log(`User logged in: ${user.email}`);
    res.json({ token, userId: user.id, email: user.email, name: user.name, profile: { ftp: user.ftp, weight: user.weight } });
  } catch (e) {
    console.error('Login error:', e);
    res.status(500).json({ error: 'Login failed' });
  }
});

// Get profile (authenticated)
app.get('/auth/profile', requireAuth, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT id, email, name, ftp, weight FROM users WHERE id = $1`,
      [req.user.userId]
    );
    if (!rows[0]) return res.status(404).json({ error: 'User not found' });
    const u = rows[0];
    res.json({ userId: u.id, email: u.email, name: u.name, profile: { ftp: u.ftp, weight: u.weight } });
  } catch (e) {
    res.status(500).json({ error: 'Failed to fetch profile' });
  }
});

// Update profile (authenticated)
app.put('/auth/profile', requireAuth, async (req, res) => {
  const { name, ftp, weight } = req.body;
  try {
    const { rows } = await pool.query(
      `UPDATE users SET
        name   = COALESCE($1, name),
        ftp    = COALESCE($2, ftp),
        weight = COALESCE($3, weight)
       WHERE id = $4
       RETURNING id, email, name, ftp, weight`,
      [name || null, ftp || null, weight || null, req.user.userId]
    );
    if (!rows[0]) return res.status(404).json({ error: 'User not found' });
    const u = rows[0];
    res.json({ userId: u.id, email: u.email, name: u.name, profile: { ftp: u.ftp, weight: u.weight } });
  } catch (e) {
    res.status(500).json({ error: 'Failed to update profile' });
  }
});

// ==========================================================
//  COACHING ENDPOINT
// ==========================================================

app.post('/api/coaching/ask', requireAuth, async (req, res) => {
  const userId = req.user.userId;
  const { userMsg, systemSupplement } = req.body;

  if (!userMsg) return res.status(400).json({ error: 'userMsg is required' });

  // Rate limit: count today's queries for this user
  try {
    const { rows } = await pool.query(
      `SELECT COUNT(*) AS cnt FROM coaching_queries
        WHERE user_id = $1 AND created_at::date = CURRENT_DATE`,
      [userId]
    );
    if (parseInt(rows[0].cnt, 10) >= RATE_LIMIT_PER_DAY) {
      return res.status(429).json({
        error: `Daily coaching limit reached (${RATE_LIMIT_PER_DAY} queries/day). Try again tomorrow.`
      });
    }
  } catch (e) {
    console.error('Rate limit check failed:', e);
    // Allow through on DB error — don't block users due to rate-limit DB issues
  }

  // Build system prompt: base prompt from file + optional athlete-specific supplement
  const systemPrompt = systemSupplement
    ? `${coachingPrompt}\n\n---\nATHLETE PROFILE (personalised context):\n${systemSupplement}`
    : coachingPrompt;

  try {
    const message = await anthropic.messages.create({
      model:      COACHING_MODEL,
      max_tokens: 2000,
      system:     systemPrompt,
      messages:   [{ role: 'user', content: userMsg }]
    });

    const responseText = message.content[0].text;

    // Log query for analytics and rate limiting
    await pool.query(
      `INSERT INTO coaching_queries (user_id, query, response) VALUES ($1, $2, $3)`,
      [userId, userMsg.slice(0, 2000), responseText.slice(0, 8000)]
    ).catch(err => console.error('Failed to log coaching query:', err));

    console.log(`Coaching query for user ${userId} — ${message.usage?.input_tokens || '?'} in / ${message.usage?.output_tokens || '?'} out tokens`);
    res.json({ coaching_response: responseText, timestamp: new Date() });

  } catch (e) {
    console.error('Claude API error:', e);
    res.status(503).json({ error: 'Coaching temporarily unavailable. Please try again in a few moments.' });
  }
});

// ==========================================================
//  PLAN GENERATION ENDPOINT
// ==========================================================

app.post('/api/plan/generate', requireAuth, async (req, res) => {
  const userId = req.user.userId;
  const { messages, system } = req.body;

  if (!messages || !Array.isArray(messages) || messages.length === 0) {
    return res.status(400).json({ error: 'messages array is required' });
  }

  // Rate limit: shared with coaching queries
  try {
    const { rows } = await pool.query(
      `SELECT COUNT(*) AS cnt FROM coaching_queries
        WHERE user_id = $1 AND created_at::date = CURRENT_DATE`,
      [userId]
    );
    if (parseInt(rows[0].cnt, 10) >= RATE_LIMIT_PER_DAY) {
      return res.status(429).json({
        error: `Daily query limit reached (${RATE_LIMIT_PER_DAY}/day). Try again tomorrow.`
      });
    }
  } catch (e) {
    console.error('Rate limit check failed:', e);
  }

  try {
    const createParams = {
      model:      COACHING_MODEL,
      max_tokens: 4000,
      messages
    };
    if (system) createParams.system = system;

    const message = await anthropic.messages.create(createParams);
    const responseText = message.content[0].text;

    // Log for rate limiting and analytics
    const queryPreview = messages[messages.length - 1]?.content?.slice?.(0, 2000) || '';
    await pool.query(
      `INSERT INTO coaching_queries (user_id, query, response) VALUES ($1, $2, $3)`,
      [userId, queryPreview, responseText.slice(0, 8000)]
    ).catch(err => console.error('Failed to log plan query:', err));

    console.log(`Plan generation for user ${userId} — ${message.usage?.input_tokens || '?'} in / ${message.usage?.output_tokens || '?'} out tokens`);
    res.json({ response: responseText });

  } catch (e) {
    console.error('Claude API error (plan generate):', e);
    res.status(503).json({ error: 'Plan generation temporarily unavailable. Please try again in a few moments.' });
  }
});

// ==========================================================
//  STRAVA OAUTH
// ==========================================================

app.get('/strava/auth', (req, res) => {
  const clientId  = process.env.STRAVA_CLIENT_ID;
  const backendUrl = process.env.BACKEND_URL;
  if (!clientId || !backendUrl) {
    return res.status(500).json({ error: 'Strava integration not configured on server' });
  }
  const userToken = req.query.token;
  if (!userToken) return res.status(401).json({ error: 'Authentication required' });
  try { jwt.verify(userToken, JWT_SECRET); } catch (e) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
  const redirectUri = `${backendUrl}/strava/callback`;
  const scope = 'read,activity:read_all,profile:read_all';
  const stravaAuthUrl = `https://www.strava.com/oauth/authorize`
    + `?client_id=${clientId}`
    + `&redirect_uri=${encodeURIComponent(redirectUri)}`
    + `&response_type=code`
    + `&scope=${scope}`
    + `&approval_prompt=auto`
    + `&state=${encodeURIComponent(userToken)}`;
  res.redirect(stravaAuthUrl);
});

app.get('/strava/callback', async (req, res) => {
  const { code, state } = req.query;
  if (!code) return res.status(400).send('Missing authorization code from Strava');
  if (!state) return res.status(400).send('Missing state — please try connecting Strava again from the app.');
  let userId;
  try {
    const decoded = jwt.verify(state, JWT_SECRET);
    userId = decoded.userId;
  } catch (e) {
    return res.status(400).send('Session expired — please try connecting Strava again from the app.');
  }
  try {
    const response = await fetch('https://www.strava.com/oauth/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        client_id: process.env.STRAVA_CLIENT_ID,
        client_secret: process.env.STRAVA_CLIENT_SECRET,
        code, grant_type: 'authorization_code'
      })
    });
    const data = await response.json();
    if (!response.ok) return res.status(400).send('Failed to connect to Strava.');

    const athleteId = data.athlete.id;
    await pool.query(
      `UPDATE users SET strava_athlete_id=$1, strava_access_token=$2, strava_refresh_token=$3, strava_expires_at=$4 WHERE id=$5`,
      [athleteId, data.access_token, data.refresh_token, data.expires_at, userId]
    );
    tokenStore[athleteId] = { access_token: data.access_token, refresh_token: data.refresh_token, expires_at: data.expires_at, athlete: data.athlete };
    console.log(`Strava connected for ${data.athlete.firstname} ${data.athlete.lastname} (${athleteId}), user ${userId}`);
    const frontendUrl = process.env.FRONTEND_URL || 'https://velocoach-ai.netlify.app';
    res.redirect(`${frontendUrl}?strava_connected=true`);
  } catch (error) {
    console.error('OAuth callback error:', error);
    res.status(500).send('Something went wrong connecting to Strava.');
  }
});

async function refreshStravaToken(athleteId) {
  const stored = tokenStore[athleteId];
  if (!stored) return null;
  const now = Math.floor(Date.now() / 1000);
  if (stored.expires_at > now + 300) return stored.access_token;

  const response = await fetch('https://www.strava.com/oauth/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      client_id: process.env.STRAVA_CLIENT_ID,
      client_secret: process.env.STRAVA_CLIENT_SECRET,
      grant_type: 'refresh_token',
      refresh_token: stored.refresh_token
    })
  });
  const data = await response.json();
  if (!response.ok) return null;
  stored.access_token = data.access_token;
  stored.refresh_token = data.refresh_token;
  stored.expires_at = data.expires_at;
  return data.access_token;
}

// Strava data endpoints
app.get('/strava/activities', async (req, res) => {
  const { athlete_id, per_page = 30, page = 1 } = req.query;
  if (!athlete_id || !tokenStore[athlete_id]) return res.status(401).json({ error: 'Not connected' });
  try {
    const accessToken = await refreshStravaToken(athlete_id);
    if (!accessToken) return res.status(401).json({ error: 'Token expired. Please reconnect.' });
    const response = await fetch(`https://www.strava.com/api/v3/athlete/activities?per_page=${per_page}&page=${page}`, {
      headers: { 'Authorization': `Bearer ${accessToken}` }
    });
    res.json(await response.json());
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch activities from Strava' });
  }
});

app.get('/strava/athlete', async (req, res) => {
  const { athlete_id } = req.query;
  if (!athlete_id || !tokenStore[athlete_id]) return res.status(401).json({ error: 'Not connected' });
  res.json(tokenStore[athlete_id].athlete);
});

app.get('/strava/status', (req, res) => {
  const { athlete_id } = req.query;
  const connected = !!(athlete_id && tokenStore[athlete_id]);
  res.json({ connected, athlete_id: connected ? athlete_id : null });
});

// ==========================================================
//  TRAININGPEAKS API PROXY
// ==========================================================

app.post('/tp/connect', (req, res) => {
  const { athlete_id, token } = req.body;
  if (!athlete_id || !token) return res.status(400).json({ error: 'athlete_id and token required' });
  tpTokenStore[athlete_id] = { token, connected_at: Date.now() };
  console.log(`TrainingPeaks connected for athlete ${athlete_id}`);
  res.json({ connected: true, athlete_id });
});

app.get('/tp/status', (req, res) => {
  const { athlete_id } = req.query;
  const connected = !!(athlete_id && tpTokenStore[athlete_id]);
  res.json({ connected, athlete_id: connected ? athlete_id : null });
});

app.post('/tp/disconnect', (req, res) => {
  const { athlete_id } = req.body;
  if (athlete_id && tpTokenStore[athlete_id]) delete tpTokenStore[athlete_id];
  res.json({ connected: false });
});

function getTPToken(athlete_id, res) {
  if (!athlete_id || !tpTokenStore[athlete_id]) {
    res.status(401).json({ error: 'Not connected' });
    return null;
  }
  return tpTokenStore[athlete_id].token;
}

app.get('/tp/workouts', async (req, res) => {
  const { athlete_id, start_date, end_date } = req.query;
  const token = getTPToken(athlete_id, res);
  if (!token) return;
  try {
    const url = `https://tpapi.trainingpeaks.com/fitness/v6/athletes/${athlete_id}/workouts/${start_date}/${end_date}`;
    const response = await fetch(url, { headers: { 'Authorization': `Bearer ${token}`, 'Accept': 'application/json' } });
    if (!response.ok) return res.status(response.status).json({ error: 'Failed to fetch workouts' });
    res.json(await response.json());
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch workouts from TrainingPeaks' });
  }
});

app.post('/tp/workouts', async (req, res) => {
  const { athlete_id } = req.query;
  const token = getTPToken(athlete_id, res);
  if (!token) return;
  try {
    const url = `https://tpapi.trainingpeaks.com/fitness/v1/athletes/${athlete_id}/workouts`;
    const response = await fetch(url, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json', 'Accept': 'application/json' },
      body: JSON.stringify(req.body)
    });
    if (!response.ok) return res.status(response.status).json({ error: 'Failed to create workout' });
    res.json(await response.json());
  } catch (error) {
    res.status(500).json({ error: 'Failed to create workout on TrainingPeaks' });
  }
});

app.put('/tp/workouts/:workoutId', async (req, res) => {
  const { athlete_id } = req.query;
  const { workoutId } = req.params;
  const token = getTPToken(athlete_id, res);
  if (!token) return;
  try {
    const url = `https://tpapi.trainingpeaks.com/fitness/v3/athletes/${athlete_id}/workouts/${workoutId}`;
    const response = await fetch(url, {
      method: 'PUT',
      headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json', 'Accept': 'application/json' },
      body: JSON.stringify(req.body)
    });
    if (!response.ok) return res.status(response.status).json({ error: 'Failed to update workout' });
    res.json(await response.json());
  } catch (error) {
    res.status(500).json({ error: 'Failed to update workout on TrainingPeaks' });
  }
});

app.delete('/tp/workouts/:workoutId', async (req, res) => {
  const { athlete_id } = req.query;
  const { workoutId } = req.params;
  const token = getTPToken(athlete_id, res);
  if (!token) return;
  try {
    const url = `https://tpapi.trainingpeaks.com/fitness/v3/athletes/${athlete_id}/workouts/${workoutId}`;
    const response = await fetch(url, { method: 'DELETE', headers: { 'Authorization': `Bearer ${token}` } });
    if (!response.ok) return res.status(response.status).json({ error: 'Failed to delete workout' });
    res.json({ deleted: true, workoutId });
  } catch (error) {
    res.status(500).json({ error: 'Failed to delete workout on TrainingPeaks' });
  }
});

app.get('/tp/athlete', async (req, res) => {
  const { athlete_id } = req.query;
  const token = getTPToken(athlete_id, res);
  if (!token) return;
  try {
    const response = await fetch('https://tpapi.trainingpeaks.com/users/v3/user', {
      headers: { 'Authorization': `Bearer ${token}`, 'Accept': 'application/json' }
    });
    if (!response.ok) return res.status(response.status).json({ error: 'Failed to fetch TP profile' });
    res.json(await response.json());
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch TrainingPeaks profile' });
  }
});

// ---------- Start ----------
initSchema()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`VeloCoach Backend running on port ${PORT}`);
      console.log(`Auth: /auth/signup, /auth/login (PostgreSQL)`);
      console.log(`Strava: ${process.env.BACKEND_URL}/strava/auth`);
      console.log(`TrainingPeaks: enabled`);
    });
  })
  .catch(err => {
    console.error('Failed to initialise DB schema:', err);
    process.exit(1);
  });
