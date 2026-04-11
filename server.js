// ============================================================
// VeloCoach AI â Backend Server
// Handles Auth, Strava OAuth, and proxies activity data
// ============================================================

require('dotenv').config();
const express = require('express');
const cors    = require('cors');
const crypto  = require('crypto');
const app     = express();
const PORT    = process.env.PORT || 3000;

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

// ---------- In-memory stores ----------
const tokenStore   = {};   // Strava tokens
const tpTokenStore = {};   // TrainingPeaks tokens
const userStore    = {};   // Auth users: { email: { id, email, name, passwordHash, salt, profile, createdAt } }
const sessionStore = {};   // Auth sessions: { token: { userId, email, expiresAt } }

// ---------- Auth helpers ----------
const JWT_SECRET = process.env.JWT_SECRET || 'velocoach-secret-' + crypto.randomBytes(16).toString('hex');

function hashPassword(password, salt) {
  if (!salt) salt = crypto.randomBytes(32).toString('hex');
  const hash = crypto.pbkdf2Sync(password, salt, 10000, 64, 'sha512').toString('hex');
  return { hash, salt };
}

function generateToken(userId, email) {
  const token = crypto.randomBytes(48).toString('hex');
  const expiresAt = Date.now() + 30 * 24 * 60 * 60 * 1000; // 30 days
  sessionStore[token] = { userId, email, expiresAt };
  return token;
}

function verifyToken(token) {
  const session = sessionStore[token];
  if (!session) return null;
  if (Date.now() > session.expiresAt) { delete sessionStore[token]; return null; }
  return session;
}

// Auth middleware
function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  const token = authHeader.slice(7);
  const session = verifyToken(token);
  if (!session) return res.status(401).json({ error: 'Invalid or expired token' });
  req.userId = session.userId;
  req.userEmail = session.email;
  next();
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
app.post('/auth/signup', (req, res) => {
  const { email, password, name } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }
  if (password.length < 6) {
    return res.status(400).json({ error: 'Password must be at least 6 characters' });
  }

  const normalizedEmail = email.toLowerCase().trim();
  if (userStore[normalizedEmail]) {
    return res.status(409).json({ error: 'An account with this email already exists. Try signing in.' });
  }

  const userId = 'u_' + crypto.randomBytes(12).toString('hex');
  const { hash, salt } = hashPassword(password);

  userStore[normalizedEmail] = {
    id: userId,
    email: normalizedEmail,
    name: name || 'Athlete',
    passwordHash: hash,
    salt,
    profile: { name: name || 'Athlete' },
    createdAt: Date.now()
  };

  const token = generateToken(userId, normalizedEmail);
  console.log(`New user signed up: ${normalizedEmail} (${userId})`);

  res.json({ token, userId, email: normalizedEmail, name: name || 'Athlete' });
});

// Login
app.post('/auth/login', (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }

  const normalizedEmail = email.toLowerCase().trim();
  const user = userStore[normalizedEmail];

  if (!user) {
    return res.status(401).json({ error: 'No account found with this email. Try creating one.' });
  }

  const { hash } = hashPassword(password, user.salt);
  if (hash !== user.passwordHash) {
    return res.status(401).json({ error: 'Incorrect password. Please try again.' });
  }

  const token = generateToken(user.id, normalizedEmail);
  console.log(`User logged in: ${normalizedEmail}`);

  res.json({
    token,
    userId: user.id,
    email: normalizedEmail,
    name: user.name,
    profile: user.profile
  });
});

// Get/update profile (authenticated)
app.get('/auth/profile', requireAuth, (req, res) => {
  const user = Object.values(userStore).find(u => u.id === req.userId);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({ userId: user.id, email: user.email, name: user.name, profile: user.profile });
});

app.put('/auth/profile', requireAuth, (req, res) => {
  const user = Object.values(userStore).find(u => u.id === req.userId);
  if (!user) return res.status(404).json({ error: 'User not found' });
  if (req.body.name) user.name = req.body.name;
  if (req.body.profile) Object.assign(user.profile, req.body.profile);
  res.json({ userId: user.id, email: user.email, name: user.name, profile: user.profile });
});

// ==========================================================
//  STRAVA OAUTH
// ==========================================================

app.get('/strava/auth', (req, res) => {
  const clientId = process.env.STRAVA_CLIENT_ID;
  const redirectUri = `${process.env.BACKEND_URL}/strava/callback`;
  const scope = 'read,activity:read_all,profile:read_all';
  const stravaAuthUrl = `https://www.strava.com/oauth/authorize`
    + `?client_id=${clientId}`
    + `&redirect_uri=${encodeURIComponent(redirectUri)}`
    + `&response_type=code`
    + `&scope=${scope}`
    + `&approval_prompt=auto`;
  res.redirect(stravaAuthUrl);
});

app.get('/strava/callback', async (req, res) => {
  const { code } = req.query;
  if (!code) return res.status(400).send('Missing authorization code from Strava');

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
    tokenStore[athleteId] = {
      access_token: data.access_token,
      refresh_token: data.refresh_token,
      expires_at: data.expires_at,
      athlete: data.athlete
    };
    console.log(`Strava connected for ${data.athlete.firstname} ${data.athlete.lastname} (${athleteId})`);
    const frontendUrl = process.env.FRONTEND_URL || 'https://velocoach-ai.netlify.app';
    res.redirect(`${frontendUrl}?strava_athlete_id=${athleteId}&strava_connected=true`);
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
app.listen(PORT, () => {
  console.log(`VeloCoach Backend running on port ${PORT}`);
  console.log(`Frontend: ${process.env.FRONTEND_URL}`);
  console.log(`Auth: /auth/signup, /auth/login`);
  console.log(`Strava: ${process.env.BACKEND_URL}/strava/auth`);
  console.log(`TrainingPeaks: enabled`);
});
