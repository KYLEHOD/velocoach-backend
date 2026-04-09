// ============================================================
// VeloCoach AI — Backend Server
// Handles Strava OAuth and proxies activity data to the frontend
// ============================================================

require('dotenv').config();
const express = require('express');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;

// ---------- CORS ----------
// Allow your VeloCoach frontend to talk to this server
app.use(cors({
  origin: process.env.FRONTEND_URL || 'https://velocoach-ai.netlify.app',
  credentials: true
}));

app.use(express.json());

// ---------- In-memory token store ----------
// For now we store tokens in memory. This means they reset if the
// server restarts, but it keeps things simple. We can add a database later.
const tokenStore = {};

// ---------- Health check ----------
app.get('/', (req, res) => {
  res.json({
    status: 'ok',
    service: 'VeloCoach Backend',
    endpoints: ['/strava/auth', '/strava/callback', '/strava/activities']
  });
});

// ==========================================================
//  STRAVA OAUTH
// ==========================================================

// Step 1: Redirect user to Strava's authorization page
// The frontend calls this when the user clicks "Connect Strava"
app.get('/strava/auth', (req, res) => {
  const clientId = process.env.STRAVA_CLIENT_ID;
  const redirectUri = `${process.env.BACKEND_URL}/strava/callback`;
  const scope = 'read,activity:read_all,profile:read_all';

  const stravaAuthUrl =
    `https://www.strava.com/oauth/authorize` +
    `?client_id=${clientId}` +
    `&redirect_uri=${encodeURIComponent(redirectUri)}` +
    `&response_type=code` +
    `&scope=${scope}` +
    `&approval_prompt=auto`;

  res.redirect(stravaAuthUrl);
});

// Step 2: Strava sends the user back here with a code
// We exchange that code for an access token
app.get('/strava/callback', async (req, res) => {
  const { code } = req.query;

  if (!code) {
    return res.status(400).send('Missing authorization code from Strava');
  }

  try {
    // Exchange the code for tokens
    const response = await fetch('https://www.strava.com/oauth/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        client_id: process.env.STRAVA_CLIENT_ID,
        client_secret: process.env.STRAVA_CLIENT_SECRET,
        code: code,
        grant_type: 'authorization_code'
      })
    });

    const data = await response.json();

    if (!response.ok) {
      console.error('Strava token exchange failed:', data);
      return res.status(400).send('Failed to connect to Strava. Please try again.');
    }

    // Store the tokens keyed by the athlete's Strava ID
    const athleteId = data.athlete.id;
    tokenStore[athleteId] = {
      access_token: data.access_token,
      refresh_token: data.refresh_token,
      expires_at: data.expires_at,
      athlete: data.athlete
    };

    console.log(`Strava connected for athlete: ${data.athlete.firstname} ${data.athlete.lastname} (ID: ${athleteId})`);

    // Redirect back to VeloCoach with the athlete ID so the frontend knows who connected
    const frontendUrl = process.env.FRONTEND_URL || 'https://velocoach-ai.netlify.app';
    res.redirect(`${frontendUrl}?strava_athlete_id=${athleteId}&strava_connected=true`);

  } catch (error) {
    console.error('OAuth callback error:', error);
    res.status(500).send('Something went wrong connecting to Strava.');
  }
});

// Step 3: Refresh the access token if it has expired
async function refreshStravaToken(athleteId) {
  const stored = tokenStore[athleteId];
  if (!stored) return null;

  // Check if token is still valid (with 5 min buffer)
  const now = Math.floor(Date.now() / 1000);
  if (stored.expires_at > now + 300) {
    return stored.access_token; // Still valid
  }

  // Token expired — refresh it
  console.log(`Refreshing Strava token for athlete ${athleteId}...`);
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
  if (!response.ok) {
    console.error('Token refresh failed:', data);
    return null;
  }

  // Update stored tokens
  stored.access_token = data.access_token;
  stored.refresh_token = data.refresh_token;
  stored.expires_at = data.expires_at;

  return data.access_token;
}

// ==========================================================
//  STRAVA DATA ENDPOINTS
// ==========================================================

// Get recent activities for a connected athlete
app.get('/strava/activities', async (req, res) => {
  const { athlete_id, per_page = 30, page = 1 } = req.query;

  if (!athlete_id || !tokenStore[athlete_id]) {
    return res.status(401).json({
      error: 'Not connected',
      message: 'Strava is not connected for this athlete. Please connect first via /strava/auth'
    });
  }

  try {
    const accessToken = await refreshStravaToken(athlete_id);
    if (!accessToken) {
      return res.status(401).json({ error: 'Token expired. Please reconnect Strava.' });
    }

    const response = await fetch(
      `https://www.strava.com/api/v3/athlete/activities?per_page=${per_page}&page=${page}`,
      { headers: { 'Authorization': `Bearer ${accessToken}` } }
    );

    const activities = await response.json();
    res.json(activities);

  } catch (error) {
    console.error('Failed to fetch activities:', error);
    res.status(500).json({ error: 'Failed to fetch activities from Strava' });
  }
});

// Get the connected athlete's profile
app.get('/strava/athlete', async (req, res) => {
  const { athlete_id } = req.query;

  if (!athlete_id || !tokenStore[athlete_id]) {
    return res.status(401).json({ error: 'Not connected' });
  }

  // Return the stored profile (no API call needed)
  res.json(tokenStore[athlete_id].athlete);
});

// Check connection status
app.get('/strava/status', (req, res) => {
  const { athlete_id } = req.query;
  const connected = !!(athlete_id && tokenStore[athlete_id]);
  res.json({ connected, athlete_id: connected ? athlete_id : null });
});

// ---------- Start the server ----------
app.listen(PORT, () => {
  console.log(`VeloCoach Backend running on port ${PORT}`);
  console.log(`Frontend URL: ${process.env.FRONTEND_URL}`);
  console.log(`Strava auth: ${process.env.BACKEND_URL}/strava/auth`);
});
