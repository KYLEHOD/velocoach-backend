// ============================================================
// VeloCoach AI â Backend Server
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
    endpoints: ['/strava/auth', '/strava/callback', '/strava/activities', '/tp/connect', '/tp/workouts', '/tp/athlete']
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

  // Token expired â refresh it
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

// ==========================================================
//  TRAININGPEAKS API PROXY
//  The frontend stores the user's TP bearer token (from their
//  logged-in session) and athlete ID. We proxy all TP API calls
//  through here to avoid CORS blocks.
// ==========================================================

// In-memory TP token store (keyed by athlete ID)
const tpTokenStore = {};

// Save TP credentials (called from frontend after user provides token)
app.post('/tp/connect', (req, res) => {
  const { athlete_id, token } = req.body;
  if (!athlete_id || !token) {
    return res.status(400).json({ error: 'athlete_id and token are required' });
  }
  tpTokenStore[athlete_id] = { token, connected_at: Date.now() };
  console.log(`TrainingPeaks connected for athlete ${athlete_id}`);
  res.json({ connected: true, athlete_id });
});

// Check TP connection status
app.get('/tp/status', (req, res) => {
  const { athlete_id } = req.query;
  const connected = !!(athlete_id && tpTokenStore[athlete_id]);
  res.json({ connected, athlete_id: connected ? athlete_id : null });
});

// Disconnect TP
app.post('/tp/disconnect', (req, res) => {
  const { athlete_id } = req.body;
  if (athlete_id && tpTokenStore[athlete_id]) {
    delete tpTokenStore[athlete_id];
  }
  res.json({ connected: false });
});

// Helper: get TP token or return 401
function getTPToken(athlete_id, res) {
  if (!athlete_id || !tpTokenStore[athlete_id]) {
    res.status(401).json({
      error: 'Not connected',
      message: 'TrainingPeaks is not connected. Please connect first.'
    });
    return null;
  }
  return tpTokenStore[athlete_id].token;
}

// GET workouts for a date range
app.get('/tp/workouts', async (req, res) => {
  const { athlete_id, start_date, end_date } = req.query;
  const token = getTPToken(athlete_id, res);
  if (!token) return;

  try {
    const url = `https://tpapi.trainingpeaks.com/fitness/v6/athletes/${athlete_id}/workouts/${start_date}/${end_date}`;
    const response = await fetch(url, {
      headers: {
        'Authorization': `Bearer ${token}`,
        'Accept': 'application/json'
      }
    });

    if (!response.ok) {
      const text = await response.text();
      console.error(`TP workouts fetch failed (${response.status}):`, text);
      return res.status(response.status).json({ error: 'Failed to fetch workouts', detail: text });
    }

    const workouts = await response.json();
    res.json(workouts);
  } catch (error) {
    console.error('TP workouts error:', error);
    res.status(500).json({ error: 'Failed to fetch workouts from TrainingPeaks' });
  }
});

// POST create a new workout
app.post('/tp/workouts', async (req, res) => {
  const { athlete_id } = req.query;
  const token = getTPToken(athlete_id, res);
  if (!token) return;

  try {
    const url = `https://tpapi.trainingpeaks.com/fitness/v1/athletes/${athlete_id}/workouts`;
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json',
        'Accept': 'application/json'
      },
      body: JSON.stringify(req.body)
    });

    if (!response.ok) {
      const text = await response.text();
      console.error(`TP create workout failed (${response.status}):`, text);
      return res.status(response.status).json({ error: 'Failed to create workout', detail: text });
    }

    const workout = await response.json();
    console.log(`TP workout created for athlete ${athlete_id}: ${workout.workoutId || workout.id || 'ok'}`);
    res.json(workout);
  } catch (error) {
    console.error('TP create workout error:', error);
    res.status(500).json({ error: 'Failed to create workout on TrainingPeaks' });
  }
});

// PUT update an existing workout
app.put('/tp/workouts/:workoutId', async (req, res) => {
  const { athlete_id } = req.query;
  const { workoutId } = req.params;
  const token = getTPToken(athlete_id, res);
  if (!token) return;

  try {
    const url = `https://tpapi.trainingpeaks.com/fitness/v3/athletes/${athlete_id}/workouts/${workoutId}`;
    const response = await fetch(url, {
      method: 'PUT',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json',
        'Accept': 'application/json'
      },
      body: JSON.stringify(req.body)
    });

    if (!response.ok) {
      const text = await response.text();
      console.error(`TP update workout failed (${response.status}):`, text);
      return res.status(response.status).json({ error: 'Failed to update workout', detail: text });
    }

    const workout = await response.json();
    res.json(workout);
  } catch (error) {
    console.error('TP update workout error:', error);
    res.status(500).json({ error: 'Failed to update workout on TrainingPeaks' });
  }
});

// DELETE a workout
app.delete('/tp/workouts/:workoutId', async (req, res) => {
  const { athlete_id } = req.query;
  const { workoutId } = req.params;
  const token = getTPToken(athlete_id, res);
  if (!token) return;

  try {
    const url = `https://tpapi.trainingpeaks.com/fitness/v3/athletes/${athlete_id}/workouts/${workoutId}`;
    const response = await fetch(url, {
      method: 'DELETE',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Accept': 'application/json'
      }
    });

    if (!response.ok) {
      const text = await response.text();
      console.error(`TP delete workout failed (${response.status}):`, text);
      return res.status(response.status).json({ error: 'Failed to delete workout', detail: text });
    }

    res.json({ deleted: true, workoutId });
  } catch (error) {
    console.error('TP delete workout error:', error);
    res.status(500).json({ error: 'Failed to delete workout on TrainingPeaks' });
  }
});

// GET athlete profile/info from TP
app.get('/tp/athlete', async (req, res) => {
  const { athlete_id } = req.query;
  const token = getTPToken(athlete_id, res);
  if (!token) return;

  try {
    const response = await fetch(`https://tpapi.trainingpeaks.com/users/v3/user`, {
      headers: {
        'Authorization': `Bearer ${token}`,
        'Accept': 'application/json'
      }
    });

    if (!response.ok) {
      const text = await response.text();
      return res.status(response.status).json({ error: 'Failed to fetch TP profile', detail: text });
    }

    const profile = await response.json();
    res.json(profile);
  } catch (error) {
    console.error('TP athlete error:', error);
    res.status(500).json({ error: 'Failed to fetch TrainingPeaks profile' });
  }
});

// ---------- Start the server ----------
app.listen(PORT, () => {
  console.log(`VeloCoach Backend running on port ${PORT}`);
  console.log(`Frontend URL: ${process.env.FRONTEND_URL}`);
  console.log(`Strava auth: ${process.env.BACKEND_URL}/strava/auth`);
  console.log(`TrainingPeaks proxy: enabled`);
});
