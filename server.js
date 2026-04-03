/**
 * server.js — Challonge OAuth Token Proxy
 *
 * This is a minimal Node.js + Express backend. Its only job is to
 * handle the two requests that require your client_secret:
 *   1. Exchanging an authorization code for an access + refresh token
 *   2. Using a refresh token to get a new access token
 *
 * Everything else (listing tournaments, reporting scores, etc.) is
 * called directly from the browser using challonge-api.js.
 *
 * ── Setup ────────────────────────────────────────────────────────────────────
 *
 *   npm init -y
 *   npm install express dotenv cors
 *
 * Create a .env file (never commit this):
 *
 *   CHALLONGE_CLIENT_ID=your_client_id_here
 *   CHALLONGE_CLIENT_SECRET=your_client_secret_here
 *   CHALLONGE_REDIRECT_URI=https://yoursite.com/callback.html
 *   ALLOWED_ORIGIN=https://yoursite.com
 *   PORT=3000
 *
 * Run:
 *   node server.js
 *
 * ── Deployment notes ─────────────────────────────────────────────────────────
 *
 *   This file works as-is on any Node host: Railway, Render, Fly.io,
 *   a VPS, etc. If you prefer serverless, see the commented examples
 *   at the bottom of this file for Vercel and Cloudflare Workers.
 */

import 'dotenv/config';
import express  from 'express';
import cors     from 'cors';

const app = express();

// ── Config ────────────────────────────────────────────────────────────────────

const {
  CHALLONGE_CLIENT_ID:     CLIENT_ID,
  CHALLONGE_CLIENT_SECRET: CLIENT_SECRET,
  CHALLONGE_REDIRECT_URI:  REDIRECT_URI,
  ALLOWED_ORIGIN,
  PORT = 3000,
} = process.env;

if (!CLIENT_ID || !CLIENT_SECRET || !REDIRECT_URI) {
  console.error('Missing required environment variables. Check your .env file.');
  process.exit(1);
}

const CHALLONGE_TOKEN_URL = 'https://api.challonge.com/oauth/token';

// ── Middleware ────────────────────────────────────────────────────────────────

app.use(express.json());
app.use(express.static('.'));

// Only allow requests from your own frontend — not from arbitrary origins
app.use(cors({
  origin: ALLOWED_ORIGIN ?? '*',    // set ALLOWED_ORIGIN in production
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
}));

// ── Helper ────────────────────────────────────────────────────────────────────

/**
 * Forwards a token request to Challonge, injecting the client_secret.
 * Returns the parsed JSON response or throws with an error message.
 */
async function requestChallongeToken(body) {
  const response = await fetch(CHALLONGE_TOKEN_URL, {
    method:  'POST',
    headers: { 'Content-Type': 'application/json' },
    body:    JSON.stringify(body),
  });

  const data = await response.json();

  if (!response.ok) {
    const message = data?.error_description ?? data?.error ?? 'Token request failed';
    throw Object.assign(new Error(message), { status: response.status });
  }

  // Log the token response keys (not values) so we know what Challonge returns
  console.log('[token] response keys:', Object.keys(data));

  return data;
}

// ── Routes ────────────────────────────────────────────────────────────────────

/**
 * POST /api/challonge-token
 *
 * Accepts two different payloads from the browser:
 *
 * 1. Authorization code exchange:
 *    { code: "...", redirect_uri: "..." }
 *
 * 2. Token refresh:
 *    { grant_type: "refresh_token", refresh_token: "..." }
 *
 * The client_secret is added here — it never touches the browser.
 */
app.post('/api/challonge-token', async (req, res) => {
  const { code, redirect_uri, grant_type, refresh_token } = req.body;

  try {
    let challongeBody;

    if (grant_type === 'refresh_token') {
      // ── Token refresh ──────────────────────────────────────────────────────
      if (!refresh_token) {
        return res.status(400).json({ error: 'refresh_token is required' });
      }

      challongeBody = {
        grant_type:    'refresh_token',
        refresh_token,
        client_id:     CLIENT_ID,
        client_secret: CLIENT_SECRET,
      };

    } else {
      // ── Authorization code exchange ────────────────────────────────────────
      if (!code) {
        return res.status(400).json({ error: 'code is required' });
      }

      challongeBody = {
        grant_type:    'authorization_code',
        code,
        redirect_uri:  redirect_uri ?? REDIRECT_URI,
        client_id:     CLIENT_ID,
        client_secret: CLIENT_SECRET,
      };
    }

    const tokenData = await requestChallongeToken(challongeBody);
    return res.json(tokenData);

  } catch (err) {
    console.error('Token proxy error:', err.message);
    return res.status(err.status ?? 500).json({ error: err.message });
  }
});

// ── Challonge API Proxy ───────────────────────────────────────────────────────
// Routes all API requests through the server to avoid CORS issues
app.all('/api/challonge-proxy', async (req, res) => {
  // Get path from query param (GET/HEAD/DELETE) or body (_path)
  const pathFromQuery = req.query.path;
  const { _path, ...bodyData } = req.body || {};
  const path = pathFromQuery || _path;

  if (!path) {
    return res.status(400).json({ error: 'Missing path in request' });
  }

  const authHeader = req.headers.authorization;
  if (!authHeader) {
    return res.status(401).json({ error: 'Missing authorization header' });
  }

  try {
    const method = req.method;
    const fetchOptions = {
      method,
      headers: {
        'Content-Type':       'application/vnd.api+json',
        'Accept':             'application/json',
        'Authorization-Type': 'v2',
        'Authorization':      authHeader,
      },
    };

    // Only include body for methods that support it
    if (!['GET', 'HEAD', 'DELETE'].includes(method) && Object.keys(bodyData).length > 0) {
      fetchOptions.body = JSON.stringify(bodyData);
    }

    const response = await fetch(`https://api.challonge.com/v2.1${path}`, fetchOptions);
    const data = await response.json().catch(() => null);

    if (!response.ok) {
      const messages = data?.errors?.map(e => e.detail).join(', ') ?? response.statusText;
      return res.status(response.status).json({ error: messages || 'API request failed' });
    }

    return res.status(response.status).json(data);
  } catch (err) {
    console.error('API proxy error:', err.message);
    return res.status(500).json({ error: err.message });
  }
});

// ── Current-user endpoint ─────────────────────────────────────────────────────
// Tries multiple Challonge URL patterns with clean OAuth headers (no Content-Type
// or Authorization-Type, which the general proxy always sends and which confuse
// the user-info endpoint on some Challonge API versions).
app.get('/api/challonge-user', async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'Missing authorization' });

  // Try each candidate URL, first with v2 auth header, then without
  const candidates = [
    { url: 'https://api.challonge.com/v2.1/me',       v2: true  },
    { url: 'https://api.challonge.com/v2.1/me',       v2: false },
    { url: 'https://api.challonge.com/v2.1/users/me', v2: true  },
    { url: 'https://api.challonge.com/users/me.json', v2: false },
  ];

  for (const { url, v2 } of candidates) {
    try {
      const headers = {
        'Authorization': authHeader,
        'Accept':        'application/json',
        ...(v2 ? { 'Authorization-Type': 'v2' } : {}),
      };
      const r = await fetch(url, { headers });
      const data = await r.json().catch(() => null);
      console.log(`[challonge-user] ${url} (v2=${v2}) → ${r.status}`, JSON.stringify(data)?.slice(0, 200));
      if (r.ok && data) return res.json(data);
    } catch (e) {
      console.log(`[challonge-user] ${url} → error:`, e.message);
    }
  }

  return res.status(404).json({ error: 'User info not available from any endpoint' });
});

// Health check — useful for uptime monitors and deployment verification
app.get('/health', (_req, res) => res.json({ ok: true }));

// ── Start ─────────────────────────────────────────────────────────────────────

app.listen(PORT, () => {
  console.log(`Challonge proxy listening on http://localhost:${PORT}`);
});


/* ══════════════════════════════════════════════════════════════════════════════
   SERVERLESS ALTERNATIVES
   If you'd rather not run a persistent server, here are drop-in equivalents.
   ══════════════════════════════════════════════════════════════════════════════

── Vercel Serverless Function ─────────────────────────────────────────────────
Save as: /api/challonge-token.js  (Vercel auto-routes /api/* files)
Set env vars in your Vercel project dashboard.

export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).end();

  const { code, redirect_uri, grant_type, refresh_token } = req.body;

  const body = grant_type === 'refresh_token'
    ? { grant_type: 'refresh_token', refresh_token,
        client_id: process.env.CHALLONGE_CLIENT_ID,
        client_secret: process.env.CHALLONGE_CLIENT_SECRET }
    : { grant_type: 'authorization_code', code,
        redirect_uri: redirect_uri ?? process.env.CHALLONGE_REDIRECT_URI,
        client_id: process.env.CHALLONGE_CLIENT_ID,
        client_secret: process.env.CHALLONGE_CLIENT_SECRET };

  const upstream = await fetch('https://api.challonge.com/oauth/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });

  const data = await upstream.json();
  res.status(upstream.status).json(data);
}

── Cloudflare Worker ──────────────────────────────────────────────────────────
Set secrets via: wrangler secret put CHALLONGE_CLIENT_SECRET  etc.

export default {
  async fetch(request, env) {
    if (request.method !== 'POST') return new Response('Method Not Allowed', { status: 405 });

    const { code, redirect_uri, grant_type, refresh_token } = await request.json();

    const body = grant_type === 'refresh_token'
      ? { grant_type: 'refresh_token', refresh_token,
          client_id: env.CHALLONGE_CLIENT_ID,
          client_secret: env.CHALLONGE_CLIENT_SECRET }
      : { grant_type: 'authorization_code', code,
          redirect_uri: redirect_uri ?? env.CHALLONGE_REDIRECT_URI,
          client_id: env.CHALLONGE_CLIENT_ID,
          client_secret: env.CHALLONGE_CLIENT_SECRET };

    const upstream = await fetch('https://api.challonge.com/oauth/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });

    return new Response(await upstream.text(), {
      status: upstream.status,
      headers: { 'Content-Type': 'application/json' },
    });
  }
};

*/
