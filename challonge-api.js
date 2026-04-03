/**
 * challonge-api.js
 * Challonge API v2.1 — Vanilla JS integration module
 *
 * Exports: ChallongeAuth, Tournaments, Participants, Matches, User
 *
 * ⚠️  The token exchange / refresh steps require your client_secret
 *     and MUST run server-side. Point tokenProxyUrl at your server.js
 *     (or Vercel / Cloudflare Worker equivalent). Everything else in
 *     this file is safe to call directly from the browser.
 */

// ─────────────────────────────────────────────────────────────────────────────
// CONFIG — fill these in
// ─────────────────────────────────────────────────────────────────────────────

const CHALLONGE_CONFIG = {
  clientId:      '0b7d9e1319fd5ab0ed67a54ba1b7490156ac3d33e5419fbc8bbb4ffc7d804802',
  redirectUri:   'http://localhost:3000/callback.html',
  tokenProxyUrl: 'http://localhost:3000/api/challonge-token',
  userUrl:       'http://localhost:3000/api/challonge-user',
};

const API_BASE = 'https://api.challonge.com/v2.1';

const OAUTH_SCOPES = [
  'me',
  'tournaments:read',
  'tournaments:write',
  'matches:read',
  'matches:write',
  'participants:read',
  'participants:write',
].join(' ');


// ─────────────────────────────────────────────────────────────────────────────
// TOKEN STORAGE
// ─────────────────────────────────────────────────────────────────────────────

const TokenStore = {
  save(tokenResponse) {
    sessionStorage.setItem('challonge_access_token',  tokenResponse.access_token);
    sessionStorage.setItem('challonge_refresh_token', tokenResponse.refresh_token);
    const expiresAt = Date.now() + tokenResponse.expires_in * 1000;
    sessionStorage.setItem('challonge_expires_at', String(expiresAt));
    // Some OAuth providers return the username in the token response — save it if present
    const username = tokenResponse.username
      || tokenResponse.preferred_username
      || tokenResponse.user?.username
      || tokenResponse.data?.attributes?.username;
    if (username) sessionStorage.setItem('challonge_username', String(username));
  },
  getAccessToken()  { return sessionStorage.getItem('challonge_access_token');  },
  getRefreshToken() { return sessionStorage.getItem('challonge_refresh_token'); },
  getExpiresAt()    { return Number(sessionStorage.getItem('challonge_expires_at')); },
  getUsername()     { return sessionStorage.getItem('challonge_username'); },
  isExpired() {
    const expiresAt = TokenStore.getExpiresAt();
    return !expiresAt || Date.now() >= expiresAt - 60_000;
  },
  clear() {
    sessionStorage.removeItem('challonge_access_token');
    sessionStorage.removeItem('challonge_refresh_token');
    sessionStorage.removeItem('challonge_expires_at');
    sessionStorage.removeItem('challonge_username');
  },
};


// ─────────────────────────────────────────────────────────────────────────────
// OAUTH
// ─────────────────────────────────────────────────────────────────────────────

export const ChallongeAuth = {
  login() {
    const state = crypto.randomUUID();
    sessionStorage.setItem('challonge_oauth_state', state);
    const params = new URLSearchParams({
      client_id:     CHALLONGE_CONFIG.clientId,
      redirect_uri:  CHALLONGE_CONFIG.redirectUri,
      response_type: 'code',
      scope:         OAUTH_SCOPES,
      state,
    });
    window.location.href = `https://api.challonge.com/oauth/authorize?${params}`;
  },

  async handleCallback() {
    const params     = new URLSearchParams(window.location.search);
    const code       = params.get('code');
    const state      = params.get('state');
    const savedState = sessionStorage.getItem('challonge_oauth_state');

    if (!code)                throw new Error('No authorization code in callback URL.');
    if (state !== savedState) throw new Error('OAuth state mismatch — possible CSRF attack.');

    sessionStorage.removeItem('challonge_oauth_state');

    const response = await fetch(CHALLONGE_CONFIG.tokenProxyUrl, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ code, redirect_uri: CHALLONGE_CONFIG.redirectUri }),
    });

    if (!response.ok) {
      const err = await response.json().catch(() => ({}));
      throw new Error(`Token exchange failed: ${err.error ?? response.statusText}`);
    }

    TokenStore.save(await response.json());
    return true;
  },

  async refreshToken() {
    const refreshToken = TokenStore.getRefreshToken();
    if (!refreshToken) throw new Error('No refresh token — user must log in again.');

    const response = await fetch(CHALLONGE_CONFIG.tokenProxyUrl, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ grant_type: 'refresh_token', refresh_token: refreshToken }),
    });

    if (!response.ok) throw new Error('Token refresh failed — user must log in again.');
    TokenStore.save(await response.json());
  },

  isLoggedIn() { return !!TokenStore.getAccessToken() && !TokenStore.isExpired(); },
  logout()     { TokenStore.clear(); },
};


// ─────────────────────────────────────────────────────────────────────────────
// CORE REQUEST HELPER
// ─────────────────────────────────────────────────────────────────────────────

async function apiRequest(path, options = {}) {
  if (TokenStore.isExpired()) await ChallongeAuth.refreshToken();

  const token = TokenStore.getAccessToken();
  if (!token) throw new Error('Not authenticated. Call ChallongeAuth.login() first.');

  const method = options.method || 'GET';
  
  // For GET/HEAD/DELETE, send path as query param; for others, in body
  let url = 'http://localhost:3000/api/challonge-proxy';
  const fetchOptions = {
    method,
    headers: {
      'Content-Type':       'application/json',
      'Accept':             'application/json',
      'Authorization':      `Bearer ${token}`,
    },
  };

  if (['GET', 'HEAD', 'DELETE'].includes(method)) {
    url += '?path=' + encodeURIComponent(path);
  } else {
    const requestBody = (() => {
      try {
        return options.body ? JSON.parse(options.body) : {};
      } catch {
        return {};
      }
    })();
    fetchOptions.body = JSON.stringify({ ...requestBody, _path: path });
  }

  const response = await fetch(url, fetchOptions);

  if (!response.ok) {
    const errorBody = await response.json().catch(() => ({}));
    const messages  = errorBody?.errors?.map(e => e.detail).join(', ') ?? response.statusText;
    throw new Error(`Challonge API ${response.status}: ${messages}`);
  }

  if (response.status === 204) return null;
  return response.json();
}


// ─────────────────────────────────────────────────────────────────────────────
// TOURNAMENTS
// ─────────────────────────────────────────────────────────────────────────────

export const Tournaments = {
  async list(filters = {}) {
    const query = new URLSearchParams(filters).toString();
    const data  = await apiRequest(`/tournaments${query ? `?${query}` : ''}`);
    return data.data;
  },

  async create(attrs) {
    const data = await apiRequest('/tournaments', {
      method: 'POST',
      body:   JSON.stringify({ data: { type: 'Tournament', attributes: attrs } }),
    });
    return data.data;
  },

  async get(id) {
    const data = await apiRequest(`/tournaments/${id}`);
    return data.data;
  },

  async update(id, attrs) {
    const data = await apiRequest(`/tournaments/${id}`, {
      method: 'PUT',
      body:   JSON.stringify({ data: { type: 'Tournament', id: String(id), attributes: attrs } }),
    });
    return data.data;
  },

  async delete(id) {
    return apiRequest(`/tournaments/${id}`, { method: 'DELETE' });
  },

  async changeState(id, state) {
    const data = await apiRequest(`/tournaments/${id}/change_state`, {
      method: 'POST',
      body:   JSON.stringify({ data: { type: 'TournamentState', attributes: { state } } }),
    });
    return data.data;
  },

  start(id)    { return Tournaments.changeState(id, 'start');    },
  finalize(id) { return Tournaments.changeState(id, 'finalize'); },
  reset(id)    { return Tournaments.changeState(id, 'reset');    },
};


// ─────────────────────────────────────────────────────────────────────────────
// PARTICIPANTS
// ─────────────────────────────────────────────────────────────────────────────

export const Participants = {
  /**
   * List all participants in a tournament.
   * @param {string|number} tournamentId
   */
  async list(tournamentId) {
    const data = await apiRequest(`/tournaments/${tournamentId}/participants`);
    return data.data;
  },

  /**
   * Add a single participant.
   * If email or username is provided, Challonge will invite that user.
   * @param {string|number} tournamentId
   * @param {object} attrs
   * @example
   *   Participants.create(tournamentId, {
   *     name:     'Player One',
   *     seed:     1,
   *     email:    'player@example.com',  // optional — sends a Challonge invite
   *     username: 'challonge_username',  // optional — invite by username instead
   *     misc:     'any string you want', // optional — custom metadata
   *   })
   */
  async create(tournamentId, attrs) {
    const data = await apiRequest(`/tournaments/${tournamentId}/participants`, {
      method: 'POST',
      body:   JSON.stringify({ data: { type: 'Participants', attributes: attrs } }),
    });
    return data.data;
  },

  /**
   * Get a single participant by ID.
   * @param {string|number} tournamentId
   * @param {string|number} participantId
   */
  async get(tournamentId, participantId) {
    const data = await apiRequest(`/tournaments/${tournamentId}/participants/${participantId}`);
    return data.data;
  },

  /**
   * Update a participant (name, seed, misc, etc.).
   * @param {string|number} tournamentId
   * @param {string|number} participantId
   * @param {object} attrs
   */
  async update(tournamentId, participantId, attrs) {
    const data = await apiRequest(`/tournaments/${tournamentId}/participants/${participantId}`, {
      method: 'PUT',
      body:   JSON.stringify({
        data: { type: 'Participants', id: String(participantId), attributes: attrs },
      }),
    });
    return data.data;
  },

  /**
   * Remove a single participant from a tournament.
   * @param {string|number} tournamentId
   * @param {string|number} participantId
   */
  async delete(tournamentId, participantId) {
    return apiRequest(`/tournaments/${tournamentId}/participants/${participantId}`, {
      method: 'DELETE',
    });
  },

  /**
   * Add multiple participants in one request — much faster than looping.
   * @param {string|number} tournamentId
   * @param {Array<{name: string, seed?: number, email?: string, username?: string, misc?: string}>} participants
   * @example
   *   Participants.bulkCreate(tournamentId, [
   *     { name: 'Alice', seed: 1 },
   *     { name: 'Bob',   seed: 2 },
   *     { name: 'Carol', seed: 3, email: 'carol@example.com' },
   *   ])
   */
  async bulkCreate(tournamentId, participants) {
    const data = await apiRequest(`/tournaments/${tournamentId}/participants/bulk_add`, {
      method: 'POST',
      body:   JSON.stringify({
        data: { type: 'Participants', attributes: { participants } },
      }),
    });
    return Array.isArray(data) ? data : data.data;
  },

  /**
   * Remove every participant from a tournament.
   * Useful for resetting entrants without deleting the tournament itself.
   * @param {string|number} tournamentId
   */
  async clearAll(tournamentId) {
    return apiRequest(`/tournaments/${tournamentId}/participants/clear`, {
      method: 'DELETE',
    });
  },

  /**
   * Randomize participant seeding order.
   * @param {string|number} tournamentId
   */
  async randomize(tournamentId) {
    const data = await apiRequest(`/tournaments/${tournamentId}/participants/randomize`, {
      method: 'PUT',
    });
    return data.data;
  },
};


// ─────────────────────────────────────────────────────────────────────────────
// MATCHES
// ─────────────────────────────────────────────────────────────────────────────

export const Matches = {
  async list(tournamentId, filters = {}) {
    const query = new URLSearchParams(filters).toString();
    const data  = await apiRequest(`/tournaments/${tournamentId}/matches${query ? `?${query}` : ''}`);
    return data.data;
  },

  async get(tournamentId, matchId) {
    const data = await apiRequest(`/tournaments/${tournamentId}/matches/${matchId}`);
    return data.data;
  },

  /**
   * Report a score and declare a winner.
   * @param {string|number} tournamentId
   * @param {string|number} matchId
   * @param {object} attrs
   * @example
   *   Matches.reportScore(tId, mId, {
   *     scores_csv: '3-1,2-3,3-2',  // p1score-p2score per set, comma-separated
   *     winner_id:  12345,           // participant ID of the winner
   *   })
   */
  async reportScore(tournamentId, matchId, attrs) {
    const data = await apiRequest(`/tournaments/${tournamentId}/matches/${matchId}`, {
      method: 'PUT',
      body:   JSON.stringify({
        data: { type: 'Match', id: String(matchId), attributes: attrs },
      }),
    });
    return data.data;
  },

  async changeState(tournamentId, matchId, state) {
    const data = await apiRequest(`/tournaments/${tournamentId}/matches/${matchId}/change_state`, {
      method: 'POST',
      body:   JSON.stringify({ data: { type: 'MatchState', attributes: { state } } }),
    });
    return data.data;
  },

  markUnderway(tournamentId, matchId) {
    return Matches.changeState(tournamentId, matchId, 'underway');
  },
};


// ─────────────────────────────────────────────────────────────────────────────
// USER
// ─────────────────────────────────────────────────────────────────────────────

export const User = {
  async getMe() {
    const token = TokenStore.getAccessToken();
    if (!token) return null;

    // Step 1: username saved directly from the OAuth token response (free, no network)
    const storedUsername = TokenStore.getUsername();
    if (storedUsername) return { attributes: { username: storedUsername } };

    // Step 2: try to decode a JWT access token (no network call)
    try {
      const parts = token.split('.');
      if (parts.length === 3) {
        const payload = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')));
        const username = payload.username || payload.preferred_username || payload.name || payload.sub;
        if (username && typeof username === 'string' && !username.match(/^\d+$/)) {
          return { attributes: { username } };
        }
      }
    } catch (_) { /* not a JWT — fall through */ }

    // Step 3: use the general proxy (includes Authorization-Type: v2 which Challonge requires)
    try {
      const data = await apiRequest('/me');
      const username = data?.attributes?.username || data?.data?.attributes?.username;
      if (username) {
        sessionStorage.setItem('challonge_username', String(username));
        return { attributes: { username } };
      }
    } catch (_) { /* /me not available — fall through */ }

    // Step 4: dedicated server route (tries multiple URL patterns)
    try {
      const r = await fetch(CHALLONGE_CONFIG.userUrl, {
        headers: { 'Authorization': `Bearer ${token}` },
      });
      if (r.ok) {
        const data = await r.json().catch(() => null);
        const username = data?.data?.attributes?.username
          || data?.attributes?.username
          || data?.username;
        if (username) {
          sessionStorage.setItem('challonge_username', String(username));
          return { attributes: { username } };
        }
      }
    } catch (_) { /* server unreachable — fall through */ }

    return null;
  },
};
