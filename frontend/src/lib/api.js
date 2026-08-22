/**
 * API client for AreYouSievious backend.
 */

const BASE = '/api';
const CSRF_COOKIE = 'ays_csrf';
const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);
const CSRF_EXEMPT_PATHS = new Set(['/auth/login']);

// The requests that happen BEFORE there is a session. A 401 here means the
// credentials just sent were refused — not that a session ended, because none
// exists yet. Same membership as CSRF_EXEMPT_PATHS above and as the backend's
// own middleware.py EXEMPT_PATHS, for the same reason; kept separate because
// they answer different questions and a future pre-auth path need not be CSRF
// exempt.
const PRE_AUTH_PATHS = new Set(['/auth/login']);

/**
 * A failed request, carrying the status that caused it.
 *
 * The status lives on the error because callers used to read it out of the
 * MESSAGE — `e.message.includes('401')` in Login.svelte — which was wrong
 * twice over. It never matched, because a 401 threw `Error('Session
 * expired')` with no digits in it; and it would have matched the wrong
 * things, because `${status}: ${body}` puts the server's text in the message,
 * so a diagnostic reading `line 401:` looked like a rejected password.
 */
export class ApiError extends Error {
  constructor(message, status, { preAuth = false } = {}) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    // True only for a 401 answering a pre-auth request. Lets a caller say
    // "these credentials were refused" without knowing which paths those are.
    this.preAuth = preAuth;
  }
}

/**
 * Turn a failed response into an ApiError, and end the session if it ended.
 *
 * One place, because two request paths need it: `request` and the multipart
 * `importScript`, which builds its own fetch and used to carry a hand-copied
 * version of this. Two copies of "what does a 401 mean" is how they drift.
 */
async function failureFor(res, path) {
  const preAuth = PRE_AUTH_PATHS.has(path);
  if (res.status === 401 && !preAuth) {
    // A session that existed and no longer does. Tearing down local state is
    // the right response — and exactly the wrong one for a refused login,
    // which is why that case never reaches here.
    window.dispatchEvent(new CustomEvent('ays:logout'));
    return new ApiError('Session expired', 401);
  }
  const text = await res.text();
  if (res.status === 401) return new ApiError(text || 'Authentication failed', 401, { preAuth });
  return new ApiError(`${res.status}: ${text}`, res.status);
}

function getCsrfToken() {
  // Double-submit cookie: read the non-httponly ays_csrf cookie set
  // by the backend on login and send it back as X-CSRF-Token. A
  // cross-origin attacker cannot read this cookie (SOP), so they
  // cannot forge a matching header even though the browser will
  // attach the cookie on a forged request.
  const match = document.cookie.match(/(?:^|;\s*)ays_csrf=([^;]+)/);
  return match ? decodeURIComponent(match[1]) : '';
}

function withCsrf(method, path, headers) {
  const m = (method || 'GET').toUpperCase();
  if (SAFE_METHODS.has(m) || CSRF_EXEMPT_PATHS.has(path)) return headers;
  return { ...headers, 'X-CSRF-Token': getCsrfToken() };
}

async function request(path, opts = {}) {
  const headers = withCsrf(opts.method, path, {
    'Content-Type': 'application/json',
    ...opts.headers,
  });
  const res = await fetch(BASE + path, {
    credentials: 'include',
    ...opts,
    headers,
  });
  if (!res.ok) throw await failureFor(res, path);
  return res.json();
}

export const api = {
  // Auth
  login: (data) => request('/auth/login', { method: 'POST', body: JSON.stringify(data) }),
  logout: () => request('/auth/logout', { method: 'POST' }),
  status: () => request('/auth/status'),

  // Scripts
  listScripts: () => request('/scripts'),
  getScript: (name) => request(`/scripts/${encodeURIComponent(name)}`),
  getScriptRaw: (name) => request(`/scripts/${encodeURIComponent(name)}/raw`),
  saveScript: (name, data) => request(`/scripts/${encodeURIComponent(name)}`, {
    method: 'PUT', body: JSON.stringify(data),
  }),
  saveScriptRaw: (name, content) => request(`/scripts/${encodeURIComponent(name)}/raw`, {
    method: 'PUT', body: JSON.stringify({ content }),
  }),
  activateScript: (name) => request(`/scripts/${encodeURIComponent(name)}/activate`, { method: 'POST' }),
  deleteScript: (name) => request(`/scripts/${encodeURIComponent(name)}`, { method: 'DELETE' }),

  // Export/Import
  exportScript: (name) => `${BASE}/scripts/${encodeURIComponent(name)}/export`,
  importScript: (name, file) => {
    const form = new FormData();
    form.append('name', name);
    form.append('file', file);
    return fetch(BASE + '/scripts/import', {
      method: 'POST',
      credentials: 'include',
      headers: { 'X-CSRF-Token': getCsrfToken() },
      body: form,
    }).then(async r => {
      if (!r.ok) throw await failureFor(r, '/scripts/import');
      return r.json();
    });
  },

  // Folders
  listFolders: () => request('/folders'),
  createFolder: (name) => request('/folders', { method: 'POST', body: JSON.stringify({ name }) }),
};
