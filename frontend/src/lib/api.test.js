/**
 * The API client's 401 handling (areyousievious-8fg.21).
 *
 * `request()` treated EVERY 401 as a session expiry: it dispatched
 * `ays:logout` and threw `Error('Session expired')`. A login is the one place
 * where a 401 means the opposite — these credentials were refused, and there
 * is no session to expire, because none was ever created.
 *
 * The visible bug was in Login.svelte:
 *
 *     error = e.message.includes('401') ? 'Invalid credentials' : e.message;
 *
 * `'Session expired'` contains no `401`, so that branch could never match.
 * Verified before this change: a mistyped password showed "Session expired"
 * AND fired the global logout event.
 *
 * The sniff was doubly wrong. Reading a status out of a MESSAGE also matches
 * the wrong things — `throw new Error(`${res.status}: ${text}`)` puts the
 * body in the message, so any error whose text happens to contain `401`
 * reads as a credential failure. The status travels on the error now.
 *
 * The pre-auth path list mirrors `CSRF_EXEMPT_PATHS` above it, and the
 * backend's own `middleware.py` `EXEMPT_PATHS`, for the same reason: login is
 * the request that happens before there is a session.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { api, ApiError } from './api.js';

// `vi.stubGlobal` rather than assigning to `globalThis.*`: this project has
// no jsdom, so the globals do not exist, and a bare assignment is also a
// svelte-check error (`npm run check` runs in CI) because a stub object is
// not a real `Document` or `Window`. stubGlobal sidesteps both and undoes
// itself, so one test cannot leak a stub into the next.
let dispatched = [];

function respond({ status, body = '', json = {} }) {
  vi.stubGlobal(
    'fetch',
    vi.fn().mockResolvedValue({
      status,
      ok: status >= 200 && status < 300,
      text: async () => body,
      json: async () => json,
    }),
  );
}

function logouts() {
  return dispatched.filter((event) => event.type === 'ays:logout').length;
}

beforeEach(() => {
  dispatched = [];
  vi.stubGlobal('window', { dispatchEvent: (event) => dispatched.push(event) });
  vi.stubGlobal('document', { cookie: 'ays_csrf=tok' });
  vi.stubGlobal(
    'CustomEvent',
    class {
      constructor(type) {
        this.type = type;
      }
    },
  );
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('a 401 answering the login request', () => {
  it('does not report the session as expired', async () => {
    respond({ status: 401, body: 'Authentication failed' });
    await expect(api.login({ host: 'h', username: 'u', password: 'wrong' })).rejects.toThrow(
      ApiError,
    );
  });

  it('does not fire the global logout event', async () => {
    // There is no session to end. Firing it tore down state the user was
    // still using and sent them round a loop that cannot succeed.
    respond({ status: 401, body: 'Authentication failed' });
    await api.login({ host: 'h', username: 'u', password: 'x' }).catch(() => {});
    expect(logouts()).toBe(0);
  });

  it('carries the status, so no caller has to read it out of a message', async () => {
    respond({ status: 401, body: 'Authentication failed' });
    const error = await api.login({ host: 'h', username: 'u', password: 'x' }).catch((e) => e);
    expect(error.status).toBe(401);
    expect(error.preAuth).toBe(true);
  });
});

describe('a 401 answering any other request', () => {
  it('is still a session expiry, and still fires the logout event', async () => {
    respond({ status: 401, body: '' });
    const error = await api.listScripts().catch((e) => e);
    expect(error.message).toBe('Session expired');
    expect(error.status).toBe(401);
    expect(error.preAuth).toBe(false);
    expect(logouts()).toBe(1);
  });

  it('applies to the import path too, which builds its own request', async () => {
    respond({ status: 401, body: '' });
    const error = await api.importScript('n', new Blob()).catch((e) => e);
    expect(error).toBeInstanceOf(ApiError);
    expect(error.status).toBe(401);
    expect(logouts()).toBe(1);
  });
});

describe('the status never comes from the message text', () => {
  it('a non-401 whose BODY contains 401 is not a credential failure', async () => {
    // The hazard the old sniff carried: the body is interpolated into the
    // message, so a script named `401` or a diagnostic quoting a line number
    // read as a rejected password.
    respond({ status: 400, body: 'line 401: unknown command' });
    const error = await api.listScripts().catch((e) => e);
    expect(error.status).toBe(400);
    expect(error.preAuth).toBe(false);
    expect(logouts()).toBe(0);
  });

  it('every failure carries its status', async () => {
    respond({ status: 502, body: 'The mail server is unavailable.' });
    const error = await api.listFolders().catch((e) => e);
    expect(error).toBeInstanceOf(ApiError);
    expect(error.status).toBe(502);
    expect(error.message).toContain('unavailable');
  });
});

describe('a successful request is unaffected', () => {
  it('returns the parsed body', async () => {
    respond({ status: 200, json: { username: 'u' } });
    await expect(api.login({ host: 'h', username: 'u', password: 'ok' })).resolves.toEqual({
      username: 'u',
    });
    expect(logouts()).toBe(0);
  });
});
