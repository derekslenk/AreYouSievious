/**
 * API client for AreYouSievious backend.
 */

const BASE = '/api';

async function request(path, opts = {}) {
  const res = await fetch(BASE + path, {
    credentials: 'include',
    headers: { 'Content-Type': 'application/json', ...opts.headers },
    ...opts,
  });
  if (res.status === 401) {
    // Session expired
    window.dispatchEvent(new CustomEvent('ays:logout'));
    throw new Error('Session expired');
  }
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`${res.status}: ${text}`);
  }
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
      method: 'POST', credentials: 'include', body: form,
    }).then(r => {
      if (r.status === 401) { window.dispatchEvent(new CustomEvent('ays:logout')); throw new Error('Session expired'); }
      if (!r.ok) return r.text().then(t => { throw new Error(`${r.status}: ${t}`); });
      return r.json();
    });
  },

  // Folders
  listFolders: () => request('/folders'),
  createFolder: (name) => request('/folders', { method: 'POST', body: JSON.stringify({ name }) }),
};
