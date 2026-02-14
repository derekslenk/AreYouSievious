import { writable } from 'svelte/store';

export const user = writable(null); // { username, host } or null
export const scripts = writable([]); // [{ name, active }]
export const currentScript = writable(null); // parsed script JSON
export const currentScriptName = writable('');
export const folders = writable([]); // [{ name, delimiter, flags }]
export const view = writable('login'); // 'login' | 'dashboard' | 'editor' | 'raw'
export const toast = writable(null); // { message, type: 'success'|'error' }

export function showToast(message, type = 'success') {
  toast.set({ message, type });
  setTimeout(() => toast.set(null), 3000);
}
