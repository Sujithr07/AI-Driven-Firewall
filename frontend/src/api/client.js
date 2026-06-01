/**
 * Centralized API configuration.
 * In dev, Vite proxies /api to the Flask backend (see vite.config.js).
 * In production, set VITE_API_URL to the real backend origin.
 */
const API_BASE = import.meta.env.VITE_API_URL || '';

export function apiUrl(path) {
  return `${API_BASE}${path}`;
}

export function authHeaders() {
  const token = localStorage.getItem('token');
  return {
    'Content-Type': 'application/json',
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
  };
}

export async function apiFetch(path, options = {}) {
  const url = apiUrl(path);
  const headers = { ...authHeaders(), ...options.headers };
  const res = await fetch(url, { ...options, headers });

  if (res.status === 401) {
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    window.location.reload();
    throw new Error('Session expired');
  }

  return res;
}
