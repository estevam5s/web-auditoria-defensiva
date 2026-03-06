/*  ═══════════════════════════════════════════════════════════════════
    HTTP Helper — Shared fetch wrapper with timeout and error handling
    ═══════════════════════════════════════════════════════════════════ */

const fetch = require('node-fetch');

const DEFAULT_TIMEOUT = 10000;

async function safeFetch(url, options = {}) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), options.timeout || DEFAULT_TIMEOUT);

  try {
    const res = await fetch(url, {
      ...options,
      signal: controller.signal,
      headers: {
        'User-Agent': 'SupabaseGuard/1.0 SecurityAudit',
        ...options.headers
      }
    });

    const text = await res.text();
    let json = null;
    try { json = JSON.parse(text); } catch {}

    return {
      ok: res.ok,
      status: res.status,
      statusText: res.statusText,
      headers: Object.fromEntries(res.headers.entries()),
      text,
      json,
      url: res.url
    };
  } catch (err) {
    return {
      ok: false,
      status: 0,
      statusText: err.name === 'AbortError' ? 'Timeout' : err.message,
      headers: {},
      text: '',
      json: null,
      error: err.message,
      url
    };
  } finally {
    clearTimeout(timeout);
  }
}

// Build standard Supabase headers
function supabaseHeaders(anonKey) {
  const headers = {
    'Content-Type': 'application/json',
    'Accept': 'application/json'
  };
  if (anonKey) {
    headers['apikey'] = anonKey;
    headers['Authorization'] = `Bearer ${anonKey}`;
  }
  return headers;
}

module.exports = { safeFetch, supabaseHeaders };
