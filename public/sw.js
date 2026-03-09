/* ═══════════════════════════════════════════════════════════════════
   SERVICE WORKER — Auto-versioned Cache with Deploy Invalidation
   Estratégia: Network-first para HTML/JS/CSS, cache-first para fonts.
   O cache é invalidado automaticamente quando o servidor retorna
   uma versão diferente via /api/version.
   ═══════════════════════════════════════════════════════════════════ */

const CACHE_PREFIX = 'supabase-guard-';
const VERSION_URL  = '/api/version';
const VERSION_CHECK_INTERVAL = 5 * 60 * 1000; // 5 min — era 30s, aumentado para evitar reload durante scans

let CURRENT_CACHE = null;
let _notifiedVersion = null; // evita notificar a mesma versão múltiplas vezes

// ── Helpers ──────────────────────────────────────────────────────

async function getServerVersion() {
  try {
    const res = await fetch(VERSION_URL, { cache: 'no-store' });
    if (!res.ok) return null;
    const data = await res.json();
    return data.buildHash || data.version || null;
  } catch {
    return null;
  }
}

async function resolveCurrentCache() {
  if (CURRENT_CACHE) return CURRENT_CACHE;
  // Try to find existing cache
  const keys = await caches.keys();
  const existing = keys.find(k => k.startsWith(CACHE_PREFIX));
  if (existing) {
    CURRENT_CACHE = existing;
    return CURRENT_CACHE;
  }
  // Create new cache with timestamp
  CURRENT_CACHE = CACHE_PREFIX + Date.now();
  return CURRENT_CACHE;
}

async function deleteOldCaches(keepName) {
  const keys = await caches.keys();
  await Promise.all(
    keys
      .filter(k => k.startsWith(CACHE_PREFIX) && k !== keepName)
      .map(k => caches.delete(k))
  );
}

async function nukeCacheAndReload(newHash) {
  // Evita notificar múltiplas vezes para a mesma versão
  if (_notifiedVersion === newHash) return;
  _notifiedVersion = newHash;

  const newCacheName = CACHE_PREFIX + newHash;
  CURRENT_CACHE = newCacheName;
  await deleteOldCaches(newCacheName);
  // Notifica clientes — eles decidem quando recarregar (não forçamos)
  const clients = await self.clients.matchAll({ type: 'window' });
  for (const client of clients) {
    client.postMessage({ type: 'CACHE_INVALIDATED', newVersion: newHash });
  }
}

// ── Files to pre-cache on install ────────────────────────────────

const PRECACHE_URLS = [
  '/',
  '/index.html',
  '/styles.css',
  '/app.js',
  '/manifest.json',
];

const FONT_URLS = [
  'https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;600;700&family=Inter:wght@300;400;500;600;700&display=swap'
];

// ── Install ───────────────────────────────────────────────────────

self.addEventListener('install', event => {
  event.waitUntil(
    (async () => {
      const version = await getServerVersion();
      const cacheName = version ? CACHE_PREFIX + version : CACHE_PREFIX + Date.now();
      CURRENT_CACHE = cacheName;

      const cache = await caches.open(cacheName);
      // Pre-cache app shell (ignore failures)
      await Promise.allSettled(PRECACHE_URLS.map(url => cache.add(url)));
      await self.skipWaiting();
    })()
  );
});

// ── Activate ──────────────────────────────────────────────────────

self.addEventListener('activate', event => {
  event.waitUntil(
    (async () => {
      const cacheName = await resolveCurrentCache();
      await deleteOldCaches(cacheName);
      await self.clients.claim();
    })()
  );
});

// ── Fetch — Network-first for app files, Cache-first for fonts ───

self.addEventListener('fetch', event => {
  const req = event.request;
  const url = new URL(req.url);

  // Always bypass SW for API calls
  if (url.pathname.startsWith('/api/')) return;

  // Non-GET → bypass
  if (req.method !== 'GET') return;

  // Fonts / external → cache-first (rarely change)
  if (!url.origin.includes(self.location.origin)) {
    event.respondWith(cacheFirst(req));
    return;
  }

  // App shell (HTML, JS, CSS) → network-first
  event.respondWith(networkFirst(req));
});

async function networkFirst(req) {
  const cacheName = await resolveCurrentCache();

  try {
    const netRes = await fetch(req, { cache: 'no-cache' });
    if (netRes.ok) {
      const cache = await caches.open(cacheName);
      cache.put(req, netRes.clone()); // update cache silently
    }
    return netRes;
  } catch {
    // Offline — try cache
    const cached = await caches.match(req);
    if (cached) return cached;
    // Last resort: return index.html for navigation
    if (req.mode === 'navigate') {
      return caches.match('/index.html');
    }
    return new Response('Offline', { status: 503 });
  }
}

async function cacheFirst(req) {
  const cached = await caches.match(req);
  if (cached) return cached;

  try {
    const netRes = await fetch(req);
    if (netRes.ok) {
      const cacheName = await resolveCurrentCache();
      const cache = await caches.open(cacheName);
      cache.put(req, netRes.clone());
    }
    return netRes;
  } catch {
    return new Response('Offline', { status: 503 });
  }
}

// ── Version polling — invalidate cache when deploy detected ───────

async function checkForUpdate() {
  try {
    const serverVersion = await getServerVersion();
    if (!serverVersion) return;

    const cacheName = await resolveCurrentCache();
    const currentHash = cacheName.replace(CACHE_PREFIX, '');

    if (currentHash !== serverVersion && !cacheName.endsWith(serverVersion)) {
      console.log(`[SW] Nova versão detectada: ${serverVersion} (atual: ${currentHash}). Invalidando cache...`);
      await nukeCacheAndReload(serverVersion);
    }
  } catch {
    // ignore
  }
}

// Poll for updates every 30s
setInterval(checkForUpdate, VERSION_CHECK_INTERVAL);

// ── Messages from main thread ─────────────────────────────────────

self.addEventListener('message', event => {
  if (!event.data) return;

  switch (event.data.type) {
    case 'SKIP_WAITING':
      self.skipWaiting();
      break;

    case 'CHECK_UPDATE':
      checkForUpdate();
      break;

    case 'CLEAR_CACHE':
      caches.keys().then(keys =>
        Promise.all(keys.filter(k => k.startsWith(CACHE_PREFIX)).map(k => caches.delete(k)))
      ).then(() => {
        CURRENT_CACHE = null;
        event.source?.postMessage({ type: 'CACHE_CLEARED' });
      });
      break;
  }
});
