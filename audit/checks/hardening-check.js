/*  ═══════════════════════════════════════════════════════════════════
    HARDENING CHECK: Rate Limiting & Cache Analysis
    Detects missing rate-limit signaling and unsafe cache headers
    on Supabase REST, Auth, GraphQL, Storage and Edge endpoints
    ═══════════════════════════════════════════════════════════════════ */

const { safeFetch, supabaseHeaders } = require('../helpers/http');

// Endpoints to check for rate limiting and cache headers
const KEY_ENDPOINTS = [
  '/rest/v1/',
  '/auth/v1/settings',
  '/auth/v1/signup',
  '/auth/v1/token',
  '/auth/v1/otp',
  '/auth/v1/recover',
  '/auth/v1/user',
  '/storage/v1/bucket',
  '/graphql/v1',
];

// Rate limiting headers (any of these indicate protection)
const RATE_LIMIT_HEADERS = [
  'x-ratelimit-limit',
  'x-ratelimit-remaining',
  'x-ratelimit-reset',
  'ratelimit-limit',
  'ratelimit-remaining',
  'retry-after',
  'x-rate-limit-limit',
  'x-rate-limit-remaining',
  'cf-cache-status', // Cloudflare rate-limiting signal
];

// Unsafe cache-control values for data endpoints
const UNSAFE_CACHE_PATTERNS = [
  /max-age=(?:[1-9]\d{3,}|\d{2,})/i, // max-age >= 10s on data endpoint
  /s-maxage=/i,
  /public/i,
];

async function hardeningCheck(config, emit) {
  const results = [];
  const baseUrl = config.projectUrl;
  const anonKey = config.anonKey;
  const headers = supabaseHeaders(anonKey);

  emit({ type: 'log', level: 'info', message: '[Hardening] Analisando rate limiting e cache nos endpoints...' });

  const noRateLimit = [];
  const unsafeCache = [];
  let totalChecked = 0;

  // Check key endpoints
  const endpointChecks = KEY_ENDPOINTS.map(path => ({
    path,
    url: `${baseUrl}${path}`
  }));

  // Also add all exposed REST tables from catalog
  const catalogTables = (config._catalog?.tables || []).slice(0, 50);
  for (const table of catalogTables) {
    endpointChecks.push({
      path: `/rest/v1/${table.name}`,
      url: `${baseUrl}/rest/v1/${table.name}?select=*&limit=1`
    });
  }

  const BATCH = 8;
  for (let i = 0; i < endpointChecks.length; i += BATCH) {
    const batch = endpointChecks.slice(i, i + BATCH);
    const promises = batch.map(async ({ path, url }) => {
      const res = await safeFetch(url, { headers, timeout: 6000 });
      if (!res.ok && res.status === 0) return null;

      totalChecked++;
      const resHeaders = res.headers || {};

      // Check rate limit headers
      const hasRateLimit = RATE_LIMIT_HEADERS.some(h => resHeaders[h] !== undefined);

      // Check cache headers on data endpoints
      const cacheControl = resHeaders['cache-control'] || '';
      const isUnsafeCache = path.startsWith('/rest/v1/') && cacheControl
        ? UNSAFE_CACHE_PATTERNS.some(p => p.test(cacheControl))
        : false;

      return { path, hasRateLimit, cacheControl, isUnsafeCache, status: res.status };
    });

    const batchResults = await Promise.all(promises);
    for (const r of batchResults) {
      if (!r) continue;
      if (!r.hasRateLimit) noRateLimit.push(r.path);
      if (r.isUnsafeCache) unsafeCache.push({ path: r.path, cacheControl: r.cacheControl });
    }
  }

  emit({ type: 'log', level: 'info', message: `[Hardening] ${totalChecked} endpoints verificados` });

  // Rate limiting report
  if (noRateLimit.length > 0) {
    const criticalNoRateLimit = noRateLimit.filter(p =>
      p.includes('/auth/') || p.includes('/rest/v1/users') || p.includes('/rest/v1/auth')
    );

    results.push({
      check: 'Hardening — Rate Limiting Ausente',
      status: criticalNoRateLimit.length > 0 ? 'FAIL' : 'WARN',
      severity: criticalNoRateLimit.length > 0 ? 'high' : 'medium',
      message: `${noRateLimit.length} endpoint(s) sem sinalização de rate limiting — vulneráveis a brute force e abuso.`,
      details: {
        totalWithoutRateLimit: noRateLimit.length,
        totalChecked,
        criticalEndpoints: criticalNoRateLimit,
        allEndpoints: noRateLimit.slice(0, 30),
        recommendation: 'Configure rate limiting no Supabase Dashboard > Auth Rate Limits. Use Cloudflare ou outro WAF para proteção adicional.'
      }
    });
  } else if (totalChecked > 0) {
    results.push({
      check: 'Hardening — Rate Limiting',
      status: 'PASS',
      severity: 'info',
      message: `Rate limiting detectado em todos os ${totalChecked} endpoints verificados.`,
      details: { totalChecked }
    });
  }

  // Cache headers report
  if (unsafeCache.length > 0) {
    results.push({
      check: 'Hardening — Cache Inseguro em Endpoints de Dados',
      status: 'WARN',
      severity: 'medium',
      message: `${unsafeCache.length} endpoint(s) de dados com cache-control inseguro. Respostas podem ser cacheadas por proxies.`,
      details: {
        endpoints: unsafeCache.slice(0, 20),
        recommendation: 'Use Cache-Control: no-store ou private em endpoints que retornam dados de usuário.'
      }
    });
  }

  // Auth endpoints brute-force surface
  const authEndpointsNoLimit = noRateLimit.filter(p => p.includes('/auth/'));
  if (authEndpointsNoLimit.length > 0) {
    results.push({
      check: 'Hardening — Auth Sem Rate Limiting',
      status: 'WARN',
      severity: 'high',
      message: `${authEndpointsNoLimit.length} endpoint(s) de autenticação sem rate limiting — risco de brute force.`,
      details: {
        endpoints: authEndpointsNoLimit,
        recommendation: 'Configure rate limits em Auth > Rate Limits no Supabase Dashboard: signup, OTP, recovery.'
      }
    });
  }

  if (results.length === 0) {
    results.push({
      check: 'Hardening — Rate Limiting & Cache',
      status: 'PASS',
      severity: 'info',
      message: 'Hardening adequado detectado nos endpoints verificados.',
      details: { totalChecked }
    });
  }

  return results;
}

module.exports = { hardeningCheck };
