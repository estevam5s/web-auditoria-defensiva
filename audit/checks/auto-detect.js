/*  ═══════════════════════════════════════════════════════════════════
    AUTO-DETECT: Supabase Credentials Scanner
    Automatically detects SUPABASE_URL and ANON_KEY from public JS bundles
    Enables full audit without manual credential input
    ═══════════════════════════════════════════════════════════════════ */

const { safeFetch } = require('../helpers/http');

const KEY_PATTERNS = [
  { name: 'SUPABASE_URL', regex: /https:\/\/[a-z0-9-]+\.supabase\.co/gi },
  { name: 'ANON_KEY', regex: /eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]+/g },
];

const STATIC_BUNDLE_PATHS = [
  '/app.js', '/main.js', '/bundle.js', '/app.bundle.js', '/main.bundle.js',
  '/static/js/main.js', '/static/js/bundle.js', '/static/js/app.js',
  '/assets/index.js', '/assets/app.js', '/assets/main.js',
  '/_next/static/chunks/main.js', '/_next/static/chunks/framework.js',
  '/_next/static/chunks/pages/_app.js',
  '/dist/bundle.js', '/build/static/js/main.js',
  '/js/app.js', '/js/main.js', '/js/config.js', '/js/env.js',
  '/env.js', '/config.js', '/constants.js', '/globals.js',
  '/admin/js/env.js', '/public/env.js', '/public/config.js',
  '/src/config.js', '/src/env.js', '/src/supabase.js',
  '/lib/supabase.js', '/utils/supabase.js', '/supabase.js',
];

// Parse HTML to discover actual script URLs (critical for hashed filenames like index-CitENTfB.js)
async function discoverScriptUrlsFromHTML(baseUrl) {
  const discovered = [];

  for (const htmlPath of ['/', '/index.html']) {
    const res = await safeFetch(baseUrl + htmlPath, { timeout: 10000 });
    if (!res.ok || !res.text) continue;

    const html = res.text;

    // Extract <script src="...">
    const scriptRegex = /<script[^>]+src=["']([^"']+)["']/gi;
    let match;
    while ((match = scriptRegex.exec(html)) !== null) {
      let src = match[1].split('?')[0];
      if (src.startsWith('//')) src = 'https:' + src;
      else if (src.startsWith('/')) src = baseUrl + src;
      else if (!src.startsWith('http')) src = baseUrl + '/' + src;
      if (!discovered.includes(src)) discovered.push(src);
    }

    // Extract <link rel="preload" as="script"> and modulepreload
    const preloadRegex = /<link[^>]+href=["']([^"']+\.js[^"']*)["'][^>]*rel=["'](?:preload|modulepreload)["']|<link[^>]*rel=["'](?:preload|modulepreload)["'][^>]+href=["']([^"']+\.js[^"']*)["']/gi;
    while ((match = preloadRegex.exec(html)) !== null) {
      let src = (match[1] || match[2] || '').split('?')[0];
      if (src.startsWith('/')) src = baseUrl + src;
      if (src && !discovered.includes(src)) discovered.push(src);
    }

    if (discovered.length > 0) break;
  }

  return discovered;
}

async function autoDetectCredentials(baseUrl, emit) {
  const results = {
    supabaseUrl: null,
    anonKey: null,
    serviceRoleKey: null,
    sources: [],
    scannedPaths: 0,
    confidence: 0
  };

  emit({ type: 'log', level: 'info', message: '[Auto-Detect] Iniciando detecção automática de credenciais...' });

  // Step 1: Parse HTML to find actual script URLs (critical for hashed filenames)
  emit({ type: 'log', level: 'info', message: '[Auto-Detect] Analisando HTML para descobrir scripts dinâmicos...' });
  const htmlScripts = await discoverScriptUrlsFromHTML(baseUrl);

  if (htmlScripts.length > 0) {
    emit({ type: 'log', level: 'info', message: `[Auto-Detect] ${htmlScripts.length} scripts descobertos no HTML` });
  }

  // Step 2: Build scan list — HTML scripts first, then static fallback paths
  const staticUrls = STATIC_BUNDLE_PATHS.map(p => baseUrl + p);
  const allUrls = [...new Set([...htmlScripts, ...staticUrls])];

  for (const url of allUrls) {
    const res = await safeFetch(url, { timeout: 8000 });
    results.scannedPaths++;

    if (!res.ok || !res.text || res.text.length < 50) continue;

    const content = res.text.substring(0, 3000000);
    const sourcePath = url.replace(baseUrl, '') || '/';

    for (const pattern of KEY_PATTERNS) {
      const matches = content.match(pattern.regex);
      if (!matches) continue;

      const unique = [...new Set(matches)];

      for (const match of unique) {
        if (pattern.name === 'SUPABASE_URL' && !results.supabaseUrl) {
          results.supabaseUrl = match;
          results.sources.push({ type: 'SUPABASE_URL', source: sourcePath, value: maskValue(match) });
          emit({ type: 'log', level: 'info', message: `[Auto-Detect] SUPABASE_URL detectada em ${sourcePath}: ${maskValue(match)}` });
        }

        if (pattern.name === 'ANON_KEY' && !results.anonKey) {
          if (isLikelyAnonKey(match)) {
            results.anonKey = match;
            results.sources.push({ type: 'ANON_KEY', source: sourcePath, value: maskValue(match) });
            emit({ type: 'log', level: 'info', message: `[Auto-Detect] ANON_KEY detectada em ${sourcePath}` });
          } else if (isServiceRoleKey(match) && !results.serviceRoleKey) {
            results.serviceRoleKey = match;
            results.sources.push({ type: 'SERVICE_ROLE_KEY', source: sourcePath, value: maskValue(match) });
            emit({ type: 'log', level: 'warn', message: `[Auto-Detect] SERVICE_ROLE_KEY EXPOSTA em ${sourcePath}!` });
          }
        }
      }
    }

    if (results.supabaseUrl && results.anonKey) break;
  }

  // Step 3: If the provided URL itself is a Supabase URL
  if (!results.supabaseUrl) {
    const supabaseUrlFromBase = baseUrl.match(/https?:\/\/[a-z0-9-]+\.supabase\.co/);
    if (supabaseUrlFromBase) {
      results.supabaseUrl = supabaseUrlFromBase[0];
      results.sources.push({ type: 'SUPABASE_URL', source: 'URL fornecida', value: maskValue(results.supabaseUrl) });
    }
  }

  if (results.anonKey || results.supabaseUrl) {
    results.confidence = calculateConfidence(results);
    emit({ type: 'log', level: 'info', message: `[Auto-Detect] Confiança: ${results.confidence}%` });
  }

  return results;
}

function isLikelyAnonKey(jwt) {
  try {
    const parts = jwt.split('.');
    if (parts.length !== 3) return false;
    const payload = JSON.parse(Buffer.from(parts[1], 'base64').toString());
    return payload.role === 'anon' || (!payload.role && payload.iss === 'supabase');
  } catch {
    return false;
  }
}

function isServiceRoleKey(jwt) {
  try {
    const parts = jwt.split('.');
    if (parts.length !== 3) return false;
    const payload = JSON.parse(Buffer.from(parts[1], 'base64').toString());
    return payload.role === 'service_role';
  } catch {
    return false;
  }
}

function maskValue(value) {
  if (!value) return null;
  if (value.length <= 20) return '***';
  return value.substring(0, 12) + '...' + value.substring(value.length - 8);
}

function calculateConfidence(results) {
  let confidence = 0;
  if (results.supabaseUrl) confidence += 40;
  if (results.anonKey) confidence += 50;
  if (results.serviceRoleKey) confidence += 10;
  if (results.sources.length > 1) confidence += 10;
  return Math.min(100, confidence);
}

async function runAutoDetect(config, emit) {
  const results = [];
  const baseUrl = config.projectUrl;

  const detected = await autoDetectCredentials(baseUrl, emit);

  if (detected.supabaseUrl || detected.anonKey) {
    const hasServiceRole = !!detected.serviceRoleKey;

    results.push({
      check: 'Auto-Detect — Credenciais',
      status: hasServiceRole ? 'FAIL' : 'PASS',
      severity: hasServiceRole ? 'critical' : 'info',
      message: hasServiceRole
        ? `SERVICE_ROLE_KEY EXPOSTA publicamente! Acesso admin ao banco detectado.`
        : detected.anonKey
          ? `Credenciais Supabase detectadas automaticamente (confiança: ${detected.confidence}%)`
          : `SUPABASE_URL detectada automaticamente`,
      details: {
        supabaseUrl: detected.supabaseUrl,
        anonKeyFound: !!detected.anonKey,
        serviceRoleKeyFound: hasServiceRole,
        confidence: detected.confidence,
        sources: detected.sources,
        scannedPaths: detected.scannedPaths,
        recommendation: hasServiceRole
          ? 'URGENTE: Nunca exponha a service_role key publicamente. Revogue e rotacione imediatamente.'
          : 'Credenciais detectadas com sucesso. Auditoria prosseguirá com credenciais automáticas.'
      }
    });

    return {
      results,
      detected: {
        supabaseUrl: detected.supabaseUrl,
        anonKey: detected.anonKey,
        serviceRoleKey: detected.serviceRoleKey,
        confidence: detected.confidence
      }
    };
  } else {
    results.push({
      check: 'Auto-Detect — Credenciais',
      status: 'WARN',
      severity: 'medium',
      message: 'Nenhuma credencial Supabase detectada automaticamente.',
      details: {
        scannedPaths: detected.scannedPaths,
        recommendation: 'Forneça a anon key manualmente para auditoria completa do Supabase.'
      }
    });

    return {
      results,
      detected: {
        supabaseUrl: null,
        anonKey: null,
        confidence: 0
      }
    };
  }
}

module.exports = { autoDetectCredentials, runAutoDetect };
