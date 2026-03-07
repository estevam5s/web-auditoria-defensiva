/*  ═══════════════════════════════════════════════════════════════════
    AUTO-DETECT: Supabase Credentials Scanner
    Automatically detects SUPABASE_URL and ANON_KEY from public JS bundles
    Enables full audit without manual credential input
    ═══════════════════════════════════════════════════════════════════ */

const { safeFetch } = require('../helpers/http');

const SUPABASE_URL_PATTERNS = [
  /(?:supabaseUrl|SUPABASE_URL|supabase_url|SUPABASE_URL_API)\s*[=:]\s*["'](https?:\/\/[a-z0-9-]+\.supabase\.co)["']/gi,
  /supabase\s*:\s*\{[^}]*?url\s*[=:]\s*["'](https?:\/\/[a-z0-9-]+\.supabase\.co)["']/gi,
  /createClient\s*\(\s*["'](https?:\/\/[a-z0-9-]+\.supabase\.co)["']/gi,
  /"projectUrl"\s*:\s*"([^"]*\.supabase\.co)"/g,
  /"supabaseUrl"\s*:\s*"([^"]*\.supabase\.co)"/g,
];

const ANON_KEY_PATTERNS = [
  /(?:anonKey|ANON_KEY|anon_key|PUBLIC_ANON_KEY)\s*[=:]\s*["'](eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]+)["']/gi,
  /apikey\s*[=:]\s*["'](eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]+)["']/gi,
  /"anonKey"\s*:\s*"([^"]*\.eyJ[^"]*)"/g,
  /"apikey"\s*:\s*"([^"]*\.eyJ[^"]*)"/g,
];

const SERVICE_ROLE_PATTERNS = [
  /(?:serviceRoleKey|SERVICE_ROLE_KEY|service_role_key)\s*[=:]\s*["'](eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.eyJyb2xlIjoic2VydmljZV9yb2xlIn0\.[A-Za-z0-9_-]+)["']/gi,
];

const BUNDLE_PATHS = [
  '/',
  '/index.html',
  '/app.js',
  '/main.js',
  '/bundle.js',
  '/app.bundle.js',
  '/main.bundle.js',
  '/static/js/main.js',
  '/static/js/bundle.js',
  '/static/js/app.js',
  '/assets/index.js',
  '/assets/app.js',
  '/_next/static/chunks/main.js',
  '/_next/static/chunks/framework.js',
  '/_next/static/chunks/pages/_app.js',
  '/dist/bundle.js',
  '/build/static/js/main.js',
  '/js/app.js',
  '/js/main.js',
  '/js/config.js',
  '/env.js',
  '/config.js',
  '/constants.js',
  '/globals.js',
  '/_nuxt/',
  '/.next/',
];

const KEY_PATTERNS = [
  { name: 'SUPABASE_URL', regex: /https:\/\/[a-z0-9-]+\.supabase\.co/gi },
  { name: 'ANON_KEY', regex: /eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]+/g },
];

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

  for (const path of BUNDLE_PATHS) {
    const url = baseUrl + path;
    const res = await safeFetch(url, { timeout: 8000 });

    results.scannedPaths++;

    if (!res.ok || !res.text || res.text.length < 50) continue;

    const content = res.text.substring(0, 2000000);

    for (const pattern of KEY_PATTERNS) {
      const matches = content.match(pattern.regex);
      if (!matches) continue;

      const unique = [...new Set(matches)];

      for (const match of unique) {
        if (pattern.name === 'SUPABASE_URL' && !results.supabaseUrl) {
          results.supabaseUrl = match;
          results.sources.push({ type: 'SUPABASE_URL', source: path, value: maskValue(match) });
          emit({ type: 'log', level: 'info', message: `[Auto-Detect] SUPABASE_URL detectada em ${path}` });
        }

        if (pattern.name === 'ANON_KEY' && !results.anonKey) {
          if (isLikelyAnonKey(match)) {
            results.anonKey = match;
            results.sources.push({ type: 'ANON_KEY', source: path, value: maskValue(match) });
            emit({ type: 'log', level: 'info', message: `[Auto-Detect] ANON_KEY detectada em ${path}` });
          }
        }
      }
    }

    if (results.supabaseUrl && results.anonKey) break;
  }

  if (!results.supabaseUrl) {
    const supabaseUrlFromBase = baseUrl.match(/https?:\/\/([a-z0-9-]+)\.supabase\.co/);
    if (supabaseUrlFromBase) {
      results.supabaseUrl = supabaseUrlFromBase[0];
      results.sources.push({ type: 'SUPABASE_URL', source: 'URL fornecida', value: maskValue(results.supabaseUrl) });
    }
  }

  if (results.anonKey) {
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
    return payload.role === 'anon' || !payload.role;
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
  if (results.sources.length > 1) confidence += 10;
  return Math.min(100, confidence);
}

async function runAutoDetect(config, emit) {
  const results = [];
  const baseUrl = config.projectUrl;

  const detected = await autoDetectCredentials(baseUrl, emit);

  if (detected.supabaseUrl || detected.anonKey) {
    results.push({
      check: 'Auto-Detect — Credenciais',
      status: 'PASS',
      severity: 'info',
      message: detected.anonKey 
        ? `Credenciais detectadas automaticamente (confiança: ${detected.confidence}%)`
        : `SUPABASE_URL detectada automaticamente`,
      details: {
        supabaseUrl: detected.supabaseUrl,
        anonKeyFound: !!detected.anonKey,
        confidence: detected.confidence,
        sources: detected.sources,
        scannedPaths: detected.scannedPaths,
        recommendation: detected.anonKey 
          ? 'Credenciais detectadas com sucesso. Auditoria prosseguirá com credenciais automáticas.'
          : 'Anon key não detectada. Alguns testes podem ter limitação.'
      }
    });

    return {
      results,
      detected: {
        supabaseUrl: detected.supabaseUrl,
        anonKey: detected.anonKey,
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
        recommendation: 'Forneça a anon key manualmente para auditoria completa.'
      }
    });

    return {
      results,
      detected: {
        supabaseUrl: baseUrl,
        anonKey: null,
        confidence: 0
      }
    };
  }
}

module.exports = { autoDetectCredentials, runAutoDetect };
