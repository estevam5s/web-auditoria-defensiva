'use strict';

/* ═══════════════════════════════════════════════════════════════════
   BRUTE FORCE RESILIENCE TEST ENGINE v2
   Detecta o endpoint real de autenticação a partir de uma URL de login,
   testa credenciais e detecta rate limiting, lockout e credenciais fracas.
   ═══════════════════════════════════════════════════════════════════ */

const http         = require('http');
const https        = require('https');
const { URL }      = require('url');
const { EventEmitter } = require('events');

// ── Wordlist embutida — credenciais comuns de pentest ────────────
const BUILTIN_WORDLIST = [
  // ─── Pares clássicos de admin ───────────────────────────────────
  { user: 'admin@admin.com',       pass: 'admin' },
  { user: 'admin@admin.com',       pass: 'password' },
  { user: 'admin@admin.com',       pass: 'admin123' },
  { user: 'admin@admin.com',       pass: '123456' },
  { user: 'admin@admin.com',       pass: 'password123' },
  { user: 'admin@admin.com',       pass: 'P@ssw0rd' },
  { user: 'admin@admin.com',       pass: 'Admin@2024' },
  { user: 'admin@admin.com',       pass: 'Admin@2025' },
  { user: 'admin@admin.com',       pass: 'Admin2025!' },
  { user: 'admin@admin.com',       pass: 'letmein' },
  { user: 'admin@admin.com',       pass: 'welcome1' },
  { user: 'admin@admin.com',       pass: 'qwerty123' },
  { user: 'admin@admin.com',       pass: 'iloveyou' },
  { user: 'admin@admin.com',       pass: '111111' },
  { user: 'admin@admin.com',       pass: '000000' },
  { user: 'admin@admin.com',       pass: 'master' },
  { user: 'admin@admin.com',       pass: 'dragon' },
  { user: 'admin@admin.com',       pass: 'monkey' },
  { user: 'admin@admin.com',       pass: 'sunshine' },
  { user: 'admin@admin.com',       pass: 'shadow' },
  // ─── Variações de endereço de e-mail ───────────────────────────
  { user: 'admin@example.com',     pass: 'admin' },
  { user: 'admin@example.com',     pass: 'password' },
  { user: 'admin@example.com',     pass: 'admin123' },
  { user: 'test@test.com',         pass: 'test' },
  { user: 'test@test.com',         pass: 'password' },
  { user: 'test@test.com',         pass: 'test123' },
  { user: 'user@user.com',         pass: 'user' },
  { user: 'user@user.com',         pass: 'password' },
  { user: 'demo@demo.com',         pass: 'demo' },
  { user: 'demo@demo.com',         pass: 'demo123' },
  { user: 'root@root.com',         pass: 'root' },
  { user: 'root@root.com',         pass: 'toor' },
  { user: 'support@example.com',   pass: 'support' },
  { user: 'info@example.com',      pass: 'info123' },
  { user: 'contact@example.com',   pass: 'contact' },
  // ─── Usernames sem domínio (form-based endpoints) ───────────────
  { user: 'admin',                 pass: 'admin' },
  { user: 'admin',                 pass: 'password' },
  { user: 'admin',                 pass: '123456' },
  { user: 'administrator',         pass: 'administrator' },
  { user: 'administrator',         pass: 'password' },
  { user: 'root',                  pass: 'root' },
  { user: 'root',                  pass: 'password' },
  { user: 'guest',                 pass: 'guest' },
  { user: 'guest',                 pass: 'password' },
  { user: 'test',                  pass: 'test' },
  { user: 'test',                  pass: 'password' },
  // ─── Supabase / projeto-específicos ────────────────────────────
  { user: 'admin@supabase.io',     pass: 'supabase' },
  { user: 'anon@supabase.io',      pass: 'anon' },
  { user: 'service@supabase.io',   pass: 'service_role' },
  // ─── Senhas comuns do OWASP Top-10 ─────────────────────────────
  { user: 'admin@admin.com',       pass: 'abc123' },
  { user: 'admin@admin.com',       pass: '12345678' },
  { user: 'admin@admin.com',       pass: 'qwerty' },
  { user: 'admin@admin.com',       pass: '1234567890' },
  { user: 'admin@admin.com',       pass: 'superman' },
  { user: 'admin@admin.com',       pass: 'batman' },
  { user: 'admin@admin.com',       pass: 'trustno1' },
  { user: 'admin@admin.com',       pass: 'pass1234' },
  { user: 'admin@admin.com',       pass: 'pass@123' },
  { user: 'admin@admin.com',       pass: 'hello123' },
  { user: 'admin@admin.com',       pass: 'changeme' },
  { user: 'admin@admin.com',       pass: 'secret' },
  { user: 'admin@admin.com',       pass: 'temp1234' },
  { user: 'admin@admin.com',       pass: 'default' },
  // ─── Sondas de SQL Injection (testa WAF/sanitização) ───────────
  { user: "' OR '1'='1",           pass: "' OR '1'='1" },
  { user: 'admin',                 pass: "' OR 1=1--" },
  { user: "admin'--",              pass: 'anything' },
  { user: '" OR ""="',             pass: '" OR ""="' },
  { user: 'admin',                 pass: "1' OR '1'='1" },
  // ─── Sondas NoSQL Injection ─────────────────────────────────────
  { user: 'admin@admin.com',       pass: '{"$gt":""}' },
  { user: '{"$gt":""}',            pass: 'anything' },
];

// ── Parser de wordlist customizada ───────────────────────────────
function parseWordlist(text, defaultUser = 'admin@target.com') {
  return text
    .split('\n')
    .map(l => l.trim())
    .filter(l => l && !l.startsWith('#') && !l.startsWith('//'))
    .slice(0, 1000)
    .map(line => {
      // Split on first colon only — handles email:password correctly
      const colonIdx = line.indexOf(':');
      if (colonIdx > 0 && colonIdx < line.length - 1) {
        return { user: line.slice(0, colonIdx), pass: line.slice(colonIdx + 1) };
      }
      return { user: defaultUser, pass: line };
    });
}

// ── HTTP GET utility (nativo, sem dependências externas) ─────────
function httpGet(url, timeoutMs = 10000) {
  return new Promise((resolve, reject) => {
    let parsed;
    try { parsed = new URL(url); } catch (e) { return reject(e); }

    const lib = parsed.protocol === 'https:' ? https : http;
    const req = lib.request({
      hostname: parsed.hostname,
      port:     parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
      path:     parsed.pathname + (parsed.search || ''),
      method:   'GET',
      headers: {
        'User-Agent': 'Mozilla/5.0 (compatible; SupabaseGuard/2.0)',
        'Accept':     'text/html,application/json,*/*',
      },
      timeout: timeoutMs,
    }, res => {
      let body = '';
      res.on('data', d => { if (body.length < 200000) body += d; });
      res.on('end', () => resolve({ status: res.statusCode, body, headers: res.headers }));
    });

    req.on('timeout', () => { req.destroy(); reject(new Error('TIMEOUT')); });
    req.on('error',  reject);
    req.end();
  });
}

// ── Detecta o tipo de endpoint de login ─────────────────────────
function detectEndpointType(urlStr) {
  if (urlStr.includes('/auth/v1/token'))               return 'supabase_token';
  if (urlStr.includes('/auth/v1/'))                    return 'supabase_auth';
  if (urlStr.includes('/api/auth/callback/credentials')) return 'nextauth';
  if (urlStr.includes('/api/auth/signin'))             return 'nextauth';
  if (urlStr.includes('/api/auth'))                    return 'api_json';
  if (urlStr.includes('/api/login'))                   return 'api_json';
  if (urlStr.includes('/api/session'))                 return 'api_json';
  if (urlStr.includes('/api/user'))                    return 'api_json';
  if (urlStr.includes('.json'))                        return 'api_json';
  return 'form';
}

// ── Resolve o endpoint real de autenticação a partir de uma URL de página ──
// Quando o usuário informa uma URL de página (/login, /signin), tenta
// descobrir automaticamente o endpoint de API real por:
//   1. Buscar Supabase URL no HTML/scripts inline
//   2. Detectar Next.js e padrão NextAuth
//   3. Parsear form action
//   4. Buscar chamadas fetch/axios no HTML inline
//   5. Fallback para padrões comuns do domínio
async function resolveLoginEndpoint(urlStr, emit) {
  const raw = urlStr.startsWith('http') ? urlStr : 'https://' + urlStr;
  let parsed;
  try { parsed = new URL(raw); } catch { return { url: raw, type: 'form', detected: 'unknown' }; }

  const origin = parsed.origin;
  const path   = parsed.pathname;

  // Já parece ser um endpoint de API — usar diretamente
  if (
    path.includes('/api/')    ||
    path.includes('/auth/v1/')||
    path.endsWith('.json')    ||
    parsed.search.includes('grant_type=')
  ) {
    return { url: parsed.href, type: detectEndpointType(parsed.href), detected: 'direct' };
  }

  emit?.({ type: 'log', level: 'info', message: `[BF] Analisando página de login: ${parsed.href}` });

  try {
    const page = await httpGet(parsed.href, 8000);
    const html = page.body;

    // ── 1. Busca URL do Supabase (máxima prioridade) ──────────────
    const supabaseMatch = html.match(/https?:\/\/([a-z0-9-]+)\.supabase\.co/);
    if (supabaseMatch) {
      const supabaseAuthUrl = `https://${supabaseMatch[1]}.supabase.co/auth/v1/token?grant_type=password`;
      emit?.({ type: 'log', level: 'info', message: `[BF] Supabase detectado no bundle → ${supabaseAuthUrl}` });
      return { url: supabaseAuthUrl, type: 'supabase_token', detected: 'supabase' };
    }

    // ── 2. Detecta Next.js ────────────────────────────────────────
    const isNextJs = html.includes('__NEXT_DATA__') || html.includes('/_next/static') || html.includes('next/dist');

    // ── 3. Busca scripts externos e inspeciona o primeiro ─────────
    const scriptSrcs = [];
    const scriptRegex = /<script[^>]+src=["']([^"']+\.js[^"']*)["']/gi;
    let scriptMatch;
    while ((scriptMatch = scriptRegex.exec(html)) !== null) {
      let src = scriptMatch[1].split('?')[0];
      if (src.startsWith('//'))  src = 'https:' + src;
      else if (src.startsWith('/')) src = origin + src;
      else if (!src.startsWith('http')) src = origin + '/' + src;
      scriptSrcs.push(src);
      if (scriptSrcs.length >= 5) break; // limite: inspecionar só os primeiros 5
    }

    for (const scriptUrl of scriptSrcs) {
      try {
        const scriptRes = await httpGet(scriptUrl, 6000);
        const code = scriptRes.body;
        // Supabase URL no bundle
        const sbMatch = code.match(/https?:\/\/([a-z0-9-]+)\.supabase\.co/);
        if (sbMatch) {
          const supabaseAuthUrl = `https://${sbMatch[1]}.supabase.co/auth/v1/token?grant_type=password`;
          emit?.({ type: 'log', level: 'info', message: `[BF] Supabase encontrado em ${scriptUrl} → ${supabaseAuthUrl}` });
          return { url: supabaseAuthUrl, type: 'supabase_token', detected: 'supabase_bundle' };
        }
      } catch { /* continua */ }
    }

    // ── 4. Busca form action no HTML ──────────────────────────────
    const formMatch =
      html.match(/<form[^>]+action=["']([^"'#][^"']*)["'][^>]*method=["']post["']/i) ||
      html.match(/<form[^>]+method=["']post["'][^>]+action=["']([^"'#][^"']*)["']/i);
    if (formMatch) {
      let action = formMatch[1];
      if (!action.startsWith('http')) action = origin + (action.startsWith('/') ? '' : '/') + action;
      const type = detectEndpointType(action);
      emit?.({ type: 'log', level: 'info', message: `[BF] Form action detectado → ${action} (${type})` });
      return { url: action, type };
    }

    // ── 5. Busca chamada fetch/axios inline ───────────────────────
    const fetchMatch = html.match(/(?:fetch|axios\.post)\s*\(\s*['"`]([^'"`]*(?:login|auth|signin|session)[^'"`]*)['"`]/i);
    if (fetchMatch) {
      let apiUrl = fetchMatch[1];
      if (!apiUrl.startsWith('http')) apiUrl = origin + (apiUrl.startsWith('/') ? '' : '/') + apiUrl;
      emit?.({ type: 'log', level: 'info', message: `[BF] API call detectado no HTML → ${apiUrl}` });
      return { url: apiUrl, type: 'api_json', detected: 'fetch_inline' };
    }

    // ── 6. Next.js detectado → tentar NextAuth ────────────────────
    if (isNextJs) {
      const nextAuthUrl = `${origin}/api/auth/callback/credentials`;
      emit?.({ type: 'log', level: 'info', message: `[BF] Next.js detectado → tentando NextAuth: ${nextAuthUrl}` });
      return { url: nextAuthUrl, type: 'nextauth', detected: 'nextjs', origin };
    }

  } catch (err) {
    emit?.({ type: 'log', level: 'warn', message: `[BF] Falha ao inspecionar página: ${err.message}` });
  }

  // ── 7. Fallback: padrões comuns baseados no domínio ──────────────
  emit?.({ type: 'log', level: 'warn', message: `[BF] Usando padrão genérico: ${origin}/api/login` });
  return {
    url:       `${origin}/api/login`,
    type:      'api_json',
    detected:  'fallback',
    candidates: [
      `${origin}/api/login`,
      `${origin}/api/auth/login`,
      `${origin}/api/signin`,
      `${origin}/api/users/login`,
      raw, // também testa a URL original
    ],
  };
}

// ── Obtém CSRF token do NextAuth ─────────────────────────────────
async function getNextAuthCsrf(origin) {
  try {
    const res = await httpGet(`${origin}/api/auth/csrf`, 5000);
    if (res.status === 200) {
      const json = JSON.parse(res.body);
      const cookie = res.headers['set-cookie'];
      return {
        csrfToken: json.csrfToken || '',
        cookie: Array.isArray(cookie) ? cookie.join('; ') : (cookie || ''),
      };
    }
  } catch { /* csrf não disponível */ }
  return null;
}

// ── Monta payload e headers para cada tipo ───────────────────────
function buildPayload(credential, endpointType, csrfData) {
  if (endpointType === 'supabase_token' || endpointType === 'supabase_auth') {
    return {
      contentType: 'application/json',
      body: JSON.stringify({ email: credential.user, password: credential.pass }),
    };
  }

  if (endpointType === 'nextauth') {
    // NextAuth requer o csrfToken no body
    const params = new URLSearchParams({
      csrfToken: csrfData?.csrfToken || '',
      callbackUrl: '/',
      json: 'true',
      email: credential.user,
      username: credential.user,
      password: credential.pass,
    });
    return {
      contentType: 'application/x-www-form-urlencoded',
      body: params.toString(),
      csrfCookie: csrfData?.cookie || '',
    };
  }

  if (endpointType === 'api_json') {
    return {
      contentType: 'application/json',
      body: JSON.stringify({
        email:    credential.user,
        username: credential.user,
        login:    credential.user,
        password: credential.pass,
      }),
    };
  }

  // form-urlencoded genérico
  const params = new URLSearchParams({
    username: credential.user,
    email:    credential.user,
    login:    credential.user,
    password: credential.pass,
  });
  return { contentType: 'application/x-www-form-urlencoded', body: params.toString() };
}

// ── Detecta se a resposta indica sucesso de autenticação ─────────
// Muito mais preciso que a versão anterior — evita falsos positivos
function isSuccess(status, body, headers) {
  const contentType = (headers?.['content-type'] || '').toLowerCase();
  const setCookie   = headers?.['set-cookie'];
  const location    = headers?.['location'] || '';

  // ── Respostas 200/201 ──────────────────────────────────────────
  if (status === 200 || status === 201) {
    const isJson = contentType.includes('application/json') ||
                   body.trimStart().startsWith('{') ||
                   body.trimStart().startsWith('[');

    if (isJson) {
      try {
        const json = JSON.parse(body);

        // ── Falha explícita (erro no JSON) ────────────────────────
        if (json.error)      return false;
        if (json.error_code) return false;
        if (json.code === 'invalid_credentials') return false;
        if (json.code === 'invalid_login_credentials') return false;
        if (typeof json.message === 'string' &&
            /invalid|incorrect|wrong|unauthorized|bad credential|invalid password|not found|does not exist/i
            .test(json.message)) return false;
        if (typeof json.msg === 'string' &&
            /invalid|incorrect|wrong|unauthorized|bad/i.test(json.msg)) return false;
        if (typeof json.detail === 'string' &&
            /invalid|incorrect|wrong/i.test(json.detail)) return false;

        // ── Sucesso explícito ─────────────────────────────────────
        if (json.access_token)  return true;
        if (json.token)         return true;
        if (json.jwt)           return true;
        if (json.auth_token)    return true;
        if (json.id_token)      return true;
        if (json.refresh_token && json.access_token) return true;
        if (json.token_type?.toLowerCase() === 'bearer' && !json.error) return true;
        if (json.session?.access_token) return true;
        if (json.session?.user?.id)     return true;
        if (json.data?.session?.access_token) return true;
        if (json.user?.id && !json.error && !json.message) return true;
        // NextAuth success: { ok: true, url: '/dashboard' }
        if (json.ok === true && json.url && !json.error) return true;
        // Generic: { success: true, token: '...' }
        if (json.success === true && (json.token || json.data?.token)) return true;

        // JSON sem indicador de token → não é sucesso
        return false;
      } catch { /* JSON inválido → não é sucesso */ return false; }
    }

    // ── Resposta HTML ─────────────────────────────────────────────
    if (contentType.includes('text/html')) {
      // Verificar se há cookie de sessão sendo definido
      if (setCookie) {
        const cookies = Array.isArray(setCookie) ? setCookie : [setCookie];
        const hasAuthCookie = cookies.some(c =>
          /session|auth[-_]?token|jwt|access[-_]?token|next-auth\.session/i.test(c)
        );
        if (hasAuthCookie) return true;
      }
      // HTML como resposta a POST é geralmente a página de login re-renderizada (falha)
      return false;
    }

    // ── Resposta não-JSON e não-HTML ──────────────────────────────
    if (body.includes('access_token') || body.includes('"token"')) return true;
    return false;
  }

  // ── Redirecionamento: sucesso se não volta para página de login ──
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

// ── Realiza uma tentativa de login ────────────────────────────────
async function doAttempt(parsedUrl, credential, endpointType, anonKey, delayMs, csrfData) {
  if (delayMs > 0) await new Promise(r => setTimeout(r, delayMs));

  return new Promise(resolve => {
    const t0  = Date.now();
    const lib = parsedUrl.protocol === 'https:' ? https : http;
    const { contentType, body, csrfCookie } = buildPayload(credential, endpointType, csrfData);
    const bodyBuf = Buffer.from(body, 'utf8');

    const reqHeaders = {
      'User-Agent':     'Mozilla/5.0 (compatible; SupabaseGuard-BruteforceTest/2.0; authorized-security-test)',
      'Accept':         'application/json, text/html, */*',
      'Content-Type':   contentType,
      'Content-Length': bodyBuf.length,
      'X-Security-Test': '1',
      'Connection':     'keep-alive',
      'Referer':        parsedUrl.origin + '/login',
      'Origin':         parsedUrl.origin,
    };

    // Cookie do CSRF (NextAuth)
    if (csrfCookie) {
      reqHeaders['Cookie'] = csrfCookie;
    }

    // apikey do Supabase
    if (anonKey && (endpointType === 'supabase_token' || endpointType === 'supabase_auth')) {
      reqHeaders['apikey']        = anonKey;
      reqHeaders['Authorization'] = `Bearer ${anonKey}`;
    }

    const req = lib.request({
      hostname: parsedUrl.hostname,
      port:     parsedUrl.port || (parsedUrl.protocol === 'https:' ? 443 : 80),
      path:     parsedUrl.pathname + (parsedUrl.search || ''),
      method:   'POST',
      headers:  reqHeaders,
      timeout:  12000,
    }, res => {
      let data = '';
      res.on('data', d => { if (data.length < 4096) data += d; });
      res.on('end', () => {
        const lat     = Date.now() - t0;
        const status  = res.statusCode;
        const success = isSuccess(status, data, res.headers);
        const blocked = status === 429 || (status === 403 && !success) || status === 423;
        const waf     = (status === 403 || status === 406 || status === 429) && (
          data.toLowerCase().includes('cloudflare') ||
          data.toLowerCase().includes('waf')        ||
          data.toLowerCase().includes('blocked')    ||
          data.toLowerCase().includes('captcha')    ||
          (res.headers?.['cf-ray'] !== undefined)
        );
        resolve({
          ok: true, status, lat, success, blocked, waf,
          user: credential.user, pass: credential.pass,
          snippet: data.slice(0, 200),
          contentType: res.headers['content-type'] || '',
          setCookie: res.headers['set-cookie'] || null,
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
      ok: false, error: e.code || 'CONN_ERR', lat: Date.now() - t0,
      user: credential.user, pass: credential.pass,
    }));

    req.write(bodyBuf);
    req.end();
  });
}

// ── Score de segurança anti-bruteforce ───────────────────────────
function calcSecurityScore(results, hits) {
  if (!results.length) return { score: 0, grade: 'N/A', color: '#888', label: 'Sem dados', summary: '' };

  const blocked   = results.filter(r => r.blocked).length;
  const wafHits   = results.filter(r => r.waf).length;
  const sqlProbes = results.filter(r => r.user && (r.user.includes("'") || r.user.includes('"'))).length;
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
  if      (s >= 90) { grade = 'A+'; color = '#22c55e'; label = 'Fortemente Protegido';  summary = 'Excelente. O servidor detectou e bloqueou o ataque de forma eficiente. Rate limiting e/ou WAF estão ativos.'; }
  else if (s >= 78) { grade = 'A';  color = '#22c55e'; label = 'Bem Protegido';          summary = 'Rate limiting ativo. A maioria das tentativas foi bloqueada. Pequenas melhorias recomendadas.'; }
  else if (s >= 65) { grade = 'B+'; color = '#84cc16'; label = 'Proteção Boa';           summary = 'Proteção detectada, mas não bloqueia todas as tentativas. Reforce o rate limiting.'; }
  else if (s >= 52) { grade = 'B';  color = '#a3e635'; label = 'Proteção Adequada';      summary = 'Alguma proteção existe. Recomendado endurecer limites de tentativas e implementar lockout.'; }
  else if (s >= 38) { grade = 'C';  color = '#eab308'; label = 'Proteção Fraca';         summary = 'Rate limiting insuficiente. Ataques prolongados podem ter sucesso. Ação recomendada.'; }
  else if (s >= 22) { grade = 'D';  color = '#f97316'; label = 'Vulnerável';             summary = 'Sem proteção efetiva. O endpoint aceita tentativas praticamente ilimitadas. Alto risco.'; }
  else              { grade = 'F';  color = '#ef4444'; label = 'Crítico';                summary = 'Nenhuma proteção anti-brute-force detectada. Vulnerabilidade crítica — ação imediata necessária.'; }

  return { score: s, grade, color, label, summary };
}

// ── Recomendações baseadas nos resultados ────────────────────────
function buildRecommendations(results, hits, endpointType) {
  const blocked    = results.filter(r => r.blocked).length;
  const blockRate  = results.length ? blocked / results.length : 0;
  const sqlProbes  = results.filter(r => r.user && r.user.includes("'")).length;
  const sqlBlocked = results.filter(r => r.user && r.user.includes("'") && r.blocked).length;
  const items = [];

  if (hits.length > 0) {
    items.push({
      priority: 'P0', icon: '🚨',
      title: 'URGENTE: Credenciais comprometidas — ação imediata',
      body: `${hits.length} par(es) de credenciais válido(s) encontrado(s) no teste. Troque as senhas agora, invalide todos os tokens de sessão ativos e ative notificações de login suspeito.`,
    });
  }

  if (blockRate < 0.4) {
    items.push({
      priority: 'P1', icon: '🚦',
      title: 'Implementar Rate Limiting agressivo',
      body: 'Configure no máximo 5 tentativas de login por IP a cada 15 minutos. Use express-rate-limit + Redis. Retorne 429 com Retry-After header. Bloqueie IPs temporariamente após exceder o limite.',
    });
  }

  if (blockRate < 0.6) {
    items.push({
      priority: 'P1', icon: '🔐',
      title: 'Habilitar bloqueio progressivo de conta',
      body: 'Após 3 tentativas falhas: delay progressivo. Após 5: bloqueio de 15 min. Após 10: bloqueio de 1h + notificação por e-mail. Implemente via Supabase Auth Hooks ou middleware dedicado.',
    });
  }

  items.push({
    priority: 'P1', icon: '📱',
    title: 'Implementar autenticação multi-fator (MFA/TOTP)',
    body: 'MFA torna força bruta ineficaz mesmo com senha correta. Supabase suporta TOTP (Google Authenticator). Ative como obrigatório para contas administrativas e opcional para usuários finais.',
  });

  if (sqlProbes > 0 && sqlBlocked < sqlProbes) {
    items.push({
      priority: 'P1', icon: '💉',
      title: 'Reforçar proteção contra SQL/NoSQL Injection',
      body: 'Tentativas de SQL Injection no campo de login não foram todas bloqueadas. Verifique que o backend usa queries parametrizadas, sanitiza entradas e tem WAF configurado para regras de injeção.',
    });
  }

  items.push({
    priority: 'P2', icon: '🔍',
    title: 'Implementar detecção de anomalias de autenticação',
    body: 'Monitore padrões suspeitos: múltiplas tentativas do mesmo IP, sequências rápidas, horários incomuns, user agents idênticos. Configure alertas em tempo real via Supabase Hooks + Slack/PagerDuty.',
  });

  items.push({
    priority: 'P2', icon: '🌐',
    title: 'Considerar CAPTCHA adaptativo no endpoint de login',
    body: 'Ative CAPTCHA (hCaptcha, Cloudflare Turnstile) que dispara automaticamente ao detectar padrões de bot. Supabase suporta CAPTCHA nativo — habilite nas configurações de Auth.',
  });

  items.push({
    priority: 'P3', icon: '📊',
    title: 'Configurar SIEM e alertas de login',
    body: 'Integre logs de autenticação com Datadog, Grafana ou similar. Crie alertas para: >10 falhas/minuto por IP, login de geo-localização nova, tentativas fora do horário comercial.',
  });

  return items.slice(0, 6);
}

// ── Criador do teste ─────────────────────────────────────────────
function createBruteforceTest(config) {
  const emitter = new EventEmitter();
  emitter.setMaxListeners(50);

  const run = async () => {
    // ── 1. Resolver endpoint real ─────────────────────────────────
    const logEmit = (d) => emitter.emit('log', d);

    const resolved = await resolveLoginEndpoint(config.loginUrl, logEmit);
    let loginUrl     = resolved.url;
    let endpointType = resolved.type;

    emitter.emit('resolved', {
      originalUrl:  config.loginUrl,
      resolvedUrl:  loginUrl,
      endpointType,
      detected:     resolved.detected,
    });

    // ── 2. Para NextAuth: obter CSRF token ────────────────────────
    let csrfData = null;
    if (endpointType === 'nextauth' && resolved.origin) {
      emitter.emit('log', { type: 'log', level: 'info', message: '[BF] Obtendo CSRF token do NextAuth...' });
      csrfData = await getNextAuthCsrf(resolved.origin || new URL(loginUrl).origin);
      if (csrfData?.csrfToken) {
        emitter.emit('log', { type: 'log', level: 'info', message: `[BF] CSRF token obtido: ${csrfData.csrfToken.slice(0, 12)}...` });
      }
    }

    // ── 3. Parsear URL do endpoint ────────────────────────────────
    let parsed;
    try {
      const raw = loginUrl.startsWith('http') ? loginUrl : 'https://' + loginUrl;
      parsed = new URL(raw);
    } catch {
      emitter.emit('error', 'URL de login inválida após resolução');
      return;
    }

    const credentials   = config.credentials?.length ? config.credentials : BUILTIN_WORDLIST;
    const delayMs       = Math.max(50, Math.min(2000, config.delayMs ?? 150));
    const stopOnSuccess = config.stopOnSuccess !== false;

    emitter.emit('start', {
      target:          parsed.origin + parsed.pathname,
      originalTarget:  config.loginUrl,
      total:           credentials.length,
      endpointType,
      detected:        resolved.detected,
      delayMs,
    });

    const results     = [];
    const hits        = [];
    let blockedCount  = 0;
    let consecutiveBlocks = 0;

    // ── 4. Loop de tentativas ─────────────────────────────────────
    for (let i = 0; i < credentials.length; i++) {
      if (config.signal?.aborted) {
        emitter.emit('aborted', { done: i, total: credentials.length });
        break;
      }

      // Para NextAuth com múltiplos candidatos, tentar outros se 404
      const cred   = credentials[i];
      const result = await doAttempt(parsed, cred, endpointType, config.anonKey, delayMs, csrfData);
      results.push(result);

      if (result.success) hits.push({ ...result, index: i });
      if (result.blocked) { blockedCount++; consecutiveBlocks++; }
      else consecutiveBlocks = 0;

      emitter.emit('attempt', {
        index:        i,
        total:        credentials.length,
        ...result,
        hitsTotal:    hits.length,
        blockedTotal: blockedCount,
        endpointType,
      });

      if (result.success && stopOnSuccess) {
        emitter.emit('hit_found', { ...result, index: i });
        break;
      }

      // Servidor bloqueou consistentemente — confirmar proteção e encerrar
      if (consecutiveBlocks >= 25) {
        emitter.emit('blocked_hard', {
          message: `Servidor bloqueou ${consecutiveBlocks} tentativas consecutivas — proteção anti-brute-force ativa e eficaz!`,
          total: i + 1,
        });
        break;
      }
    }

    const security        = calcSecurityScore(results, hits);
    const recommendations = buildRecommendations(results, hits, endpointType);
    const ok              = results.filter(r => r.ok);

    emitter.emit('complete', {
      hits,
      security,
      recommendations,
      stats: {
        total:     results.length,
        success:   hits.length,
        blocked:   blockedCount,
        errors:    results.filter(r => !r.ok).length,
        waf:       results.filter(r => r.waf).length,
        meanLat:   ok.length ? Math.round(ok.reduce((a, r) => a + (r.lat || 0), 0) / ok.length) : 0,
      },
      target:       loginUrl,
      originalTarget: config.loginUrl,
      endpointType,
      detected:     resolved.detected,
      timestamp:    new Date().toISOString(),
    });
  };

  return { emitter, run };
}

module.exports = { createBruteforceTest, BUILTIN_WORDLIST, parseWordlist };
