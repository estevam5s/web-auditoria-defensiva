'use strict';

/* ═══════════════════════════════════════════════════════════════════
   BRUTE FORCE RESILIENCE TEST ENGINE
   Testa a resistência de endpoints de login contra ataques de força
   bruta. Detecta rate limiting, bloqueio de conta e credenciais fracas.
   Usa apenas módulos nativos do Node.js.
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
    .slice(0, 1000)            // cap em 1000 entradas por segurança
    .map(line => {
      const colonIdx = line.indexOf(':');
      if (colonIdx > 0 && colonIdx < line.length - 1) {
        return { user: line.slice(0, colonIdx), pass: line.slice(colonIdx + 1) };
      }
      return { user: defaultUser, pass: line };
    });
}

// ── Detecta o tipo de endpoint de login ─────────────────────────
function detectEndpointType(urlStr) {
  if (urlStr.includes('/auth/v1/token'))  return 'supabase_token';
  if (urlStr.includes('/auth/v1/'))       return 'supabase_auth';
  if (urlStr.includes('/api/auth'))       return 'api_json';
  if (urlStr.includes('/api/login'))      return 'api_json';
  if (urlStr.includes('.json'))           return 'api_json';
  return 'form';
}

// ── Monta payload e headers para cada tipo ───────────────────────
function buildPayload(credential, endpointType) {
  if (endpointType === 'supabase_token' || endpointType === 'supabase_auth') {
    return {
      contentType: 'application/json',
      body: JSON.stringify({ email: credential.user, password: credential.pass }),
    };
  }
  if (endpointType === 'api_json') {
    return {
      contentType: 'application/json',
      body: JSON.stringify({ username: credential.user, email: credential.user, password: credential.pass }),
    };
  }
  // form-urlencoded genérico
  const body = `username=${encodeURIComponent(credential.user)}&email=${encodeURIComponent(credential.user)}&password=${encodeURIComponent(credential.pass)}`;
  return { contentType: 'application/x-www-form-urlencoded', body };
}

// ── Detecta se a resposta indica sucesso de autenticação ─────────
function isSuccess(status, body, headers) {
  if (status === 200 || status === 201) {
    try {
      const json = JSON.parse(body);
      if (json.access_token || json.token || json.jwt || json.auth_token) return true;
      if (json.session && (json.session.access_token || json.session.user)) return true;
      if (json.data && json.data.session) return true;
      if (json.user && (json.user.id || json.user.email) && !json.error) return true;
    } catch { /* not JSON — check raw */ }
    if (body.includes('access_token') || body.includes('Bearer ')) return true;
    // Form response with no error keyword is likely success
    if (!body.includes('Invalid') && !body.includes('incorrect') &&
        !body.includes('error') && !body.includes('fail') && body.length < 500) return true;
  }
  if ((status === 302 || status === 303) && headers && headers.location) {
    const loc = (headers.location || '').toLowerCase();
    return !loc.includes('login') && !loc.includes('signin') &&
           !loc.includes('error') && !loc.includes('fail');
  }
  return false;
}

// ── Realiza uma tentativa de login ────────────────────────────────
async function doAttempt(parsedUrl, credential, endpointType, anonKey, delayMs) {
  if (delayMs > 0) await new Promise(r => setTimeout(r, delayMs));

  return new Promise(resolve => {
    const t0  = Date.now();
    const lib = parsedUrl.protocol === 'https:' ? https : http;
    const { contentType, body } = buildPayload(credential, endpointType);
    const bodyBuf = Buffer.from(body, 'utf8');

    const headers = {
      'User-Agent':      'SupabaseGuard-BruteforceTest/1.0 (authorized-security-test)',
      'Accept':          'application/json, text/html, */*',
      'Content-Type':    contentType,
      'Content-Length':  bodyBuf.length,
      'X-Security-Test': '1',
      'Connection':      'keep-alive',
    };

    if (anonKey && (endpointType === 'supabase_token' || endpointType === 'supabase_auth')) {
      headers['apikey']        = anonKey;
      headers['Authorization'] = `Bearer ${anonKey}`;
    }

    const req = lib.request({
      hostname: parsedUrl.hostname,
      port:     parsedUrl.port || (parsedUrl.protocol === 'https:' ? 443 : 80),
      path:     parsedUrl.pathname + (parsedUrl.search || ''),
      method:   'POST',
      headers,
      timeout:  10000,
    }, res => {
      let data = '';
      res.on('data', d => { if (data.length < 2048) data += d; });
      res.on('end', () => {
        const lat     = Date.now() - t0;
        const status  = res.statusCode;
        const success = isSuccess(status, data, res.headers);
        const blocked = status === 429 || (status === 403 && !success);
        const waf     = status === 403 && (
          data.includes('cloudflare') || data.includes('Cloudflare') ||
          data.includes('WAF') || data.includes('blocked') || data.includes('captcha')
        );
        resolve({
          ok: true, status, lat, success, blocked, waf,
          user: credential.user, pass: credential.pass,
          snippet: data.slice(0, 120),
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

  // Se encontrou credenciais, é automaticamente grau F
  if (hits.length > 0) {
    return {
      score: 0, grade: 'F', color: '#ef4444',
      label: 'CREDENCIAIS EXPOSTAS',
      summary: `${hits.length} par(es) de credencial(is) válido(s) encontrado(s)! Altere senhas imediatamente e invalide todas as sessões.`,
    };
  }

  let s = 100;

  // Rate limiting
  if      (blockRate >= 0.7) s = Math.min(s, 100);       // excelente — bloqueou a maioria
  else if (blockRate >= 0.4) s -= 10;
  else if (blockRate >= 0.2) s -= 25;
  else if (blockRate >= 0.05) s -= 40;
  else                        s -= 55;                     // sem bloqueio algum

  // WAF bonus
  if (wafHits > 0) s = Math.min(100, s + 5);

  // SQL injection bloqueado
  if (sqlProbes > 0 && sqlBlocked === sqlProbes) s = Math.min(100, s + 5);
  else if (sqlProbes > 0 && sqlBlocked === 0)    s -= 10; // não bloqueou SQL injection

  // Punição por erros de conexão massivos (servidor derrubou / ficou instável)
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
  /* config:
     - loginUrl:      string
     - credentials:   [{user, pass}]   (ou BUILTIN_WORDLIST se omitido)
     - anonKey:       string | null
     - delayMs:       number (ms entre tentativas, min 50)
     - stopOnSuccess: bool (default true)
     - signal:        AbortSignal
  */
  const emitter = new EventEmitter();
  emitter.setMaxListeners(30);

  const run = async () => {
    let parsed;
    try {
      const raw = config.loginUrl.startsWith('http') ? config.loginUrl : `https://${config.loginUrl}`;
      parsed = new URL(raw);
    } catch {
      emitter.emit('error', 'URL de login inválida');
      return;
    }

    const endpointType  = detectEndpointType(config.loginUrl);
    const credentials   = config.credentials?.length ? config.credentials : BUILTIN_WORDLIST;
    const delayMs       = Math.max(50, Math.min(2000, config.delayMs ?? 150));
    const stopOnSuccess = config.stopOnSuccess !== false;

    emitter.emit('start', {
      target:       parsed.origin + parsed.pathname,
      total:        credentials.length,
      endpointType,
      delayMs,
    });

    const results     = [];
    const hits        = [];
    let blockedCount  = 0;
    let consecutiveBlocks = 0;

    for (let i = 0; i < credentials.length; i++) {
      if (config.signal?.aborted) {
        emitter.emit('aborted', { done: i, total: credentials.length });
        break;
      }

      const cred   = credentials[i];
      const result = await doAttempt(parsed, cred, endpointType, config.anonKey, delayMs);
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
      target:    config.loginUrl,
      timestamp: new Date().toISOString(),
    });
  };

  return { emitter, run };
}

module.exports = { createBruteforceTest, BUILTIN_WORDLIST, parseWordlist };
