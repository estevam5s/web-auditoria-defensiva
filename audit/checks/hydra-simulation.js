/*  ═══════════════════════════════════════════════════════════════════
    HYDRA SIMULATION — Credential Attack Detection & Defense Check
    Simulates Hydra-style credential stuffing, HTTP Basic Auth attacks,
    timing-based enumeration, and default credential testing to verify
    if the target is properly protected against automated attacks.
    This is a DEFENSIVE check — it tests if protections are in place.
    ═══════════════════════════════════════════════════════════════════ */

const https = require('https');
const http  = require('http');

// Common credential pairs used in credential stuffing attacks
const CREDENTIAL_PAIRS = [
  { user: 'admin', pass: 'admin' },
  { user: 'admin', pass: 'password' },
  { user: 'admin', pass: '123456' },
  { user: 'admin', pass: 'admin123' },
  { user: 'root', pass: 'root' },
  { user: 'root', pass: 'toor' },
  { user: 'root', pass: 'password' },
  { user: 'test', pass: 'test' },
  { user: 'guest', pass: 'guest' },
  { user: 'user', pass: 'user' },
  { user: 'administrator', pass: 'administrator' },
  { user: 'admin', pass: '' },
  { user: '', pass: '' },
  { user: 'sa', pass: '' },
  { user: 'postgres', pass: 'postgres' },
  { user: 'mysql', pass: 'mysql' },
  { user: 'supabase', pass: 'supabase' },
  { user: 'api', pass: 'api' },
  { user: 'dev', pass: 'dev' },
  { user: 'test', pass: '1234' },
];

// Common usernames for enumeration testing
const TEST_USERNAMES = [
  'admin@admin.com',
  'admin@example.com',
  'test@test.com',
  'user@user.com',
  'root@root.com',
  'admin@supabase.io',
];

// Common login endpoints across frameworks
const LOGIN_ENDPOINTS = [
  { path: '/admin', method: 'GET', type: 'basic-auth' },
  { path: '/admin/login', method: 'POST', type: 'form' },
  { path: '/administrator', method: 'GET', type: 'basic-auth' },
  { path: '/wp-login.php', method: 'POST', type: 'form' },
  { path: '/wp-admin', method: 'GET', type: 'basic-auth' },
  { path: '/login', method: 'POST', type: 'form' },
  { path: '/signin', method: 'POST', type: 'form' },
  { path: '/auth/login', method: 'POST', type: 'form' },
  { path: '/api/auth/login', method: 'POST', type: 'json' },
  { path: '/api/login', method: 'POST', type: 'json' },
  { path: '/phpmyadmin', method: 'GET', type: 'basic-auth' },
  { path: '/pma', method: 'GET', type: 'basic-auth' },
  { path: '/cpanel', method: 'GET', type: 'basic-auth' },
  { path: '/panel', method: 'GET', type: 'basic-auth' },
];

// Default system credentials
const DEFAULT_SYSTEM_CREDS = [
  { system: 'PHP MyAdmin', path: '/phpmyadmin/', user: 'root', pass: '' },
  { system: 'PHP MyAdmin', path: '/phpmyadmin/', user: 'root', pass: 'root' },
  { system: 'WordPress', path: '/wp-login.php', user: 'admin', pass: 'admin' },
  { system: 'WordPress', path: '/wp-login.php', user: 'admin', pass: 'password' },
  { system: 'cPanel', path: '/cpanel/', user: 'admin', pass: 'admin' },
  { system: 'Grafana', path: '/grafana/login', user: 'admin', pass: 'admin' },
  { system: 'Jenkins', path: '/jenkins/', user: 'admin', pass: 'admin' },
  { system: 'RabbitMQ', path: '/rabbitmq/', user: 'guest', pass: 'guest' },
  { system: 'Kibana', path: '/kibana/', user: 'elastic', pass: 'changeme' },
  { system: 'Portainer', path: '/portainer/', user: 'admin', pass: 'admin' },
];

function buildBasicAuthHeader(user, pass) {
  return 'Basic ' + Buffer.from(`${user}:${pass}`).toString('base64');
}

function httpRequest(rawUrl, opts = {}) {
  return new Promise(resolve => {
    const t0 = Date.now();
    let done = false;
    const finish = d => { if (!done) { done = true; resolve({ ...d, ms: Date.now() - t0 }); } };

    try {
      const u = new URL(rawUrl);
      const lib = u.protocol === 'https:' ? https : http;
      const method = opts.method || 'GET';
      const body = opts.body ? JSON.stringify(opts.body) : null;

      const reqOpts = {
        hostname: u.hostname,
        port: u.port || (u.protocol === 'https:' ? 443 : 80),
        path: u.pathname + u.search,
        method,
        headers: {
          'User-Agent': 'SupabaseGuard-SecurityAudit/3.1',
          'Accept': 'application/json, text/html, */*',
          ...(opts.headers || {})
        },
        rejectUnauthorized: false,
        timeout: opts.timeout || 5000
      };

      if (body) {
        reqOpts.headers['Content-Type'] = 'application/json';
        reqOpts.headers['Content-Length'] = Buffer.byteLength(body);
      }

      const req = lib.request(reqOpts, res => {
        let data = '';
        res.on('data', c => data += c);
        res.on('end', () => {
          let json = null;
          try { json = JSON.parse(data); } catch {}
          finish({ status: res.statusCode, headers: res.headers, body: data, json, error: null });
        });
      });

      req.on('error', e => finish({ status: 0, headers: {}, body: '', json: null, error: e.message }));
      req.on('timeout', () => { req.destroy(); finish({ status: 0, headers: {}, body: '', json: null, error: 'timeout' }); });
      if (body) req.write(body);
      req.end();
    } catch (e) {
      finish({ status: 0, headers: {}, body: '', json: null, error: e.message });
    }
  });
}

async function checkHydraSimulation(config, emit) {
  const baseUrl = config.projectUrl;
  const results = [];

  if (emit) emit({ type: 'progress-detail', message: '🔱 Hydra: Iniciando simulação de ataque de credenciais...' });

  // ── 1. HTTP Basic Auth Credential Testing ────────────────────────
  if (emit) emit({ type: 'progress-detail', message: '🔑 Hydra: Testando autenticação HTTP Basic...' });

  const basicAuthEndpoints = [];
  const basicAuthVulnerable = [];

  for (const endpoint of LOGIN_ENDPOINTS.filter(e => e.type === 'basic-auth').slice(0, 5)) {
    const url = baseUrl + endpoint.path;
    const firstRes = await httpRequest(url, { timeout: 4000 });

    if (firstRes.status === 401 && firstRes.headers['www-authenticate']) {
      basicAuthEndpoints.push({ path: endpoint.path, authType: firstRes.headers['www-authenticate'] });

      // Try common credentials
      for (const cred of CREDENTIAL_PAIRS.slice(0, 10)) {
        const res = await httpRequest(url, {
          headers: { 'Authorization': buildBasicAuthHeader(cred.user, cred.pass) },
          timeout: 4000
        });

        if (res.status === 200 || res.status === 302) {
          basicAuthVulnerable.push({
            path: endpoint.path,
            credentials: `${cred.user}:${cred.pass}`,
            status: res.status
          });
          break;
        }

        if (res.status === 429) break; // Rate limited — good
        await new Promise(r => setTimeout(r, 150));
      }
    }
  }

  if (basicAuthVulnerable.length > 0) {
    results.push({
      check: '🔱 Hydra — HTTP Basic Auth',
      status: 'FAIL',
      severity: 'critical',
      message: `VULNERÁVEL! ${basicAuthVulnerable.length} endpoint(s) com credenciais padrão aceitas via HTTP Basic Auth!`,
      details: {
        vulnerable: basicAuthVulnerable,
        recommendation: 'URGENTE: Altere imediatamente as credenciais padrão. Implemente autenticação forte.'
      }
    });
  } else if (basicAuthEndpoints.length > 0) {
    results.push({
      check: '🔱 Hydra — HTTP Basic Auth',
      status: 'WARN',
      severity: 'medium',
      message: `${basicAuthEndpoints.length} endpoint(s) com HTTP Basic Auth detectado(s). Credenciais comuns testadas não funcionaram.`,
      details: {
        endpoints: basicAuthEndpoints,
        recommendation: 'HTTP Basic Auth expõe credenciais em base64. Prefira autenticação moderna (OAuth2, JWT).'
      }
    });
  } else {
    results.push({
      check: '🔱 Hydra — HTTP Basic Auth',
      status: 'PASS',
      severity: 'info',
      message: 'Nenhum endpoint HTTP Basic Auth encontrado ou protegido adequadamente.',
      details: { tested: LOGIN_ENDPOINTS.filter(e => e.type === 'basic-auth').length }
    });
  }

  // ── 2. Username Enumeration via Timing Attack ─────────────────────
  if (emit) emit({ type: 'progress-detail', message: '⏱ Hydra: Testando enumeração de usuários por timing...' });

  const timingResults = [];
  const timingEndpoints = [
    `${baseUrl}/auth/v1/token?grant_type=password`,
    `${baseUrl}/auth/v1/recover`,
  ];

  for (const ep of timingEndpoints) {
    const validTimes = [];
    const invalidTimes = [];

    // Test with realistic emails
    for (const email of TEST_USERNAMES.slice(0, 3)) {
      const res = await httpRequest(ep, {
        method: 'POST',
        body: { email, password: 'WrongPassword123!@#' },
        timeout: 5000
      });
      if (res.ms > 0) validTimes.push(res.ms);
      if (res.status === 429) break;
      await new Promise(r => setTimeout(r, 200));
    }

    // Test with clearly invalid emails
    for (let i = 0; i < 3; i++) {
      const res = await httpRequest(ep, {
        method: 'POST',
        body: { email: `invalid_${Date.now()}_${i}@xyznotreal.local`, password: 'WrongPassword123!@#' },
        timeout: 5000
      });
      if (res.ms > 0) invalidTimes.push(res.ms);
      await new Promise(r => setTimeout(r, 200));
    }

    if (validTimes.length > 0 && invalidTimes.length > 0) {
      const avgValid = validTimes.reduce((a, b) => a + b, 0) / validTimes.length;
      const avgInvalid = invalidTimes.reduce((a, b) => a + b, 0) / invalidTimes.length;
      const diff = Math.abs(avgValid - avgInvalid);
      const ratioPercent = avgInvalid > 0 ? Math.round((diff / avgInvalid) * 100) : 0;

      timingResults.push({
        endpoint: ep,
        avgValidMs: Math.round(avgValid),
        avgInvalidMs: Math.round(avgInvalid),
        diffMs: Math.round(diff),
        timingDiscrepancyPercent: ratioPercent,
        vulnerable: ratioPercent > 50 && diff > 200
      });
    }
  }

  const timingVulnerable = timingResults.filter(t => t.vulnerable);

  if (timingVulnerable.length > 0) {
    results.push({
      check: '⏱ Hydra — Username Enumeration (Timing)',
      status: 'WARN',
      severity: 'medium',
      message: `Possível enumeração de usuários via timing attack em ${timingVulnerable.length} endpoint(s). Diferença de tempo detectada.`,
      details: {
        endpoints: timingVulnerable,
        allResults: timingResults,
        recommendation: 'Normalize o tempo de resposta para usuários válidos e inválidos para prevenir enumeração por timing.'
      }
    });
  } else {
    results.push({
      check: '⏱ Hydra — Username Enumeration (Timing)',
      status: 'PASS',
      severity: 'info',
      message: 'Nenhuma discrepância significativa de timing detectada. Proteção contra enumeração por timing parece adequada.',
      details: { results: timingResults }
    });
  }

  // ── 3. Default System Credentials ────────────────────────────────
  if (emit) emit({ type: 'progress-detail', message: '🖥️ Hydra: Verificando credenciais padrão de sistemas...' });

  const defaultCredVulnerable = [];
  const defaultCredFound = [];

  for (const cred of DEFAULT_SYSTEM_CREDS) {
    const url = baseUrl + cred.path;
    const res = await httpRequest(url, { timeout: 4000 });

    if (res.status !== 0 && res.status !== 404) {
      defaultCredFound.push({ system: cred.system, path: cred.path, status: res.status });

      if (res.status === 401 || res.status === 200) {
        // Try basic auth
        const authRes = await httpRequest(url, {
          headers: { 'Authorization': buildBasicAuthHeader(cred.user, cred.pass) },
          timeout: 4000
        });

        if (authRes.status === 200 || authRes.status === 302) {
          defaultCredVulnerable.push({
            system: cred.system,
            path: cred.path,
            credentials: `${cred.user}:${cred.pass}`,
            status: authRes.status
          });
        }

        // Also try POST form
        if (cred.path.includes('login') || cred.path.includes('wp-')) {
          const formRes = await httpRequest(url, {
            method: 'POST',
            body: { username: cred.user, password: cred.pass, log: cred.user, pwd: cred.pass },
            timeout: 4000
          });
          if (formRes.status === 200 && formRes.body && formRes.body.includes('dashboard')) {
            defaultCredVulnerable.push({
              system: cred.system,
              path: cred.path,
              method: 'POST',
              credentials: `${cred.user}:${cred.pass}`,
              status: formRes.status
            });
          }
        }
      }
    }
    await new Promise(r => setTimeout(r, 100));
  }

  if (defaultCredVulnerable.length > 0) {
    results.push({
      check: '🖥️ Hydra — Default System Credentials',
      status: 'FAIL',
      severity: 'critical',
      message: `CRÍTICO! ${defaultCredVulnerable.length} sistema(s) com credenciais padrão aceitas!`,
      details: {
        vulnerable: defaultCredVulnerable,
        recommendation: 'URGENTE: Altere imediatamente todas as credenciais padrão de sistemas instalados.'
      }
    });
  } else if (defaultCredFound.length > 0) {
    results.push({
      check: '🖥️ Hydra — Default System Credentials',
      status: 'WARN',
      severity: 'high',
      message: `${defaultCredFound.length} sistema(s) encontrado(s) exposto(s). Credenciais padrão não funcionaram mas sistemas devem ser protegidos.`,
      details: {
        exposedSystems: defaultCredFound,
        recommendation: 'Sistemas de administração detectados públicos. Restrinja acesso por IP ou VPN.'
      }
    });
  } else {
    results.push({
      check: '🖥️ Hydra — Default System Credentials',
      status: 'PASS',
      severity: 'info',
      message: 'Nenhum sistema com credenciais padrão detectado ou sistemas não acessíveis.',
      details: { systemsTested: DEFAULT_SYSTEM_CREDS.length }
    });
  }

  // ── 4. Credential Stuffing Detection ─────────────────────────────
  if (emit) emit({ type: 'progress-detail', message: '🎭 Hydra: Testando proteção contra credential stuffing...' });

  const stuffingEndpoint = `${baseUrl}/auth/v1/token?grant_type=password`;
  const stuffingResults = [];
  let stuffingRateLimited = false;

  // Simulate credential stuffing with rapid requests
  for (let i = 0; i < 8; i++) {
    const cred = CREDENTIAL_PAIRS[i % CREDENTIAL_PAIRS.length];
    const res = await httpRequest(stuffingEndpoint, {
      method: 'POST',
      body: { email: `stuffing${i}@victim.example.com`, password: cred.pass },
      timeout: 4000
    });

    stuffingResults.push({ status: res.status, ms: res.ms });

    if (res.status === 429) {
      stuffingRateLimited = true;
      break;
    }

    await new Promise(r => setTimeout(r, 80)); // Rapid fire
  }

  const allSuccess = stuffingResults.filter(r => r.status === 200).length;

  if (allSuccess > 0) {
    results.push({
      check: '🎭 Hydra — Credential Stuffing',
      status: 'FAIL',
      severity: 'critical',
      message: `${allSuccess} credencial(is) testada(s) resultou(ram) em login bem-sucedido durante simulação de credential stuffing!`,
      details: { successfulLogins: allSuccess, recommendation: 'URGENTE: Implemente proteção contra credential stuffing (CAPTCHA, device fingerprinting, anomaly detection).' }
    });
  } else if (stuffingRateLimited) {
    results.push({
      check: '🎭 Hydra — Credential Stuffing',
      status: 'PASS',
      severity: 'info',
      message: 'Rate limiting detectado durante simulação de credential stuffing — proteção ativa.',
      details: { requestsTested: stuffingResults.length, rateLimitedAt: stuffingResults.length }
    });
  } else {
    results.push({
      check: '🎭 Hydra — Credential Stuffing',
      status: 'WARN',
      severity: 'medium',
      message: `${stuffingResults.length} requisições de credential stuffing enviadas sem rate limiting — sistema potencialmente vulnerável.`,
      details: {
        results: stuffingResults,
        recommendation: 'Implemente rate limiting, CAPTCHA ou MFA para proteger contra credential stuffing.'
      }
    });
  }

  // ── 5. Multi-Protocol Auth Testing ───────────────────────────────
  if (emit) emit({ type: 'progress-detail', message: '🌐 Hydra: Verificando endpoints de autenticação multi-protocolo...' });

  const multiProtoEndpoints = [
    { path: '/xmlrpc.php', method: 'POST', type: 'XML-RPC (WordPress)', body: '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>' },
    { path: '/api/graphql', method: 'POST', type: 'GraphQL Auth', body: '{"query":"mutation{login(email:\\"admin@admin.com\\",password:\\"admin\\"){token}}"}' },
    { path: '/oauth/token', method: 'POST', type: 'OAuth2 Token', body: JSON.stringify({ grant_type: 'password', username: 'admin', password: 'admin', client_id: 'test' }) },
    { path: '/.env', method: 'GET', type: 'Environment File', body: null },
    { path: '/api/v1/auth/token', method: 'POST', type: 'REST API Token', body: JSON.stringify({ username: 'admin', password: 'admin' }) },
  ];

  const multiProtoVulns = [];

  for (const ep of multiProtoEndpoints) {
    const url = baseUrl + ep.path;
    const res = await httpRequest(url, {
      method: ep.method,
      body: ep.body ? (typeof ep.body === 'string' ? null : ep.body) : null,
      headers: ep.body && typeof ep.body === 'string' ? { 'Content-Type': 'text/xml' } : {},
      timeout: 4000
    });

    if (res.status === 200 && res.body && res.body.length > 0) {
      const hasToken = res.body.includes('token') || res.body.includes('access_token') || res.body.includes('jwt');
      const hasEnvData = ep.type.includes('Environment') && (res.body.includes('=') || res.body.includes('KEY'));

      if (hasToken || hasEnvData) {
        multiProtoVulns.push({
          protocol: ep.type,
          path: ep.path,
          status: res.status,
          risk: hasEnvData ? 'critical' : 'high',
          preview: res.body.substring(0, 100)
        });
      }
    }
    await new Promise(r => setTimeout(r, 100));
  }

  if (multiProtoVulns.length > 0) {
    results.push({
      check: '🌐 Hydra — Multi-Protocol Auth',
      status: 'FAIL',
      severity: multiProtoVulns.some(v => v.risk === 'critical') ? 'critical' : 'high',
      message: `${multiProtoVulns.length} endpoint(s) multi-protocolo vulnerável(is) encontrado(s)!`,
      details: {
        vulnerable: multiProtoVulns,
        recommendation: 'Desabilite endpoints não utilizados. Proteja XML-RPC, OAuth e outros protocolos de autenticação.'
      }
    });
  } else {
    results.push({
      check: '🌐 Hydra — Multi-Protocol Auth',
      status: 'PASS',
      severity: 'info',
      message: 'Nenhum endpoint de autenticação multi-protocolo vulnerável detectado.',
      details: { endpointsTested: multiProtoEndpoints.length }
    });
  }

  // ── 6. Overall Hydra Protection Score ────────────────────────────
  const criticalFindings = results.filter(r => r.status === 'FAIL' && r.severity === 'critical').length;
  const highFindings = results.filter(r => r.status === 'FAIL').length;

  let overallStatus, overallSev, overallMsg;
  if (criticalFindings > 0) {
    overallStatus = 'FAIL'; overallSev = 'critical';
    overallMsg = `🚨 SISTEMA VULNERÁVEL A ATAQUES HYDRA! ${criticalFindings} vulnerabilidade(s) crítica(s) encontrada(s).`;
  } else if (highFindings > 0) {
    overallStatus = 'FAIL'; overallSev = 'high';
    overallMsg = `Sistema parcialmente vulnerável a ataques de credenciais. ${highFindings} problema(s) encontrado(s).`;
  } else {
    overallStatus = 'PASS'; overallSev = 'info';
    overallMsg = 'Sistema bem protegido contra ataques Hydra-style. Nenhuma vulnerabilidade crítica de credenciais detectada.';
  }

  results.push({
    check: '🔱 Hydra — Análise Geral de Proteção',
    status: overallStatus,
    severity: overallSev,
    message: overallMsg,
    details: {
      criticalFindings,
      highFindings,
      checksRun: results.length,
      recommendation: criticalFindings > 0
        ? 'URGENTE: Altere credenciais padrão, implemente MFA, rate limiting e bloqueio de conta.'
        : 'Continue monitorando. Implemente MFA para todos os acessos administrativos.'
    }
  });

  return results;
}

module.exports = { checkHydraSimulation };
