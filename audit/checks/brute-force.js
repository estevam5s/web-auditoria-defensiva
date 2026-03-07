/*  ═══════════════════════════════════════════════════════════════════
    BRUTE FORCE LOGIN CHECK
    Tests authentication endpoints for brute force vulnerabilities,
    rate limiting, account locking, and weak password detection.
    ═══════════════════════════════════════════════════════════════════ */

const https = require('https');
const http  = require('http');

const COMMON_PASSWORDS = [
  'password', '123456', '12345678', '123456789', 'qwerty', 'abc123',
  'password1', 'admin', 'letmein', 'welcome', 'monkey', '1234567',
  'login', 'passw0rd', 'master', 'dragon', 'baseball', 'iloveyou',
  'trustno1', 'sunshine', 'princess', 'football', 'password123',
  'supabase', 'test', 'test1234', 'admin123', 'root', 'toor',
  'changeme', 'secret', 'secret123', 'password12', '123123',
  'password2', 'hello', 'hello123', 'world', 'qazwsx', 'password!',
  'P@ssw0rd', 'P@ssword', 'Admin@123', 'Admin@1234', 'root123',
  '123456a', '123456A', '1q2w3e4r', '1qaz2wsx', 'zaq12wsx'
];

const TEST_EMAILS = [
  'test@supabaseguard.local',
  'admin@supabaseguard.local',
  'user@supabaseguard.local',
  'test@test.com',
  'admin@test.com'
];

function httpPost(rawUrl, body, timeoutMs = 5000) {
  return new Promise(resolve => {
    const t0 = Date.now();
    let done = false;
    const finish = (data) => { if (!done) { done = true; resolve({ ...data, ms: Date.now() - t0 }); } };

    try {
      const u = new URL(rawUrl);
      const lib = u.protocol === 'https:' ? https : http;
      
      const options = {
        hostname: u.hostname,
        path: u.pathname + u.search,
        port: u.port || (u.protocol === 'https:' ? 443 : 80),
        method: 'POST',
        headers: {
          'User-Agent': 'SupabaseGuard-SecurityAudit/3.0',
          'Content-Type': 'application/json',
          'Accept': 'application/json'
        },
        rejectUnauthorized: false,
        timeout: timeoutMs
      };

      const req = lib.request(options, (res) => {
        let data = '';
        res.on('data', chunk => data += chunk);
        res.on('end', () => {
          let json = null;
          try { json = JSON.parse(data); } catch {}
          finish({ status: res.statusCode, headers: res.headers, body: data, json, error: null });
        });
      });

      req.on('error', e => finish({ status: 0, headers: {}, body: '', json: null, error: e.message }));
      req.on('timeout', () => { req.destroy(); finish({ status: 0, headers: {}, body: '', json: null, error: 'timeout' }); });

      req.write(JSON.stringify(body));
      req.end();
    } catch (e) {
      finish({ status: 0, headers: {}, body: '', json: null, error: e.message });
    }
  });
}

function detectRateLimiting(headers) {
  const keys = Object.keys(headers || {}).map(k => k.toLowerCase());
  const rateLimitHeaders = [
    'x-ratelimit-limit', 'x-ratelimit-remaining', 'x-ratelimit-reset',
    'retry-after', 'x-retry-after', 'x-rate-limit'
  ];
  return {
    detected: rateLimitHeaders.some(h => keys.includes(h)),
    headers: Object.fromEntries(Object.entries(headers).filter(([k]) => 
      rateLimitHeaders.includes(k.toLowerCase())
    ))
  };
}

async function checkBruteForce(config, emit) {
  const baseUrl = config.projectUrl;
  const results = [];
  const anonKey = config.anonKey;

  const headers = anonKey ? { 'apikey': anonKey, 'Authorization': `Bearer ${anonKey}` } : {};

  if (emit) emit({ type: 'progress-detail', message: '🔐 Iniciando análise de proteção contra força bruta...' });

  // ── 1. Test /auth/v1/token endpoint ───────────────────────────────
  if (emit) emit({ type: 'progress-detail', message: '🔑 Testando endpoint de login (/auth/v1/token)...' });
  
  const tokenUrl = `${baseUrl}/auth/v1/token?grant_type=password`;
  const tokenResults = [];
  let rateLimitHit = false;
  let lockoutDetected = false;
  let successfulLogins = [];
  let failedAttempts = 0;

  for (let i = 0; i < Math.min(COMMON_PASSWORDS.length, 20); i++) {
    const password = COMMON_PASSWORDS[i];
    
    const res = await httpPost(tokenUrl, {
      email: TEST_EMAILS[i % TEST_EMAILS.length],
      password: password
    }, 5000);

    tokenResults.push({
      password: password,
      status: res.status,
      success: res.status === 200,
      error: res.json?.error_description || res.json?.msg || null
    });

    // Check for rate limiting
    if (res.status === 429) {
      rateLimitHit = true;
      break;
    }

    // Check for successful login (wrong password but valid response)
    if (res.status === 400 && res.json?.error_description?.includes('Invalid')) {
      failedAttempts++;
    }

    // Check for successful login (should not happen with wrong credentials)
    if (res.status === 200) {
      successfulLogins.push(password);
    }

    // Small delay between attempts
    if (i < 19) await new Promise(r => setTimeout(r, 100));
  }

  const rateLimiting = detectRateLimiting(tokenResults[0]?.headers || {});

  // ── 2. Check if account lockout exists ────────────────────────────
  if (emit) emit({ type: 'progress-detail', message: '🔒 Verificando política de lockout de conta...' });

  const lockoutTest = await httpPost(tokenUrl, {
    email: 'lockout-test@supabaseguard.local',
    password: 'TestPassword123!'
  }, 5000);

  const hasLockout = lockoutTest.json?.error_description?.toLowerCase().includes('too many') ||
                     lockoutTest.json?.error_description?.toLowerCase().includes('locked') ||
                     lockoutTest.headers['retry-after'] !== undefined;

  // ── 3. Check signup endpoint for brute force ─────────────────────
  if (emit) emit({ type: 'progress-detail', message: '📝 Verificando endpoint de cadastro...' });

  const signupUrl = `${baseUrl}/auth/v1/signup`;
  const signupResults = [];

  for (let i = 0; i < 5; i++) {
    const res = await httpPost(signupUrl, {
      email: `brutetest${i}@supabaseguard.local`,
      password: 'TestPassword123!'
    }, 5000);

    signupResults.push({ status: res.status, body: res.json });
    
    if (res.status === 429) {
      rateLimitHit = true;
      break;
    }
    
    await new Promise(r => setTimeout(r, 200));
  }

  const signupRateLimit = detectRateLimiting(signupResults[0]?.headers || {});

  // ── 4. Check OTP endpoint ─────────────────────────────────────────
  if (emit) emit({ type: 'progress-detail', message: '🔢 Verificando endpoint OTP...' });

  const otpUrl = `${baseUrl}/auth/v1/otp`;
  const otpResults = [];

  for (let i = 0; i < 5; i++) {
    const res = await httpPost(otpUrl, {
      email: `otpbrutetest${i}@supabaseguard.local`
    }, 5000);

    otpResults.push({ status: res.status });
    
    if (res.status === 429) {
      rateLimitHit = true;
      break;
    }
    
    await new Promise(r => setTimeout(r, 200));
  }

  const otpRateLimit = detectRateLimiting(otpResults[0]?.headers || {});

  // ═══════════════════════════════════════════════════════════════════
  // RESULTS
  // ═══════════════════════════════════════════════════════════════════

  // Result 1: Login brute force protection
  {
    let status, sev, msg;
    
    if (successfulLogins.length > 0) {
      status = 'FAIL'; sev = 'critical';
      msg = `VULNERÁVEL A FORÇA BRUTA! ${successfulLogins.length} senha(s) aceitas pelo sistema: ${successfulLogins.slice(0, 3).join(', ')}`;
    } else if (rateLimitHit) {
      status = 'PASS'; sev = 'info';
      msg = `Rate limiting detectado após tentativas — proteção ativa contra força bruta`;
    } else if (!rateLimiting.detected && failedAttempts > 5) {
      status = 'FAIL'; sev = 'high';
      msg = `Nenhum rate limiting detectado e ${failedAttempts} tentativas falharam sem bloqueio — vulnerável a ataques de força bruta`;
    } else {
      status = 'PASS'; sev = 'info';
      msg = `Endpoint de login protegido ou sem resposta reveladora`;
    }

    results.push({
      check: '🔑 Auth — Brute Force (Login)',
      status, severity: sev, message: msg,
      details: {
        endpoint: '/auth/v1/token',
        attempts: tokenResults.length,
        successfulLogins,
        failedAttempts,
        rateLimitHit,
        rateLimiting: rateLimiting.detected,
        rateLimitHeaders: rateLimiting.headers
      }
    });
  }

  // Result 2: Account lockout policy
  {
    let status, sev, msg;
    
    if (hasLockout) {
      status = 'PASS'; sev = 'info';
      msg = `Política de lockout de conta detectada — após tentativas falhas, conta é temporariamente bloqueada`;
    } else {
      status = 'FAIL'; sev = 'high';
      msg = `Nenhuma política de lockout detectada — contas podem ser atacadas sem limite de tentativas`;
    }

    results.push({
      check: '🔒 Auth — Account Lockout Policy',
      status, severity: sev, message: msg,
      details: {
        lockoutDetected: hasLockout,
        retryAfter: lockoutTest.headers['retry-after'],
        response: lockoutTest.json
      }
    });
  }

  // Result 3: Signup brute force
  {
    let status, sev, msg;
    const signupRateLimited = signupResults.some(r => r.status === 429);
    const signupAllows = signupResults.some(r => r.status === 200);

    if (signupRateLimited) {
      status = 'PASS'; sev = 'info';
      msg = `Rate limiting ativo no endpoint de signup — proteção contra spam de cadastros`;
    } else if (signupAllows) {
      status = 'WARN'; sev = 'medium';
      msg = `Endpoint de signup aceita requisições sem limitação — vulnerável a spam de cadastros`;
    } else {
      status = 'PASS'; sev = 'info';
      msg = `Signup protegido ou validado corretamente`;
    }

    results.push({
      check: '📝 Auth — Signup Rate Limiting',
      status, severity: sev, message: msg,
      details: {
        endpoint: '/auth/v1/signup',
        tested: signupResults.length,
        rateLimited: signupRateLimited,
        allowsUnlimited: signupAllows && !signupRateLimited,
        rateLimitHeaders: signupRateLimit.headers
      }
    });
  }

  // Result 4: OTP brute force
  {
    let status, sev, msg;
    const otpRateLimited = otpResults.some(r => r.status === 429);

    if (otpRateLimited) {
      status = 'PASS'; sev = 'info';
      msg = `Rate limiting ativo no endpoint OTP — proteção contra spam de códigos`;
    } else {
      status = 'WARN'; sev = 'medium';
      msg = `Nenhum rate limiting detectado no OTP — vulnerável a ataques de enumeração de emails`;
    }

    results.push({
      check: '🔢 Auth — OTP Rate Limiting',
      status, severity: sev, message: msg,
      details: {
        endpoint: '/auth/v1/otp',
        tested: otpResults.length,
        rateLimited: otpRateLimited,
        rateLimitHeaders: otpRateLimit.headers
      }
    });
  }

  // Result 5: Overall brute force protection
  {
    const protections = [rateLimitHit, hasLockout, signupRateLimit.detected, otpRateLimit.detected].filter(Boolean).length;
    let status, sev, msg;

    if (protections >= 3) {
      status = 'PASS'; sev = 'info';
      msg = `Múltiplas camadas de proteção contra força bruta (${protections}/4)`;
    } else if (protections >= 2) {
      status = 'PASS'; sev = 'low';
      msg = `Proteção básica contra força bruta (${protections}/4)`;
    } else if (protections === 1) {
      status = 'FAIL'; sev = 'high';
      msg = `Proteção mínima contra força bruta (${protections}/4) — recomenda-se adicionar mais`;
    } else {
      status = 'FAIL'; sev = 'critical';
      msg = `NENHUMA proteção contra força bruta detectada — sistema vulnerável a ataques automatizados`;
    }

    results.push({
      check: '🚨 Auth — Análise de Proteção Geral',
      status, severity: sev, message: msg,
      details: {
        totalProtections: protections,
        loginRateLimit: rateLimitHit,
        accountLockout: hasLockout,
        signupRateLimit: signupRateLimit.detected,
        otpRateLimit: otpRateLimit.detected
      }
    });
  }

  return results;
}

module.exports = { checkBruteForce };
