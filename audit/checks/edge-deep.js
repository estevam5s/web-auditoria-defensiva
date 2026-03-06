/*  ═══════════════════════════════════════════════════════════════════
    DEEP CHECK: Edge Functions Role Control Analyzer
    Goes beyond simple discovery — verifies:
    - Functions accessible without JWT/auth
    - Functions that don't validate role claims
    - Functions leaking data for "anon" vs "authenticated"
    - Sensitive operations without authorization checks
    - API gateway bypass via direct invocation
    ═══════════════════════════════════════════════════════════════════ */

const { safeFetch, supabaseHeaders } = require('../helpers/http');

// Extended function names covering common patterns
const EDGE_FUNCTION_NAMES = [
  // Common
  'hello', 'test', 'ping', 'health', 'status', 'version',
  // Auth
  'auth', 'login', 'register', 'signup', 'signin', 'logout',
  'verify', 'verify-email', 'confirm', 'reset-password', 'forgot-password',
  'refresh-token', 'validate-token', 'magic-link', 'otp',
  // Payments / Financial
  'webhook', 'stripe-webhook', 'stripe', 'payment', 'checkout',
  'create-payment', 'process-payment', 'refund', 'subscription',
  'mercadopago', 'mercadopago-webhook', 'pix', 'boleto',
  'pagseguro', 'paypal', 'asaas', 'iugu', 'pagar-me', 'pagarme',
  'create-checkout', 'billing', 'invoice', 'charge',
  // Communication
  'send-email', 'email', 'notify', 'notification', 'push',
  'send-sms', 'sms', 'whatsapp', 'send-whatsapp', 'resend',
  // Admin
  'admin', 'dashboard', 'analytics', 'metrics', 'report',
  'manage', 'moderate', 'ban-user', 'delete-user', 'update-role',
  // Data
  'api', 'proxy', 'cors-proxy', 'fetch', 'scrape', 'crawl',
  'search', 'global-search', 'autocomplete',
  'export', 'import', 'backup', 'restore', 'sync', 'migrate',
  // AI/ML
  'ai', 'openai', 'chat', 'generate', 'embed', 'transcribe',
  'gpt', 'claude', 'gemini', 'llm', 'completion',
  // Files
  'upload', 'download', 'process', 'resize', 'convert',
  'pdf', 'generate-pdf', 'generate-report',
  // Jobs
  'cron', 'scheduler', 'worker', 'queue', 'job',
  'process-queue', 'run-job', 'cleanup',
  // Integration
  'github', 'slack', 'discord', 'telegram', 'zapier',
  'n8n', 'make', 'integromat',
];

// Roles to test
const TEST_ROLES = {
  noAuth: { name: 'Sem Auth', headers: { 'Content-Type': 'application/json' } },
  anonKey: { name: 'Anon Key', headers: null }, // will use supabaseHeaders
  fakeAdmin: {
    name: 'Fake Admin JWT',
    headers: null, // will be built dynamically
  },
};

async function deepEdgeFunctionCheck(config, emit) {
  const results = [];
  const baseUrl = config.projectUrl;
  const headers = supabaseHeaders(config.anonKey);

  emit({ type: 'log', level: 'info', message: '[Edge Functions] Iniciando análise profunda de controle de role...' });

  // ═══════════ 1. Function Discovery (GET + POST + OPTIONS) ═══════════
  emit({ type: 'log', level: 'info', message: `[Edge Functions] Escaneando ${EDGE_FUNCTION_NAMES.length} funções potenciais...` });

  const discovered = [];
  const BATCH = 6;

  for (let i = 0; i < EDGE_FUNCTION_NAMES.length; i += BATCH) {
    const batch = EDGE_FUNCTION_NAMES.slice(i, i + BATCH);
    const fetches = batch.map(fn => {
      const url = `${baseUrl}/functions/v1/${fn}`;
      return safeFetch(url, { headers, timeout: 6000 })
        .then(res => ({ fn, method: 'GET', res }))
        .then(async (result) => {
          if (result.res.status === 404 || result.res.status === 0) {
            // Try POST
            const postRes = await safeFetch(url, {
              method: 'POST',
              headers: { ...headers, 'Content-Type': 'application/json' },
              body: JSON.stringify({}),
              timeout: 6000
            });
            return { fn, method: 'POST', res: postRes };
          }
          return result;
        });
    });

    const batchResults = await Promise.all(fetches);

    for (const { fn, method, res } of batchResults) {
      if (res.status === 404 || res.status === 0) continue;

      discovered.push({
        name: fn,
        method,
        status: res.status,
        ok: res.ok,
        size: res.text?.length || 0,
        contentType: res.headers?.['content-type'] || 'unknown',
        hasJWTCheck: false, // will test below
      });
    }

    if (i % 24 === 0 && i > 0) {
      emit({ type: 'log', level: 'info', message: `[Edge Functions] ${Math.min(i + BATCH, EDGE_FUNCTION_NAMES.length)}/${EDGE_FUNCTION_NAMES.length} testadas...` });
    }
  }

  emit({ type: 'log', level: 'info', message: `[Edge Functions] ${discovered.length} funções descobertas.` });

  // ═══════════ 2. Role Control Tests ═══════════
  emit({ type: 'log', level: 'info', message: '[Edge Functions] Testando controle de role em cada função...' });

  const noAuthAccess = [];
  const noRoleCheck = [];
  const sensitiveNoAuth = [];

  // Sensitive function patterns
  const sensitivePatterns = ['admin', 'payment', 'stripe', 'checkout', 'delete', 'update-role',
    'export', 'backup', 'manage', 'billing', 'invoice', 'refund', 'transfer',
    'mercadopago', 'pix', 'send-email', 'send-sms', 'whatsapp', 'ban-user',
    'generate-token', 'reset-password', 'webhook', 'secret', 'config'];

  for (const fn of discovered) {
    const fnUrl = `${baseUrl}/functions/v1/${fn.name}`;
    const isSensitive = sensitivePatterns.some(p => fn.name.toLowerCase().includes(p));

    // Test 1: No auth at all (no apikey, no JWT)
    const noAuthRes = await safeFetch(fnUrl, {
      method: fn.method,
      headers: { 'Content-Type': 'application/json' },
      body: fn.method === 'POST' ? JSON.stringify({}) : undefined,
      timeout: 6000
    });

    if (noAuthRes.ok || (noAuthRes.status >= 200 && noAuthRes.status < 400)) {
      noAuthAccess.push({
        name: fn.name,
        method: fn.method,
        status: noAuthRes.status,
        responseSize: noAuthRes.text?.length || 0,
        isSensitive,
      });

      if (isSensitive) {
        sensitiveNoAuth.push(fn.name);
        emit({ type: 'log', level: 'warn', message: `[Edge Functions] 🚨 SENSÍVEL sem auth: ${fn.name} (${noAuthRes.status})` });
      }
    }

    // Test 2: With anon key but check if response differs (role-aware functions should return less data or 403)
    const anonRes = await safeFetch(fnUrl, {
      method: fn.method,
      headers: { ...headers, 'Content-Type': 'application/json' },
      body: fn.method === 'POST' ? JSON.stringify({ test: true }) : undefined,
      timeout: 6000
    });

    // Test 3: Try with a crafted "admin" claim in Authorization
    // (If the function doesn't verify JWT signature, this would work)
    const fakePayload = Buffer.from(JSON.stringify({
      role: 'service_role',
      sub: '00000000-0000-0000-0000-000000000000',
      iss: 'supabase',
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 3600,
    })).toString('base64url');
    const fakeJwt = `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.${fakePayload}.fake_signature`;

    const fakeAdminRes = await safeFetch(fnUrl, {
      method: fn.method,
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${fakeJwt}`,
        'apikey': config.anonKey || '',
      },
      body: fn.method === 'POST' ? JSON.stringify({}) : undefined,
      timeout: 6000
    });

    // Compare responses: if fake admin gets more data or different status, role checking may be broken
    if (fakeAdminRes.ok && anonRes.ok) {
      const anonSize = anonRes.text?.length || 0;
      const fakeSize = fakeAdminRes.text?.length || 0;

      if (fakeSize > anonSize * 1.5 && fakeSize > 100) {
        noRoleCheck.push({
          name: fn.name,
          note: 'Função retorna MAIS dados com JWT falso — pode não verificar assinatura JWT!',
          anonResponseSize: anonSize,
          fakeAdminResponseSize: fakeSize,
          severity: 'critical',
        });
        emit({ type: 'log', level: 'warn', message: `[Edge Functions] 🚨 JWT bypass potencial: ${fn.name} (anon: ${anonSize}B vs fake: ${fakeSize}B)` });
      }
    } else if (fakeAdminRes.ok && !anonRes.ok) {
      noRoleCheck.push({
        name: fn.name,
        note: 'Função aceita JWT sem verificar assinatura — retorna 200 apenas com JWT falso!',
        anonStatus: anonRes.status,
        fakeAdminStatus: fakeAdminRes.status,
        severity: 'critical',
      });
      emit({ type: 'log', level: 'warn', message: `[Edge Functions] 🚨 JWT NÃO VERIFICADO: ${fn.name}` });
    }

    // Test 4: CORS check on functions
    const optionsRes = await safeFetch(fnUrl, {
      method: 'OPTIONS',
      headers: { 'Origin': 'https://evil-attacker.com', 'Access-Control-Request-Method': 'POST' },
      timeout: 3000
    });

    if (optionsRes.ok) {
      const allowOrigin = optionsRes.headers?.['access-control-allow-origin'];
      if (allowOrigin === '*' || allowOrigin === 'https://evil-attacker.com') {
        fn.corsIssue = { allowOrigin };
      }
    }
  }

  // ═══════════ 3. Webhook Vulnerability Tests ═══════════
  emit({ type: 'log', level: 'info', message: '[Edge Functions] Testando webhooks sem assinatura...' });

  const webhookFns = discovered.filter(f =>
    f.name.includes('webhook') || f.name.includes('hook') || f.name.includes('callback')
  );

  const webhookIssues = [];
  for (const wh of webhookFns) {
    // Send fake webhook payload — if accepted, signature validation may be missing
    const fakePayload = {
      id: 'evt_fake_000',
      type: 'checkout.session.completed',
      data: { object: { id: 'cs_test_fake', amount_total: 99999, customer_email: 'attacker@evil.com' } }
    };

    const whRes = await safeFetch(`${baseUrl}/functions/v1/${wh.name}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(fakePayload),
      timeout: 6000
    });

    if (whRes.ok || whRes.status === 200) {
      webhookIssues.push({
        name: wh.name,
        status: whRes.status,
        note: 'Webhook aceita payload FALSO sem verificar assinatura! Atacante pode simular pagamentos.',
        severity: 'critical',
      });
      emit({ type: 'log', level: 'warn', message: `[Edge Functions] 🚨 Webhook sem validação de assinatura: ${wh.name}` });
    }
  }

  // ═══════════ Compile Results ═══════════
  emit({ type: 'log', level: 'info', message: `[Edge Functions] Compilando resultados...` });

  if (discovered.length > 0) {
    results.push({
      check: 'Edge Functions — Descoberta',
      status: 'INFO',
      severity: 'info',
      message: `${discovered.length} Edge Function(s) descoberta(s): ${discovered.map(f => f.name).join(', ')}`,
      details: { functions: discovered.map(f => ({ name: f.name, method: f.method, status: f.status })) }
    });
  }

  if (sensitiveNoAuth.length > 0) {
    results.push({
      check: 'Edge Functions — Sensíveis Sem Auth',
      status: 'FAIL',
      severity: 'critical',
      message: `🚨 ${sensitiveNoAuth.length} função(ões) SENSÍVEL(IS) acessível(is) sem autenticação: ${sensitiveNoAuth.join(', ')}`,
      details: {
        functions: noAuthAccess.filter(f => f.isSensitive),
        recommendation: 'URGENTE: Adicione verificação de JWT em todas as funções sensíveis. Use supabase.auth.getUser() no início do handler.'
      }
    });
  }

  if (noAuthAccess.length > sensitiveNoAuth.length) {
    const nonSensitive = noAuthAccess.filter(f => !f.isSensitive);
    results.push({
      check: 'Edge Functions — Sem Auth (Geral)',
      status: 'WARN',
      severity: 'medium',
      message: `${nonSensitive.length} função(ões) acessível(is) sem autenticação.`,
      details: {
        functions: nonSensitive,
        recommendation: 'Avalie se cada função deve ser pública. Adicione JWT verification quando necessário.'
      }
    });
  }

  if (noRoleCheck.length > 0) {
    results.push({
      check: 'Edge Functions — JWT Não Verificado',
      status: 'FAIL',
      severity: 'critical',
      message: `🚨 ${noRoleCheck.length} função(ões) não verificam assinatura JWT! JWT falso é aceito.`,
      details: {
        functions: noRoleCheck,
        recommendation: 'URGENTE: Verifique JWT com supabase.auth.getUser() — nunca confie apenas em req.headers.authorization sem validação.'
      }
    });
  }

  if (webhookIssues.length > 0) {
    results.push({
      check: 'Edge Functions — Webhooks Sem Assinatura',
      status: 'FAIL',
      severity: 'critical',
      message: `🚨 ${webhookIssues.length} webhook(s) aceita(m) payload falso! Atacante pode simular eventos de pagamento.`,
      details: {
        webhooks: webhookIssues,
        recommendation: 'URGENTE: Valide a assinatura do webhook (Stripe-Signature, etc.) antes de processar.'
      }
    });
  }

  // CORS issues on functions
  const corsIssues = discovered.filter(f => f.corsIssue);
  if (corsIssues.length > 0) {
    results.push({
      check: 'Edge Functions — CORS Permissivo',
      status: 'WARN',
      severity: 'medium',
      message: `${corsIssues.length} função(ões) com CORS wildcard ou aceitam qualquer Origin.`,
      details: {
        functions: corsIssues.map(f => ({ name: f.name, cors: f.corsIssue })),
        recommendation: 'Restrinja CORS para domínios específicos em funções sensíveis.'
      }
    });
  }

  if (discovered.length === 0) {
    results.push({
      check: 'Edge Functions — Descoberta',
      status: 'PASS',
      severity: 'info',
      message: `✓ Nenhuma Edge Function descoberta. ${EDGE_FUNCTION_NAMES.length} nomes testados.`,
      details: null
    });
  }

  return results;
}

module.exports = { deepEdgeFunctionCheck };
