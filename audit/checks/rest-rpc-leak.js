/*  ═══════════════════════════════════════════════════════════════════
    DEEP CHECK: REST & RPC Data Leak Detector
    Verifies if REST tables and RPC functions return actual data
    for GUEST (anon) role — classifies the severity of leaked data
    ═══════════════════════════════════════════════════════════════════ */

const { safeFetch, supabaseHeaders } = require('../helpers/http');

// Extended sensitive data patterns for content analysis
const SENSITIVE_CONTENT_PATTERNS = [
  { name: 'Email',          regex: /\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b/g, severity: 'high', category: 'PII' },
  { name: 'CPF',            regex: /\b\d{3}\.?\d{3}\.?\d{3}-?\d{2}\b/g,                     severity: 'critical', category: 'Document' },
  { name: 'CNPJ',           regex: /\b\d{2}\.?\d{3}\.?\d{3}\/?\d{4}-?\d{2}\b/g,             severity: 'critical', category: 'Document' },
  { name: 'Phone BR',       regex: /\b(?:\+55\s?)?(?:\(?\d{2}\)?\s?)?9?\d{4}[\s-]?\d{4}\b/g, severity: 'high', category: 'PII' },
  { name: 'Credit Card',    regex: /\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))\d{8,12}\b/g, severity: 'critical', category: 'Financial' },
  { name: 'JWT Token',      regex: /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_\-]+/g, severity: 'critical', category: 'Credential' },
  { name: 'API Key',        regex: /(?:sk_live|pk_live|sk_test|pk_test|AKIA|AIza|ghp_|gho_|glpat-|xox[bsrp]-)\w{10,}/g, severity: 'critical', category: 'API Key' },
  { name: 'UUID',           regex: /\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi, severity: 'low', category: 'ID' },
  { name: 'Private IP',     regex: /\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b/g, severity: 'medium', category: 'Infrastructure' },
  { name: 'Password Field',  regex: /["'](?:password|passwd|pwd|senha)["']\s*:\s*["'][^"']+["']/gi, severity: 'critical', category: 'Credential' },
  { name: 'Hash (bcrypt)',   regex: /\$2[ayb]\$\d{2}\$[A-Za-z0-9./]{53}/g, severity: 'critical', category: 'Credential' },
  { name: 'Hash (argon2)',   regex: /\$argon2[id]{1,2}\$[^\s"']+/g, severity: 'critical', category: 'Credential' },
  { name: 'Database URL',    regex: /(?:postgres|mysql|mongodb|redis):\/\/[^\s"'<>]+/gi, severity: 'critical', category: 'Infrastructure' },
  { name: 'Webhook URL',     regex: /https?:\/\/[^\s"']*(?:webhook|hook|callback)[^\s"']*/gi, severity: 'medium', category: 'Infrastructure' },
];

// Table categories for risk classification
const TABLE_RISK = {
  critical: ['users', 'auth_users', 'accounts', 'credentials', 'secrets', 'api_keys', 'tokens', 'sessions', 'payments', 'transactions', 'credit_cards', 'bank_accounts', 'wallets', 'keys'],
  high: ['profiles', 'customers', 'members', 'orders', 'invoices', 'billing', 'addresses', 'documents', 'patients', 'medical_records', 'subscriptions'],
  medium: ['posts', 'comments', 'messages', 'notifications', 'settings', 'preferences', 'logs', 'events', 'products'],
};

// Extended table + RPC wordlists
const TABLES = [
  'users','profiles','accounts','members','customers','admins','auth_users',
  'posts','articles','comments','messages','chats','chat_messages','notifications',
  'orders','order_items','products','categories','payments','transactions','invoices',
  'subscriptions','prices','coupons','shipping','addresses','carts','cart_items',
  'settings','config','preferences','metadata','logs','audit_logs','events',
  'documents','files','uploads','media','tokens','api_keys','secrets','credentials',
  'roles','permissions','organizations','teams','workspaces','wallets','balances',
  'transfers','bank_accounts','cards','billing','charges','refunds',
  'patients','appointments','medical_records','students','courses','grades',
  'webhooks','integrations','connections','providers','jobs','tasks',
  'usuarios','perfis','clientes','pedidos','pagamentos','produtos','configuracoes',
];

const RPC_FUNCTIONS = [
  'get_users','get_all_users','list_users','search_users','find_user',
  'get_user_by_id','get_user_by_email','get_user_data','export_users',
  'get_admin','admin_query','run_query','exec_sql','run_sql',
  'get_orders','get_payments','get_transactions','get_invoices',
  'get_secrets','get_config','get_settings','get_env','get_keys',
  'get_all','list_all','export_data','backup','get_logs',
  'create_user','delete_user','update_role','grant_admin',
  'reset_password','generate_token','create_token',
  'search','global_search','fulltext_search',
  'get_balance','get_wallet','transfer_funds',
  'get_credentials','get_api_keys','rotate_key',
  'send_email','send_notification','send_sms',
  'get_stripe_customers','get_payment_methods',
];

async function deepRESTRPCLeakCheck(config, emit) {
  const results = [];
  const baseUrl = config.projectUrl;
  const headers = supabaseHeaders(config.anonKey);

  emit({ type: 'log', level: 'info', message: '[REST/RPC Leak] Iniciando análise profunda de vazamento de dados...' });

  // ═══════════ 1. REST Table Scan with Content Analysis ═══════════
  emit({ type: 'log', level: 'info', message: `[REST/RPC Leak] Escaneando ${TABLES.length} tabelas REST...` });

  const tableLeaks = [];
  const BATCH = 8;

  for (let i = 0; i < TABLES.length; i += BATCH) {
    const batch = TABLES.slice(i, i + BATCH);
    const fetches = batch.map(table =>
      safeFetch(`${baseUrl}/rest/v1/${table}?select=*&limit=5`, { headers, timeout: 6000 })
        .then(res => ({ table, res }))
    );
    const batchResults = await Promise.all(fetches);

    for (const { table, res } of batchResults) {
      if (res.status === 404 || res.status === 0) continue;

      if (res.ok && Array.isArray(res.json) && res.json.length > 0) {
        const data = res.json;
        const columns = Object.keys(data[0]);
        const jsonStr = JSON.stringify(data);

        // Analyze content for sensitive patterns
        const sensitiveFindings = [];
        for (const pat of SENSITIVE_CONTENT_PATTERNS) {
          const matches = jsonStr.match(pat.regex);
          if (matches && matches.length > 0) {
            const unique = [...new Set(matches)];
            sensitiveFindings.push({
              type: pat.name,
              category: pat.category,
              severity: pat.severity,
              count: unique.length,
              samples: unique.slice(0, 3).map(m => maskValue(m)),
            });
          }
        }

        // Determine table risk level
        const riskLevel = TABLE_RISK.critical.includes(table) ? 'critical'
          : TABLE_RISK.high.includes(table) ? 'high'
          : TABLE_RISK.medium.includes(table) ? 'medium' : 'low';

        tableLeaks.push({
          table,
          records: data.length,
          columns,
          columnCount: columns.length,
          riskLevel,
          sensitiveFindings,
          hasCriticalData: sensitiveFindings.some(f => f.severity === 'critical'),
          hasPII: sensitiveFindings.some(f => f.category === 'PII' || f.category === 'Document'),
          hasFinancial: sensitiveFindings.some(f => f.category === 'Financial'),
          hasCredentials: sensitiveFindings.some(f => f.category === 'Credential'),
        });

        const warn = sensitiveFindings.length > 0
          ? ` (${sensitiveFindings.map(f => f.type).join(', ')})`
          : '';
        emit({ type: 'log', level: 'warn', message: `[REST/RPC Leak] ✗ ${table}: ${data.length} registros, ${columns.length} colunas${warn}` });
      }
    }

    if (i % 24 === 0 && i > 0) {
      emit({ type: 'log', level: 'info', message: `[REST/RPC Leak] ${Math.min(i + BATCH, TABLES.length)}/${TABLES.length} tabelas...` });
    }
  }

  // ═══════════ 2. RPC Function Probing with Data Analysis ═══════════
  emit({ type: 'log', level: 'info', message: `[REST/RPC Leak] Testando ${RPC_FUNCTIONS.length} funções RPC...` });

  const rpcLeaks = [];
  for (const fn of RPC_FUNCTIONS) {
    const res = await safeFetch(`${baseUrl}/rest/v1/rpc/${fn}`, {
      method: 'POST',
      headers: { ...headers, 'Content-Type': 'application/json' },
      body: JSON.stringify({}),
      timeout: 5000
    });

    if (res.status === 404 || res.status === 0) continue;

    if (res.ok && res.json !== null && res.json !== undefined) {
      const jsonStr = JSON.stringify(res.json);
      const sensitiveFindings = [];

      for (const pat of SENSITIVE_CONTENT_PATTERNS) {
        const matches = jsonStr.match(pat.regex);
        if (matches) {
          sensitiveFindings.push({
            type: pat.name,
            count: [...new Set(matches)].length,
            severity: pat.severity,
          });
        }
      }

      rpcLeaks.push({
        function: fn,
        dataType: Array.isArray(res.json) ? 'array' : typeof res.json,
        recordCount: Array.isArray(res.json) ? res.json.length : 1,
        responseSize: jsonStr.length,
        sensitiveFindings,
        hasSensitive: sensitiveFindings.length > 0,
      });

      emit({ type: 'log', level: 'warn', message: `[REST/RPC Leak] ✗ RPC ${fn}() retorna dados (${jsonStr.length} bytes)` });
    }
  }

  // ═══════════ 3. No-Auth Access Test ═══════════
  emit({ type: 'log', level: 'info', message: '[REST/RPC Leak] Testando acesso sem qualquer autenticação...' });

  const noAuthLeaks = [];
  const topTables = tableLeaks.slice(0, 10);
  for (const leak of topTables) {
    const res = await safeFetch(`${baseUrl}/rest/v1/${leak.table}?select=*&limit=1`, {
      headers: { 'Content-Type': 'application/json' }, // NO apikey/auth
      timeout: 5000
    });

    if (res.ok && Array.isArray(res.json) && res.json.length > 0) {
      noAuthLeaks.push({ table: leak.table, status: res.status });
    }
  }

  // ═══════════ 4. Row Count Estimation ═══════════
  emit({ type: 'log', level: 'info', message: '[REST/RPC Leak] Estimando volume de dados expostos...' });

  for (const leak of tableLeaks.slice(0, 15)) {
    // Use HEAD with count
    const countRes = await safeFetch(`${baseUrl}/rest/v1/${leak.table}?select=count`, {
      headers: { ...headers, 'Prefer': 'count=exact', 'Range': '0-0' },
      timeout: 5000
    });

    if (countRes.headers?.['content-range']) {
      const rangeMatch = countRes.headers['content-range'].match(/\d+-\d+\/(\d+)/);
      if (rangeMatch) {
        leak.totalRows = parseInt(rangeMatch[1]);
      }
    }
  }

  // ═══════════ Compile Results ═══════════
  emit({ type: 'log', level: 'info', message: `[REST/RPC Leak] Compilando ${tableLeaks.length} leaks REST + ${rpcLeaks.length} leaks RPC...` });

  // Critical data leaks
  const criticalLeaks = tableLeaks.filter(t => t.hasCriticalData || t.hasCredentials);
  if (criticalLeaks.length > 0) {
    results.push({
      check: 'REST/RPC — Credenciais & Tokens Expostos',
      status: 'FAIL',
      severity: 'critical',
      message: `🚨 ${criticalLeaks.length} tabela(s) expõem credenciais, tokens ou dados financeiros via REST!`,
      details: {
        tables: criticalLeaks.map(t => ({
          table: t.table,
          totalRows: t.totalRows,
          sensitiveData: t.sensitiveFindings.filter(f => f.severity === 'critical'),
        })),
        recommendation: 'URGENTE: Ative RLS e remova acesso anon a tabelas com credenciais.'
      }
    });
  }

  // PII exposure
  const piiLeaks = tableLeaks.filter(t => t.hasPII && !t.hasCriticalData);
  if (piiLeaks.length > 0) {
    results.push({
      check: 'REST/RPC — Dados Pessoais (PII) Expostos',
      status: 'FAIL',
      severity: 'high',
      message: `${piiLeaks.length} tabela(s) expõem emails, documentos (CPF/CNPJ), telefones via REST.`,
      details: {
        tables: piiLeaks.map(t => ({
          table: t.table,
          piiTypes: t.sensitiveFindings.filter(f => ['PII','Document'].includes(f.category)),
          totalRows: t.totalRows,
        })),
        recommendation: 'Configure RLS para limitar acesso a dados pessoais apenas ao proprietário.'
      }
    });
  }

  // Financial data
  const financialLeaks = tableLeaks.filter(t => t.hasFinancial);
  if (financialLeaks.length > 0) {
    results.push({
      check: 'REST/RPC — Dados Financeiros Expostos',
      status: 'FAIL',
      severity: 'critical',
      message: `💰 ${financialLeaks.length} tabela(s) expõem dados financeiros (cartões, pagamentos) via REST!`,
      details: {
        tables: financialLeaks.map(t => ({
          table: t.table,
          financialTypes: t.sensitiveFindings.filter(f => f.category === 'Financial'),
        })),
        recommendation: 'URGENTE: Dados financeiros NUNCA devem ser acessíveis via anon key. Ative RLS com políticas estritas.'
      }
    });
  }

  // General table exposure
  const generalLeaks = tableLeaks.filter(t => !t.hasCriticalData && !t.hasPII && !t.hasFinancial);
  if (generalLeaks.length > 0) {
    results.push({
      check: 'REST/RPC — Tabelas Acessíveis (GUEST)',
      status: 'WARN',
      severity: 'medium',
      message: `${generalLeaks.length} tabela(s) retornam dados para GUEST sem dados críticos mas sem RLS.`,
      details: {
        tables: generalLeaks.map(t => ({ table: t.table, columns: t.columnCount, rows: t.totalRows })),
        recommendation: 'Revise se estas tabelas devem ser públicas. Ative RLS quando possível.'
      }
    });
  }

  // RPC leaks
  if (rpcLeaks.length > 0) {
    const criticalRpc = rpcLeaks.filter(r => r.hasSensitive);
    results.push({
      check: 'REST/RPC — Funções RPC Vazando Dados',
      status: 'FAIL',
      severity: criticalRpc.length > 0 ? 'critical' : 'high',
      message: `${rpcLeaks.length} função(ões) RPC retornam dados para GUEST. ${criticalRpc.length} contêm dados sensíveis.`,
      details: {
        functions: rpcLeaks,
        recommendation: 'REVOKE EXECUTE em funções RPC sensíveis para o role anon. Valide auth.uid() dentro de cada função.'
      }
    });
  }

  // No-auth access
  if (noAuthLeaks.length > 0) {
    results.push({
      check: 'REST/RPC — Acesso Sem Autenticação',
      status: 'FAIL',
      severity: 'critical',
      message: `${noAuthLeaks.length} tabela(s) acessíveis SEM nenhuma autenticação (nem apikey)!`,
      details: {
        tables: noAuthLeaks,
        recommendation: 'Configure o Supabase para exigir apikey em todas as requisições REST.'
      }
    });
  }

  // All good
  if (tableLeaks.length === 0 && rpcLeaks.length === 0) {
    results.push({
      check: 'REST/RPC — Leak Check',
      status: 'PASS',
      severity: 'info',
      message: `✓ Nenhum vazamento de dados detectado. ${TABLES.length} tabelas e ${RPC_FUNCTIONS.length} RPCs testados.`,
      details: { tablesChecked: TABLES.length, rpcsChecked: RPC_FUNCTIONS.length }
    });
  }

  return results;
}

function maskValue(value) {
  if (!value || value.length < 6) return '***';
  if (value.length <= 12) return value.substring(0, 3) + '***' + value.substring(value.length - 2);
  return value.substring(0, 4) + '***...' + value.substring(value.length - 4);
}

module.exports = { deepRESTRPCLeakCheck };
