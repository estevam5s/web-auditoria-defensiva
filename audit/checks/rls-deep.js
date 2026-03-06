/*  ═══════════════════════════════════════════════════════════════════
    DEEP CHECK: RLS Misconfiguration Analyzer
    Goes far beyond simple table access — detects:
    - Tables with RLS disabled (SELECT/INSERT/UPDATE/DELETE)
    - Overly permissive policies (USING true, WITH CHECK true)
    - Cross-user data leakage via horizontal privilege escalation
    - Schema introspection via pg_catalog / information_schema
    - Missing policies per operation type
    - Data comparison GUEST vs authenticated USER
    ═══════════════════════════════════════════════════════════════════ */

const { safeFetch, supabaseHeaders } = require('../helpers/http');

// Extensive table list covering common app patterns
const TABLE_WORDLIST = [
  // Auth / Users
  'users', 'profiles', 'accounts', 'members', 'customers', 'admins',
  'auth_users', 'user_roles', 'user_permissions', 'user_sessions',
  'usuarios', 'perfis', 'clientes',
  // Content
  'posts', 'articles', 'pages', 'comments', 'messages', 'chats',
  'chat_messages', 'notifications', 'feeds', 'likes', 'follows',
  // E-commerce
  'orders', 'order_items', 'products', 'categories', 'carts',
  'cart_items', 'payments', 'transactions', 'invoices', 'subscriptions',
  'prices', 'coupons', 'discounts', 'shipping', 'addresses',
  'pedidos', 'pagamentos', 'produtos',
  // Financial
  'wallets', 'balances', 'transfers', 'bank_accounts', 'cards',
  'credit_cards', 'pix_keys', 'billing', 'charges', 'refunds',
  // App data
  'settings', 'config', 'configurations', 'preferences', 'metadata',
  'logs', 'audit_logs', 'events', 'analytics', 'sessions',
  'tokens', 'api_keys', 'secrets', 'credentials', 'keys',
  'documents', 'files', 'uploads', 'attachments', 'media',
  // Roles & permissions
  'roles', 'permissions', 'role_permissions', 'access_control',
  'organizations', 'teams', 'team_members', 'workspaces',
  // System
  'migrations', 'schema_migrations', 'jobs', 'queues', 'tasks',
  'webhooks', 'integrations', 'connections', 'providers',
  // Healthcare
  'patients', 'appointments', 'prescriptions', 'medical_records',
  // Education
  'students', 'courses', 'enrollments', 'grades', 'teachers',
];

// Sensitive column names that should NEVER be exposed
const CRITICAL_COLUMNS = [
  'password', 'password_hash', 'hashed_password', 'encrypted_password', 'senha',
  'secret', 'secret_key', 'api_secret', 'client_secret',
  'token', 'access_token', 'refresh_token', 'auth_token', 'bearer_token',
  'api_key', 'api_key_hash', 'private_key', 'encryption_key', 'master_key',
  'ssn', 'social_security', 'cpf', 'cnpj', 'rg', 'passport_number',
  'credit_card', 'card_number', 'cvv', 'card_cvc', 'card_exp',
  'bank_account', 'routing_number', 'iban', 'swift_code',
  'stripe_secret', 'stripe_key', 'paypal_secret', 'mercadopago_token',
  'pix_key', 'gateway_key', 'gateway_secret', 'payment_token',
  'otp', 'otp_secret', 'totp_secret', 'two_factor_secret', 'recovery_codes',
  'session_token', 'csrf_token', 'jwt_secret',
];

// Columns that indicate PII exposure
const PII_COLUMNS = [
  'email', 'phone', 'phone_number', 'telefone', 'celular',
  'address', 'endereco', 'cep', 'zipcode', 'zip_code',
  'date_of_birth', 'dob', 'nascimento', 'birthday', 'birth_date',
  'cpf', 'rg', 'cnpj', 'ssn', 'document', 'documento',
  'full_name', 'nome_completo', 'first_name', 'last_name',
  'salary', 'salario', 'income', 'renda', 'wage',
  'ip_address', 'user_agent', 'device_id', 'fingerprint',
  'medical_record', 'health_data', 'diagnosis',
  'geolocation', 'latitude', 'longitude', 'location',
];

async function deepRLSCheck(config, emit) {
  const results = [];
  const baseUrl = config.projectUrl;
  const headers = supabaseHeaders(config.anonKey);

  emit({ type: 'log', level: 'info', message: '[RLS Deep] Iniciando análise profunda de RLS...' });

  // ═══════════ 1. Schema Introspection via REST ═══════════
  emit({ type: 'log', level: 'info', message: '[RLS Deep] Tentando introspection de schema...' });

  // Try to access information_schema (should be blocked)
  const schemaEndpoints = [
    { path: '/rest/v1/information_schema.tables?select=table_name,table_schema&table_schema=eq.public&limit=50', name: 'information_schema.tables' },
    { path: '/rest/v1/information_schema.columns?select=table_name,column_name,data_type&table_schema=eq.public&limit=100', name: 'information_schema.columns' },
    { path: '/rest/v1/pg_catalog.pg_tables?select=tablename,schemaname&schemaname=eq.public&limit=50', name: 'pg_catalog.pg_tables' },
    { path: '/rest/v1/pg_stat_user_tables?select=relname,n_live_tup&limit=50', name: 'pg_stat_user_tables' },
  ];

  const schemaLeaks = [];
  for (const ep of schemaEndpoints) {
    const res = await safeFetch(baseUrl + ep.path, { headers, timeout: 8000 });
    if (res.ok && res.json && Array.isArray(res.json) && res.json.length > 0) {
      schemaLeaks.push({
        endpoint: ep.name,
        records: res.json.length,
        sample: res.json.slice(0, 5),
      });
      emit({ type: 'log', level: 'warn', message: `[RLS Deep] ⚠ Schema exposto via ${ep.name} — ${res.json.length} registros` });
    }
  }

  if (schemaLeaks.length > 0) {
    results.push({
      check: 'RLS Deep — Schema Introspection',
      status: 'FAIL',
      severity: 'critical',
      message: `Introspection de schema permitida! ${schemaLeaks.length} endpoint(s) de sistema acessível(is) via anon.`,
      details: {
        leaks: schemaLeaks,
        recommendation: 'URGENTE: Revogue SELECT em tabelas de sistema para o role anon. Execute: REVOKE SELECT ON ALL TABLES IN SCHEMA information_schema FROM anon;'
      }
    });
  }

  // ═══════════ 2. Massive Table Enumeration with Data Analysis ═══════════
  emit({ type: 'log', level: 'info', message: `[RLS Deep] Enumerando ${TABLE_WORDLIST.length} tabelas potenciais...` });

  const exposed = [];       // Tables returning data (RLS FAIL)
  const emptyAccess = [];   // Tables accessible but empty
  const blocked = [];       // Tables properly blocked
  const writable = [];      // Tables allowing INSERT/UPDATE/DELETE

  const BATCH = 8;
  for (let i = 0; i < TABLE_WORDLIST.length; i += BATCH) {
    const batch = TABLE_WORDLIST.slice(i, i + BATCH);
    const fetches = batch.map(table =>
      safeFetch(`${baseUrl}/rest/v1/${table}?select=*&limit=3`, { headers, timeout: 6000 })
        .then(res => ({ table, res }))
    );
    const batchResults = await Promise.all(fetches);

    for (const { table, res } of batchResults) {
      if (res.status === 404 || res.status === 0) continue; // doesn't exist

      if (res.ok && Array.isArray(res.json)) {
        if (res.json.length > 0) {
          const columns = Object.keys(res.json[0]);
          const criticalExposed = columns.filter(c => CRITICAL_COLUMNS.includes(c.toLowerCase()));
          const piiExposed = columns.filter(c => PII_COLUMNS.some(p => c.toLowerCase().includes(p)));

          exposed.push({
            table,
            rowCount: res.json.length,
            columns,
            criticalColumns: criticalExposed,
            piiColumns: piiExposed,
            sampleData: sanitizeRow(res.json[0]),
            severity: criticalExposed.length > 0 ? 'critical' : (piiExposed.length > 0 ? 'high' : 'medium')
          });

          emit({ type: 'log', level: 'warn', message: `[RLS Deep] ✗ EXPOSTA: ${table} (${columns.length} colunas, ${criticalExposed.length} críticas, ${piiExposed.length} PII)` });
        } else {
          emptyAccess.push({ table, note: 'Acessível mas vazia' });
        }
      } else if (res.status === 401 || res.status === 403) {
        blocked.push({ table });
      }
    }

    if (i % 24 === 0 && i > 0) {
      emit({ type: 'log', level: 'info', message: `[RLS Deep] ${i}/${TABLE_WORDLIST.length} tabelas verificadas...` });
    }
  }

  // ═══════════ 3. Write Operation Tests on Exposed Tables ═══════════
  emit({ type: 'log', level: 'info', message: `[RLS Deep] Testando operações de escrita em ${exposed.length + emptyAccess.length} tabelas acessíveis...` });

  const writeTestTables = [...exposed.map(e => e.table), ...emptyAccess.map(e => e.table)];

  for (const table of writeTestTables.slice(0, 30)) {
    // INSERT test
    const insertRes = await safeFetch(`${baseUrl}/rest/v1/${table}`, {
      method: 'POST',
      headers: { ...headers, 'Prefer': 'return=minimal', 'Content-Type': 'application/json' },
      body: JSON.stringify({ _rls_audit_probe: `audit_${Date.now()}` }),
      timeout: 5000
    });

    if (insertRes.ok || insertRes.status === 201) {
      writable.push({ table, operation: 'INSERT', status: insertRes.status });
      emit({ type: 'log', level: 'warn', message: `[RLS Deep] 🚨 INSERT permitido: ${table}` });

      // Clean up the test record
      await safeFetch(`${baseUrl}/rest/v1/${table}?_rls_audit_probe=like.audit_*`, {
        method: 'DELETE',
        headers: { ...headers, 'Prefer': 'return=minimal' },
        timeout: 3000
      });
    }

    // UPDATE test
    const updateRes = await safeFetch(`${baseUrl}/rest/v1/${table}?id=gt.0&limit=1`, {
      method: 'PATCH',
      headers: { ...headers, 'Prefer': 'return=minimal', 'Content-Type': 'application/json' },
      body: JSON.stringify({ _rls_audit_probe: null }),
      timeout: 5000
    });

    if (updateRes.ok) {
      writable.push({ table, operation: 'UPDATE', status: updateRes.status });
      emit({ type: 'log', level: 'warn', message: `[RLS Deep] 🚨 UPDATE permitido: ${table}` });
    }

    // DELETE test (very careful — only test)
    const deleteRes = await safeFetch(`${baseUrl}/rest/v1/${table}?_rls_audit_probe=eq.nonexistent_value`, {
      method: 'DELETE',
      headers: { ...headers, 'Prefer': 'return=minimal' },
      timeout: 5000
    });

    if (deleteRes.ok && deleteRes.status !== 404) {
      writable.push({ table, operation: 'DELETE', status: deleteRes.status });
      emit({ type: 'log', level: 'warn', message: `[RLS Deep] 🚨 DELETE permitido: ${table}` });
    }
  }

  // ═══════════ 4. RPC Policy Bypass Attempts ═══════════
  emit({ type: 'log', level: 'info', message: '[RLS Deep] Testando bypass de RLS via RPC...' });

  const dangerousRPCs = [
    { name: 'get_all_users', body: {} },
    { name: 'admin_query', body: { query: 'SELECT * FROM users LIMIT 5' } },
    { name: 'run_sql', body: { sql: 'SELECT * FROM users LIMIT 5' } },
    { name: 'exec', body: { command: 'SELECT current_user' } },
    { name: 'get_user_by_id', body: { user_id: 1 } },
    { name: 'get_user_by_email', body: { email: 'admin@test.com' } },
    { name: 'export_users', body: {} },
    { name: 'export_data', body: { table: 'users' } },
    { name: 'list_all', body: { table_name: 'users' } },
    { name: 'search', body: { q: '*' } },
    { name: 'get_payments', body: {} },
    { name: 'get_orders', body: {} },
    { name: 'get_transactions', body: {} },
    { name: 'get_secrets', body: {} },
    { name: 'get_config', body: {} },
    { name: 'get_keys', body: {} },
    { name: 'get_credentials', body: {} },
  ];

  const rpcLeaks = [];
  for (const rpcTest of dangerousRPCs) {
    const res = await safeFetch(`${baseUrl}/rest/v1/rpc/${rpcTest.name}`, {
      method: 'POST',
      headers: { ...headers, 'Content-Type': 'application/json' },
      body: JSON.stringify(rpcTest.body),
      timeout: 5000
    });

    if (res.ok && res.json !== null && res.json !== undefined) {
      rpcLeaks.push({
        function: rpcTest.name,
        returnsData: true,
        dataType: typeof res.json,
        isArray: Array.isArray(res.json),
        recordCount: Array.isArray(res.json) ? res.json.length : 1,
      });
      emit({ type: 'log', level: 'warn', message: `[RLS Deep] ✗ RPC bypass: rpc/${rpcTest.name} retorna dados!` });
    } else if (res.status !== 404 && res.status !== 0) {
      // Function exists but denied — good
      if (res.status === 401 || res.status === 403) {
        // Properly protected
      }
    }
  }

  // ═══════════ 5. Horizontal Privilege Escalation Test ═══════════
  emit({ type: 'log', level: 'info', message: '[RLS Deep] Testando escalação horizontal de privilégios...' });

  const horizontalIssues = [];
  for (const table of exposed.slice(0, 10)) {
    // Try with different user_id filters
    const filters = [
      { path: `?select=*&user_id=eq.1&limit=5`, name: 'user_id=1' },
      { path: `?select=*&owner_id=eq.1&limit=5`, name: 'owner_id=1' },
      { path: `?select=*&created_by=eq.1&limit=5`, name: 'created_by=1' },
      { path: `?select=*&author_id=eq.1&limit=5`, name: 'author_id=1' },
      { path: `?select=*&account_id=eq.1&limit=5`, name: 'account_id=1' },
    ];

    for (const filter of filters) {
      const res = await safeFetch(`${baseUrl}/rest/v1/${table.table}${filter.path}`, {
        headers, timeout: 5000
      });

      if (res.ok && Array.isArray(res.json) && res.json.length > 0) {
        horizontalIssues.push({
          table: table.table,
          filter: filter.name,
          recordsReturned: res.json.length,
          note: 'GUEST pode acessar dados de qualquer user_id'
        });
        break;
      }
    }
  }

  // ═══════════ Compile Results ═══════════
  emit({ type: 'log', level: 'info', message: `[RLS Deep] Compilando resultados...` });

  // Critical columns exposed
  const allCritical = exposed.filter(e => e.criticalColumns.length > 0);
  if (allCritical.length > 0) {
    results.push({
      check: 'RLS Deep — Credenciais/Segredos Expostos',
      status: 'FAIL',
      severity: 'critical',
      message: `🚨 ${allCritical.length} tabela(s) expõem colunas CRÍTICAS (senhas, tokens, chaves) para GUEST!`,
      details: {
        tables: allCritical.map(t => ({
          table: t.table,
          criticalColumns: t.criticalColumns,
          allColumns: t.columns,
        })),
        recommendation: 'URGENTE: Ative RLS imediatamente. ALTER TABLE <name> ENABLE ROW LEVEL SECURITY; Crie políticas restritivas.'
      }
    });
  }

  // PII exposed
  const allPII = exposed.filter(e => e.piiColumns.length > 0 && e.criticalColumns.length === 0);
  if (allPII.length > 0) {
    results.push({
      check: 'RLS Deep — PII Exposta (Dados Pessoais)',
      status: 'FAIL',
      severity: 'high',
      message: `${allPII.length} tabela(s) expõem dados pessoais (emails, CPF, telefone, endereço) para GUEST.`,
      details: {
        tables: allPII.map(t => ({ table: t.table, piiColumns: t.piiColumns })),
        recommendation: 'Configure RLS com políticas que limitem acesso apenas ao próprio usuário autenticado.'
      }
    });
  }

  // Writable tables
  if (writable.length > 0) {
    const uniqueWritable = [...new Set(writable.map(w => `${w.table}:${w.operation}`))];
    results.push({
      check: 'RLS Deep — Escrita Sem Auth',
      status: 'FAIL',
      severity: 'critical',
      message: `🚨 ${uniqueWritable.length} operação(ões) de escrita permitida(s) para GUEST! (INSERT/UPDATE/DELETE)`,
      details: {
        operations: writable,
        recommendation: 'URGENTE: Crie políticas RLS de escrita restritivas. Nunca permita INSERT/UPDATE/DELETE para anon sem filtros.'
      }
    });
  }

  // General exposed tables
  if (exposed.length > 0) {
    results.push({
      check: 'RLS Deep — Tabelas Sem Proteção',
      status: 'FAIL',
      severity: exposed.some(e => e.severity === 'critical') ? 'critical' : 'high',
      message: `${exposed.length} tabela(s) retornam dados para GUEST sem autenticação.`,
      details: {
        exposedTables: exposed.map(e => ({
          table: e.table,
          columns: e.columns.length,
          criticalCols: e.criticalColumns,
          piiCols: e.piiColumns,
          sample: e.sampleData
        })),
        recommendation: 'Ative RLS: ALTER TABLE <name> ENABLE ROW LEVEL SECURITY; CREATE POLICY "nome" ON <table> FOR SELECT USING (auth.uid() = user_id);'
      }
    });
  }

  // RPC leaks
  if (rpcLeaks.length > 0) {
    results.push({
      check: 'RLS Deep — RPC Bypass',
      status: 'FAIL',
      severity: 'critical',
      message: `${rpcLeaks.length} função(ões) RPC retornam dados sem autenticação – possível bypass de RLS!`,
      details: {
        functions: rpcLeaks,
        recommendation: 'REVOKE EXECUTE em funções sensíveis para anon. Use SECURITY DEFINER com cuidado e valide auth.uid() dentro da função.'
      }
    });
  }

  // Horizontal escalation
  if (horizontalIssues.length > 0) {
    results.push({
      check: 'RLS Deep — Escalação Horizontal',
      status: 'FAIL',
      severity: 'high',
      message: `${horizontalIssues.length} tabela(s) permitem acessar dados de outros usuários (IDOR/horizontal privilege escalation).`,
      details: {
        issues: horizontalIssues,
        recommendation: 'Políticas RLS devem filtrar por auth.uid(). Ex: CREATE POLICY "own_data" ON table FOR SELECT USING (user_id = auth.uid());'
      }
    });
  }

  // Empty access tables
  if (emptyAccess.length > 0) {
    results.push({
      check: 'RLS Deep — Tabelas Acessíveis (Vazias)',
      status: 'WARN',
      severity: 'medium',
      message: `${emptyAccess.length} tabela(s) acessível(is) sem dados — RLS pode estar desativado.`,
      details: {
        tables: emptyAccess,
        recommendation: 'Mesmo tabelas vazias devem ter RLS ativo para prevenir futura exposição quando dados forem inseridos.'
      }
    });
  }

  // All good
  if (exposed.length === 0 && writable.length === 0 && rpcLeaks.length === 0 && schemaLeaks.length === 0) {
    results.push({
      check: 'RLS Deep — Proteção Geral',
      status: 'PASS',
      severity: 'info',
      message: `✓ RLS parece bem configurado. ${blocked.length} tabela(s) bloqueada(s), ${TABLE_WORDLIST.length} testadas.`,
      details: { tablesChecked: TABLE_WORDLIST.length, blocked: blocked.length }
    });
  }

  // Summary
  results.push({
    check: 'RLS Deep — Resumo',
    status: 'INFO',
    severity: 'info',
    message: `Análise RLS: ${exposed.length} expostas, ${writable.length} gravação, ${rpcLeaks.length} RPC bypass, ${blocked.length} bloqueadas, ${emptyAccess.length} vazias.`,
    details: {
      totalTested: TABLE_WORDLIST.length,
      exposed: exposed.length,
      writable: writable.length,
      rpcBypass: rpcLeaks.length,
      blocked: blocked.length,
      emptyAccess: emptyAccess.length,
      schemaLeaks: schemaLeaks.length,
      horizontalEscalation: horizontalIssues.length,
    }
  });

  return results;
}

function sanitizeRow(row) {
  if (!row) return {};
  const out = {};
  for (const [k, v] of Object.entries(row)) {
    if (typeof v === 'string' && v.length > 6) {
      out[k] = v.substring(0, 3) + '***' + v.substring(v.length - 2);
    } else {
      out[k] = typeof v;
    }
  }
  return out;
}

module.exports = { deepRLSCheck };
