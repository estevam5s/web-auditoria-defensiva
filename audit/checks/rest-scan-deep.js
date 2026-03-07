/*  ═══════════════════════════════════════════════════════════════════
    REST SCAN DEEP: Comprehensive Table Testing
    Tests each table individually with anon key
    Verifies data exposure, record counts, and permissions
    ═══════════════════════════════════════════════════════════════════ */

const { safeFetch, supabaseHeaders } = require('../helpers/http');

const SENSITIVE_COLUMNS = [
  'password', 'password_hash', 'password_digest', 'hashed_password',
  'secret', 'token', 'access_token', 'refresh_token', 'api_key',
  'apikey', 'private_key', 'secret_key', 'encryption_key',
  'ssn', 'cpf', 'cpf_cnpj', 'document', 'passport', 'driver_license',
  'credit_card', 'card_number', 'cvv', 'billing_info',
  'address', 'phone', 'mobile', 'telephone', 'birth_date', 'birthday',
  'dob', 'social_security', 'national_id', 'identity_document',
  'pin', 'security_question', 'security_answer',
  'recovery_email', 'recovery_phone', 'backup_code',
  'ip_address', 'last_login_ip', 'login_ip',
  'session', 'session_id', 'cookie',
  'balance', 'account_balance', 'wallet_balance',
  'admin', 'is_admin', 'role', 'user_role', 'privileges',
  'enabled', 'active', 'verified', 'confirmed', 'status'
];

const SENSITIVE_TABLES = [
  'users', 'accounts', 'admins', 'operators', 'employees',
  'api_keys', 'secrets', 'credentials', 'passwords',
  'payments', 'transactions', 'invoices', 'billing',
  'customers', 'clients', 'members', 'members_private'
];

async function restScanDeep(config, emit, catalog = null) {
  const results = [];
  const baseUrl = config.projectUrl;
  const anonKey = config.anonKey;
  const headers = supabaseHeaders(anonKey);

  const tableTests = [];
  const exposedTables = [];
  const writableTables = [];

  // Use catalog from parameter, or from config (set by openapi-introspection)
  const activeCatalog = catalog || config._catalog;

  const tablesToTest = activeCatalog && activeCatalog.tables && activeCatalog.tables.length > 0
    ? activeCatalog.tables.map(t => t.name)
    : [
        'users', 'profiles', 'accounts', 'posts', 'orders', 'payments',
        'products', 'customers', 'messages', 'notifications', 'settings',
        'admin', 'logs', 'sessions', 'tokens', 'documents', 'files',
        'comments', 'roles', 'permissions', 'api_keys', 'secrets',
        'categories', 'tags', 'media', 'attachments', 'events'
      ];

  emit({ type: 'log', level: 'info', message: `[REST Deep] Escaneando ${tablesToTest.length} tabelas REST...` });

  const BATCH_SIZE = 8;
  let tested = 0;

  for (let i = 0; i < tablesToTest.length; i += BATCH_SIZE) {
    const batch = tablesToTest.slice(i, i + BATCH_SIZE);
    const promises = batch.map(async (tableName) => {
      const testResult = {
        table: tableName,
        readable: false,
        writable: false,
        recordCount: 0,
        exposedColumns: [],
        sensitiveColumns: [],
        severity: 'low',
        sampleData: null
      };

      const tableUrl = `${baseUrl}/rest/v1/${tableName}`;

      const selectRes = await safeFetch(`${tableUrl}?select=*&limit=500&offset=0`, {
        headers: { ...headers, 'Prefer': 'count=exact' },
        timeout: 8000
      });

      if (selectRes.ok && Array.isArray(selectRes.json)) {
        testResult.readable = true;
        // Get total count from Content-Range header if available, else use array length
        const contentRange = selectRes.headers?.['content-range'];
        const totalCount = contentRange ? parseInt(contentRange.split('/')[1]) || selectRes.json.length : selectRes.json.length;
        testResult.recordCount = totalCount;

        if (selectRes.json.length > 0) {
          testResult.exposedColumns = Object.keys(selectRes.json[0]);
          testResult.sampleData = selectRes.json.slice(0, 2);

          testResult.sensitiveColumns = testResult.exposedColumns.filter(col =>
            SENSITIVE_COLUMNS.some(s => col.toLowerCase().includes(s.toLowerCase()))
          );

          if (SENSITIVE_TABLES.some(t => tableName.toLowerCase().includes(t))) {
            testResult.severity = 'critical';
          } else if (testResult.sensitiveColumns.length > 0) {
            testResult.severity = 'high';
          } else {
            testResult.severity = 'medium';
          }
        }
      }

      const countRes = await safeFetch(`${tableUrl}?select=count`, { headers, timeout: 5000 });
      if (countRes.ok && countRes.json && countRes.json[0]?.count) {
        testResult.recordCount = countRes.json[0].count;
      }

      const insertRes = await safeFetch(tableUrl, {
        method: 'POST',
        headers: { ...headers, 'Prefer': 'return=minimal' },
        body: JSON.stringify({ _test_audit: true })
      });

      if (insertRes.status === 201 || insertRes.status === 200) {
        testResult.writable = true;
        testResult.severity = 'critical';
      } else if (insertRes.status === 403 || insertRes.status === 425) {
        testResult.writable = false;
      }

      const updateRes = await safeFetch(`${tableUrl}?select=*&limit=1`, {
        method: 'PATCH',
        headers: { ...headers, 'Prefer': 'return=minimal' },
        body: JSON.stringify({ _test_audit_update: true })
      });

      if (updateRes.status === 200 || updateRes.status === 204) {
        testResult.writable = true;
        testResult.severity = 'critical';
      }

      const deleteRes = await safeFetch(`${tableUrl}?select=*&limit=1`, {
        method: 'DELETE',
        headers: { ...headers, 'Prefer': 'return=minimal' }
      });

      if (deleteRes.status === 200 || deleteRes.status === 204) {
        testResult.writable = true;
        testResult.severity = 'critical';
      }

      return testResult;
    });

    const batchResults = await Promise.all(promises);
    for (const result of batchResults) {
      tested++;
      tableTests.push(result);

      if (result.readable) {
        exposedTables.push(result);

        if (result.writable) {
          writableTables.push(result);
        }
      }
    }

    // Log each exposed table like SupabaseGuard does
    for (const result of batchResults) {
      if (result.readable) {
        const level = result.recordCount > 0 ? 'warn' : 'info';
        emit({ type: 'log', level, message: `[REST Deep] GUEST /rest/v1/${result.table}?select=*&limit=500&offset=0 -> 200 rows=${result.recordCount}` });
        if (result.recordCount > 0) {
          emit({ type: 'log', level: 'warn', message: `[REST Deep] Tabela exposta: '${result.table}' retornou ${result.recordCount} registro(s) para GUEST.` });
        }
      }
    }

    if (tested % 20 === 0 && tested > 0) {
      emit({ type: 'log', level: 'info', message: `[REST Deep] ${tested}/${tablesToTest.length} tabelas...` });
    }
  }

  emit({ type: 'log', level: 'info', message: `[REST Deep] ${exposedTables.length} tabelas expostas, ${writableTables.length} graváveis` });

  if (exposedTables.length > 0) {
    const criticalTables = exposedTables.filter(t => t.severity === 'critical');
    const highTables = exposedTables.filter(t => t.severity === 'high');

    results.push({
      check: 'REST Deep — Table Exposure',
      status: criticalTables.length > 0 ? 'FAIL' : 'WARN',
      severity: criticalTables.length > 0 ? 'critical' : 'high',
      message: `${exposedTables.length} tabela(s) exposta(s) via REST API. ${writableTables.length} permite(m) gravação!`,
      details: {
        totalExposed: exposedTables.length,
        writableCount: writableTables.length,
        tables: exposedTables.map(t => ({
          name: t.table,
          readable: t.readable,
          writable: t.writable,
          recordCount: t.recordCount,
          columns: t.exposedColumns.length,
          sensitiveColumns: t.sensitiveColumns,
          severity: t.severity
        })),
        recommendation: 'Ative RLS em todas as tabelas. Revoque permissões do role anon para tabelas sensíveis.'
      }
    });

    const tablesWithSensitiveData = exposedTables.filter(t => t.sensitiveColumns.length > 0);
    if (tablesWithSensitiveData.length > 0) {
      results.push({
        check: 'REST Deep — Sensitive Columns Exposed',
        status: 'FAIL',
        severity: 'critical',
        message: `${tablesWithSensitiveData.length} tabela(s) expõe(m) colunas sensíveis!`,
        details: {
          tables: tablesWithSensitiveData.map(t => ({
            table: t.table,
            sensitiveColumns: t.sensitiveColumns,
            severity: t.severity
          })),
          recommendation: 'Oculte colunas sensíveis via RLS policies ou remova do select padrão.'
        }
      });
    }
  } else {
    results.push({
      check: 'REST Deep — Table Exposure',
      status: 'PASS',
      severity: 'info',
      message: 'Nenhuma tabela exposta com a anon key.',
      details: { tablesTested: tested }
    });
  }

  return { results, tableTests };
}

module.exports = { restScanDeep };
