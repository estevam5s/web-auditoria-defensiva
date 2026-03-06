/*  CHECK: RLS (Row Level Security) Status
    Tests if tables have RLS enabled via indirect detection */

const { safeFetch, supabaseHeaders } = require('../helpers/http');

async function checkRLSStatus(config) {
  const results = [];
  const baseUrl = config.projectUrl;
  const headers = supabaseHeaders(config.anonKey);

  // RLS can be indirectly tested by trying to access tables
  // If a table returns data without auth, RLS is likely disabled

  const testTables = [
    'users', 'profiles', 'accounts', 'posts', 'orders',
    'products', 'customers', 'messages', 'settings', 'admin',
    'payments', 'transactions', 'sessions', 'tokens', 'roles',
    'permissions', 'notifications', 'comments', 'documents', 'files',
    'logs', 'api_keys', 'secrets', 'config', 'metadata'
  ];

  const tablesWithoutRLS = [];
  const tablesWithRLS = [];

  for (const table of testTables) {
    // Try SELECT  as anon
    const url = `${baseUrl}/rest/v1/${table}?select=*&limit=1`;
    const res = await safeFetch(url, { headers, timeout: 5000 });

    if (res.status === 404 || res.status === 0) continue; // Table doesn't exist

    if (res.ok && Array.isArray(res.json)) {
      if (res.json.length > 0) {
        tablesWithoutRLS.push({
          table,
          hasData: true,
          columns: Object.keys(res.json[0]),
          sampleRow: Object.fromEntries(
            Object.entries(res.json[0]).map(([k, v]) => [k, typeof v === 'string' && v.length > 50 ? v.substring(0, 50) + '...' : v])
          )
        });
      } else {
        // Empty result could mean RLS blocks data or table is empty
        tablesWithRLS.push({ table, note: 'Tabela acessível mas sem dados (RLS pode estar ativo)' });
      }
    } else if (res.status === 401 || res.status === 403) {
      tablesWithRLS.push({ table, note: 'Acesso negado (RLS provavelmente ativo)' });
    }

    // Test INSERT attempt
    const insertUrl = `${baseUrl}/rest/v1/${table}`;
    const insertRes = await safeFetch(insertUrl, {
      method: 'POST',
      headers: { ...headers, 'Prefer': 'return=minimal' },
      body: JSON.stringify({ _audit_test: true }),
      timeout: 5000
    });

    if (insertRes.ok || insertRes.status === 201) {
      tablesWithoutRLS.push({
        table,
        vulnerability: 'INSERT permitido via anon!',
        severity: 'critical'
      });
    }

    // Test DELETE attempt (dry)
    const deleteUrl = `${baseUrl}/rest/v1/${table}?_audit_test=eq.true`;
    const deleteRes = await safeFetch(deleteUrl, {
      method: 'DELETE',
      headers: { ...headers, 'Prefer': 'return=minimal' },
      timeout: 5000
    });

    if (deleteRes.ok) {
      tablesWithoutRLS.push({
        table,
        vulnerability: 'DELETE permitido via anon!',
        severity: 'critical'
      });
    }
  }

  if (tablesWithoutRLS.length > 0) {
    const criticals = tablesWithoutRLS.filter(t => t.vulnerability);
    results.push({
      check: 'RLS — Tables Without Protection',
      status: 'FAIL',
      severity: criticals.length > 0 ? 'critical' : 'high',
      message: `${tablesWithoutRLS.length} tabela(s) sem proteção RLS adequada. ${criticals.length > 0 ? `${criticals.length} permitem operações de escrita!` : ''}`,
      details: {
        unprotected: tablesWithoutRLS,
        recommendation: 'Ative RLS em todas as tabelas: ALTER TABLE nome ENABLE ROW LEVEL SECURITY; e crie políticas adequadas.'
      }
    });
  }

  if (tablesWithRLS.length > 0) {
    results.push({
      check: 'RLS — Protected Tables',
      status: 'PASS',
      severity: 'info',
      message: `${tablesWithRLS.length} tabela(s) com proteção RLS ativa. ✓`,
      details: { tables: tablesWithRLS }
    });
  }

  if (tablesWithoutRLS.length === 0 && tablesWithRLS.length === 0) {
    results.push({
      check: 'RLS — Table Detection',
      status: 'INFO',
      severity: 'info',
      message: 'Nenhuma tabela comum detectada. Considere verificar manualmente.',
      details: null
    });
  }

  return results;
}

module.exports = { checkRLSStatus };
