/*  CHECK: REST API Exposure
    Tests if PostgREST is publicly accessible and leaks table structure */

const { safeFetch, supabaseHeaders } = require('../helpers/http');

async function checkRESTExposure(config) {
  const results = [];
  const baseUrl = config.projectUrl;
  const headers = supabaseHeaders(config.anonKey);

  // 1. Check if REST endpoint responds
  const restUrl = `${baseUrl}/rest/v1/`;
  const res = await safeFetch(restUrl, { headers });

  if (res.status === 0) {
    results.push({
      check: 'REST API — Connectivity',
      status: 'ERROR',
      severity: 'info',
      message: `Não foi possível conectar ao endpoint REST: ${res.statusText}`,
      details: { url: restUrl }
    });
    return results;
  }

  // 2. Check OpenAPI/Swagger schema exposure
  const schemaUrl = `${baseUrl}/rest/v1/?apikey=${config.anonKey || ''}`;
  const schemaRes = await safeFetch(schemaUrl, { headers });

  if (schemaRes.ok && schemaRes.json) {
    const tables = schemaRes.json;
    if (Array.isArray(tables) || (typeof tables === 'object' && tables.definitions)) {
      results.push({
        check: 'REST API — Schema Exposure',
        status: 'WARN',
        severity: 'medium',
        message: 'O schema REST/OpenAPI está acessível publicamente. Tabelas e colunas podem ser enumeradas.',
        details: {
          url: schemaUrl,
          hint: 'Configure RLS e limite as tabelas expostas via Dashboard > API Settings'
        }
      });
    }
  }

  // 3. Try to enumerate common table names
  const commonTables = [
    'users', 'profiles', 'accounts', 'posts', 'orders', 'payments',
    'products', 'customers', 'messages', 'notifications', 'settings',
    'admin', 'logs', 'sessions', 'tokens', 'documents', 'files',
    'comments', 'roles', 'permissions', 'api_keys', 'secrets'
  ];

  const exposedTables = [];

  for (const table of commonTables) {
    const tableUrl = `${baseUrl}/rest/v1/${table}?select=*&limit=1`;
    const tableRes = await safeFetch(tableUrl, { headers, timeout: 5000 });

    if (tableRes.ok && tableRes.json && Array.isArray(tableRes.json)) {
      exposedTables.push({
        table,
        hasData: tableRes.json.length > 0,
        columns: tableRes.json.length > 0 ? Object.keys(tableRes.json[0]) : [],
        sampleCount: tableRes.json.length
      });
    }
  }

  if (exposedTables.length > 0) {
    const withData = exposedTables.filter(t => t.hasData);
    results.push({
      check: 'REST API — Table Exposure',
      status: 'FAIL',
      severity: withData.length > 0 ? 'critical' : 'high',
      message: `${exposedTables.length} tabela(s) acessíveis via REST API. ${withData.length} contêm dados.`,
      details: {
        tables: exposedTables,
        recommendation: 'Ative RLS em todas as tabelas e revogue permissões do role anon para tabelas sensíveis.'
      }
    });
  } else {
    results.push({
      check: 'REST API — Table Exposure',
      status: 'PASS',
      severity: 'info',
      message: 'Nenhuma tabela comum encontrada exposta via REST API (GUEST).',
      details: null
    });
  }

  // 4. Check if SELECT * returns data without auth
  const noAuthRes = await safeFetch(`${baseUrl}/rest/v1/`, {
    headers: { 'Content-Type': 'application/json' }
  });

  if (noAuthRes.ok) {
    results.push({
      check: 'REST API — No Auth Access',
      status: 'WARN',
      severity: 'high',
      message: 'REST API responde sem apikey/Authorization header.',
      details: {
        status: noAuthRes.status,
        hint: 'Verifique se o endpoint requer autenticação.'
      }
    });
  } else {
    results.push({
      check: 'REST API — Auth Required',
      status: 'PASS',
      severity: 'info',
      message: 'REST API requer autenticação (apikey/Authorization).',
      details: { status: noAuthRes.status }
    });
  }

  return results;
}

module.exports = { checkRESTExposure };
