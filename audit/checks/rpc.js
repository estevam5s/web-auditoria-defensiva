/*  CHECK: RPC (Remote Procedure Call) Exposure
    Tests if PostgREST RPC functions are callable without auth */

const { safeFetch, supabaseHeaders } = require('../helpers/http');

async function checkRPCExposure(config) {
  const results = [];
  const baseUrl = config.projectUrl;
  const headers = supabaseHeaders(config.anonKey);

  // Common dangerous RPC function names
  const commonRPCs = [
    'get_users', 'get_all_users', 'list_users', 'search_users',
    'get_admin', 'admin_query', 'run_query', 'exec_sql',
    'get_secret', 'get_config', 'get_settings', 'get_env',
    'delete_user', 'update_role', 'grant_admin',
    'get_orders', 'get_payments', 'get_transactions',
    'export_data', 'backup', 'get_logs',
    'create_user', 'reset_password', 'generate_token'
  ];

  const exposedRPCs = [];

  for (const fn of commonRPCs) {
    const rpcUrl = `${baseUrl}/rest/v1/rpc/${fn}`;
    const res = await safeFetch(rpcUrl, {
      method: 'POST',
      headers,
      body: JSON.stringify({}),
      timeout: 5000
    });

    // If we get anything other than 404, the function exists
    if (res.status !== 404 && res.status !== 0) {
      exposedRPCs.push({
        function: fn,
        status: res.status,
        returnsData: res.ok && res.json !== null,
        response: res.ok ? (typeof res.json === 'string' ? res.json.substring(0, 200) : 'data returned') : res.statusText
      });
    }
  }

  if (exposedRPCs.length > 0) {
    const callable = exposedRPCs.filter(r => r.returnsData);
    results.push({
      check: 'RPC — Function Exposure',
      status: 'FAIL',
      severity: callable.length > 0 ? 'critical' : 'high',
      message: `${exposedRPCs.length} função(ões) RPC descoberta(s). ${callable.length} retornam dados.`,
      details: {
        functions: exposedRPCs,
        recommendation: 'Revogue EXECUTE no role anon para funções sensíveis. Use SECURITY DEFINER com cuidado.'
      }
    });
  } else {
    results.push({
      check: 'RPC — Function Exposure',
      status: 'PASS',
      severity: 'info',
      message: 'Nenhuma função RPC comum encontrada exposta ao role anon.',
      details: null
    });
  }

  // Check RPC without auth
  const noAuthRes = await safeFetch(`${baseUrl}/rest/v1/rpc/get_users`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({}),
    timeout: 5000
  });

  if (noAuthRes.ok) {
    results.push({
      check: 'RPC — No Auth Execution',
      status: 'FAIL',
      severity: 'critical',
      message: 'Funções RPC podem ser executadas sem autenticação!',
      details: { status: noAuthRes.status }
    });
  }

  return results;
}

module.exports = { checkRPCExposure };
