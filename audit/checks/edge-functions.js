/*  CHECK: Edge Functions Exposure
    Tests if Edge Functions are discoverable and callable */

const { safeFetch, supabaseHeaders } = require('../helpers/http');

async function checkEdgeFunctions(config) {
  const results = [];
  const baseUrl = config.projectUrl;
  const headers = supabaseHeaders(config.anonKey);

  // Common Edge Function names to probe
  const commonFunctions = [
    'hello', 'test', 'ping', 'health', 'status',
    'webhook', 'stripe-webhook', 'payment', 'checkout',
    'send-email', 'notify', 'notification',
    'admin', 'auth', 'login', 'register', 'signup',
    'api', 'proxy', 'cors-proxy',
    'generate', 'process', 'upload',
    'cron', 'scheduler', 'sync',
    'export', 'import', 'backup',
    'search', 'AI', 'openai', 'chat',
    'resend', 'send-sms'
  ];

  const discoveredFunctions = [];

  for (const fn of commonFunctions) {
    const fnUrl = `${baseUrl}/functions/v1/${fn}`;
    
    // Try GET
    const getRes = await safeFetch(fnUrl, { headers, timeout: 5000 });
    
    if (getRes.status !== 404 && getRes.status !== 0) {
      discoveredFunctions.push({
        name: fn,
        method: 'GET',
        status: getRes.status,
        responseSize: getRes.text?.length || 0,
        hasBody: getRes.text?.length > 0,
        contentType: getRes.headers?.['content-type'] || 'unknown'
      });
      continue;
    }

    // Try POST
    const postRes = await safeFetch(fnUrl, {
      method: 'POST',
      headers,
      body: JSON.stringify({}),
      timeout: 5000
    });

    if (postRes.status !== 404 && postRes.status !== 0) {
      discoveredFunctions.push({
        name: fn,
        method: 'POST',
        status: postRes.status,
        responseSize: postRes.text?.length || 0,
        hasBody: postRes.text?.length > 0,
        contentType: postRes.headers?.['content-type'] || 'unknown'
      });
    }
  }

  if (discoveredFunctions.length > 0) {
    const accessible = discoveredFunctions.filter(f => f.status >= 200 && f.status < 400);
    results.push({
      check: 'Edge Functions — Discovery',
      status: accessible.length > 0 ? 'WARN' : 'INFO',
      severity: accessible.length > 0 ? 'medium' : 'low',
      message: `${discoveredFunctions.length} Edge Function(s) descoberta(s). ${accessible.length} acessível(is).`,
      details: {
        functions: discoveredFunctions,
        recommendation: 'Verifique se Edge Functions sensíveis requerem auth. Use verify JWT no handler.'
      }
    });

    // Check each discovered function without auth
    for (const fn of accessible) {
      const noAuthRes = await safeFetch(`${baseUrl}/functions/v1/${fn.name}`, {
        method: fn.method,
        headers: { 'Content-Type': 'application/json' },
        body: fn.method === 'POST' ? JSON.stringify({}) : undefined,
        timeout: 5000
      });

      if (noAuthRes.ok) {
        results.push({
          check: `Edge Function — "${fn.name}" No Auth`,
          status: 'WARN',
          severity: 'medium',
          message: `Edge Function "${fn.name}" acessível sem Authorization header.`,
          details: { name: fn.name, status: noAuthRes.status }
        });
      }
    }
  } else {
    results.push({
      check: 'Edge Functions — Discovery',
      status: 'PASS',
      severity: 'info',
      message: 'Nenhuma Edge Function comum descoberta via enumeração.',
      details: null
    });
  }

  return results;
}

module.exports = { checkEdgeFunctions };
