/*  CHECK: Realtime Channel Exposure
    Tests if Realtime WebSocket channels can be subscribed to */

const { safeFetch, supabaseHeaders } = require('../helpers/http');

async function checkRealtimeExposure(config) {
  const results = [];
  const baseUrl = config.projectUrl;
  const headers = supabaseHeaders(config.anonKey);

  // 1. Check Realtime HTTP endpoint
  const realtimeUrl = `${baseUrl}/realtime/v1`;
  const res = await safeFetch(realtimeUrl, { headers });

  if (res.status === 0) {
    results.push({
      check: 'Realtime — Endpoint',
      status: 'INFO',
      severity: 'info',
      message: 'Endpoint Realtime não respondeu (pode usar apenas WebSocket).',
      details: { url: realtimeUrl }
    });
  }

  // 2. Check WebSocket upgrade endpoint
  const wsUrl = baseUrl.replace('https://', 'wss://').replace('http://', 'ws://');
  const wsEndpoint = `${wsUrl}/realtime/v1/websocket?apikey=${config.anonKey || ''}&vsn=1.0.0`;

  // We can't do a full WebSocket test in simple HTTP, but we can check the upgrade endpoint
  const upgradeUrl = `${baseUrl}/realtime/v1/websocket?apikey=${config.anonKey || ''}&vsn=1.0.0`;
  const upgradeRes = await safeFetch(upgradeUrl, { headers });

  if (upgradeRes.status === 101 || upgradeRes.status === 200 || upgradeRes.status === 400) {
    results.push({
      check: 'Realtime — WebSocket',
      status: 'WARN',
      severity: 'medium',
      message: 'Endpoint WebSocket Realtime está ativo e acessível.',
      details: {
        url: wsEndpoint,
        status: upgradeRes.status,
        recommendation: 'Configure RLS nas tabelas para controlar quais dados são transmitidos via Realtime. Use Realtime policies.'
      }
    });
  } else {
    results.push({
      check: 'Realtime — WebSocket',
      status: 'PASS',
      severity: 'info',
      message: 'Endpoint WebSocket Realtime não está acessível publicamente.',
      details: { status: upgradeRes.status }
    });
  }

  // 3. Check Realtime health
  const healthUrl = `${baseUrl}/realtime/v1/api/health`;
  const healthRes = await safeFetch(healthUrl, { headers });

  if (healthRes.ok) {
    results.push({
      check: 'Realtime — Health Endpoint',
      status: 'INFO',
      severity: 'low',
      message: 'Endpoint de health do Realtime está acessível.',
      details: { url: healthUrl, response: healthRes.json || healthRes.text?.substring(0, 200) }
    });
  }

  // 4. Check without auth
  const noAuthRes = await safeFetch(upgradeUrl.replace(config.anonKey || '', ''), {
    headers: {}
  });

  if (noAuthRes.status !== 401 && noAuthRes.status !== 403 && noAuthRes.status !== 0) {
    results.push({
      check: 'Realtime — No Auth Access',
      status: 'WARN',
      severity: 'medium',
      message: 'Realtime responde sem apikey.',
      details: { status: noAuthRes.status }
    });
  }

  if (results.length === 0) {
    results.push({
      check: 'Realtime — General',
      status: 'PASS',
      severity: 'info',
      message: 'Nenhum problema de exposição Realtime detectado.',
      details: null
    });
  }

  return results;
}

module.exports = { checkRealtimeExposure };
