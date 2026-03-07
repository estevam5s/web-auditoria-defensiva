/*  CHECK: Realtime Channel Exposure
    Tests if Realtime WebSocket channels can be subscribed to anonymously */

const { safeFetch, supabaseHeaders } = require('../helpers/http');

async function checkRealtimeExposure(config) {
  const results = [];
  const baseUrl = config.projectUrl;
  const anonKey = config.anonKey;
  const headers = supabaseHeaders(anonKey);

  // 1. Check Realtime health endpoint
  const healthUrl = `${baseUrl}/realtime/v1/api/health`;
  const healthRes = await safeFetch(healthUrl, { headers, timeout: 8000 });

  const isActive = healthRes.ok || healthRes.status === 200;

  if (isActive) {
    results.push({
      check: 'Realtime — Health',
      status: 'INFO',
      severity: 'info',
      message: 'Endpoint de health do Realtime está acessível.',
      details: { url: healthUrl, response: healthRes.json || healthRes.text?.substring(0, 200) }
    });
  }

  // 2. Check WebSocket upgrade endpoint with anon key
  const wsUpgradeUrl = `${baseUrl}/realtime/v1/websocket?apikey=${anonKey || ''}&vsn=1.0.0`;
  const upgradeRes = await safeFetch(wsUpgradeUrl, { headers, timeout: 8000 });

  // Supabase Realtime accepts WS upgrades: status 101 (switching), 200, or 400 (bad WS)
  const wsReachable = upgradeRes.status === 101 || upgradeRes.status === 200 || upgradeRes.status === 400;

  // 3. Test channel join via Phoenix longpoll (HTTP fallback for WS)
  // Supabase Realtime Phoenix server responds on /realtime/v1/longpoll when accessed with POST
  let channelJoinSucceeded = false;
  let channelJoinDetails = null;

  if (anonKey) {
    // Phoenix protocol: JOIN message
    const joinPayload = {
      topic: 'realtime:*',
      event: 'phx_join',
      payload: { access_token: anonKey },
      ref: '1'
    };

    const longpollRes = await safeFetch(`${baseUrl}/realtime/v1/longpoll`, {
      method: 'POST',
      headers: { ...headers, 'Content-Type': 'application/json' },
      body: JSON.stringify(joinPayload),
      timeout: 6000
    });

    if (longpollRes.ok || longpollRes.status === 200) {
      channelJoinSucceeded = true;
      channelJoinDetails = { method: 'longpoll', status: longpollRes.status };
    }

    // Also try via WS endpoint probe — if it responds with 400 (not 401/403), the channel is accessible
    if (!channelJoinSucceeded && upgradeRes.status === 400) {
      // 400 on WS upgrade usually means "bad handshake" not "unauthorized" — channel join would succeed
      channelJoinSucceeded = true;
      channelJoinDetails = { method: 'ws_probe', status: 400, note: 'WS endpoint acessível sem erro de autenticação' };
    }
  }

  // 4. Test WITHOUT any auth (no apikey)
  const noAuthUpgrade = await safeFetch(`${baseUrl}/realtime/v1/websocket?vsn=1.0.0`, {
    headers: { 'Content-Type': 'application/json' },
    timeout: 6000
  });

  const noAuthReachable = noAuthUpgrade.status !== 401 && noAuthUpgrade.status !== 403 && noAuthUpgrade.status !== 0;

  // 5. Compile results
  if (channelJoinSucceeded) {
    results.push({
      check: 'Realtime — Channel Join Anônimo',
      status: 'WARN',
      severity: 'high',
      message: 'Realtime permite join de canal com anon key. Dados em tempo real podem ser acessíveis.',
      details: {
        supported: true,
        connected: wsReachable,
        joined: channelJoinSucceeded,
        method: channelJoinDetails?.method,
        recommendation: 'Configure Realtime RLS policies para controlar quais dados são transmitidos via Realtime channels.'
      }
    });
  } else if (wsReachable) {
    results.push({
      check: 'Realtime — WebSocket',
      status: 'WARN',
      severity: 'medium',
      message: 'Endpoint WebSocket Realtime está ativo e acessível.',
      details: {
        url: wsUpgradeUrl,
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

  if (noAuthReachable && noAuthUpgrade.status !== 400) {
    results.push({
      check: 'Realtime — Acesso Sem Auth',
      status: 'WARN',
      severity: 'medium',
      message: 'Realtime responde sem apikey.',
      details: {
        status: noAuthUpgrade.status,
        recommendation: 'Verifique se o Realtime exige autenticação. Configure JWT verification no Realtime.'
      }
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
