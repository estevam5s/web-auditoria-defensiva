/*  ═══════════════════════════════════════════════════════════════════
    TAILSCALE & NETWORK SECURITY CHECK
    Detects VPN/Tailscale exposure, private network leaks, mesh network
    security, network segmentation issues, and WireGuard endpoints.
    ═══════════════════════════════════════════════════════════════════ */

const https = require('https');
const http  = require('http');
const dns   = require('dns').promises;
const net   = require('net');

// Tailscale DERP relay servers (Tailscale's relay infrastructure)
const TAILSCALE_DERP_REGIONS = [
  { region: 'New York', host: 'derp1.tailscale.com' },
  { region: 'San Francisco', host: 'derp2.tailscale.com' },
  { region: 'Amsterdam', host: 'derp3.tailscale.com' },
  { region: 'Singapore', host: 'derp4.tailscale.com' },
  { region: 'São Paulo', host: 'derp5.tailscale.com' },
];

// Tailscale magic DNS patterns
const TAILSCALE_PATTERNS = [
  /\.ts\.net$/,
  /100\.\d+\.\d+\.\d+/,   // Tailscale IP range (CGNAT 100.64.0.0/10)
  /tailscale/i,
  /tailnet/i,
];

// WireGuard default ports
const WIREGUARD_PORTS = [51820, 51821, 51822];

// Common VPN/network management paths
const VPN_PATHS = [
  '/vpn', '/vpn/', '/vpn/login', '/vpn/status',
  '/tailscale', '/tailscale/status', '/tailscale/peers',
  '/wireguard', '/wg', '/wg/status',
  '/openvpn', '/ovpn',
  '/netdata', '/netdata/',
  '/prometheus', '/prometheus/',
  '/grafana', '/grafana/',
  '/portainer', '/portainer/',
  '/_derp', '/derp',
  '/ts/status', '/ts/peers',
  '/network', '/network/status',
  '/.well-known/tailscale',
  '/api/v1/network',
  '/api/network/status',
  '/mgmt', '/management',
  '/network-status',
  '/internal/network',
  '/healthz/network',
];

// Private IP ranges
const PRIVATE_IP_RANGES = [
  /^10\./,
  /^172\.(1[6-9]|2\d|3[01])\./,
  /^192\.168\./,
  /^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./,  // CGNAT (Tailscale)
  /^169\.254\./,  // Link-local
  /^fc00:/,       // IPv6 ULA
  /^fe80:/,       // IPv6 link-local
];

function isPrivateIP(ip) {
  return PRIVATE_IP_RANGES.some(r => r.test(ip));
}

function isTailscaleIP(ip) {
  // Tailscale uses 100.64.0.0/10 (CGNAT range)
  const match = ip.match(/^100\.(\d+)\./);
  if (match) {
    const second = parseInt(match[1]);
    return second >= 64 && second <= 127;
  }
  return false;
}

function httpGet(rawUrl, opts = {}) {
  return new Promise(resolve => {
    const t0 = Date.now();
    let done = false;
    const finish = d => { if (!done) { done = true; resolve({ ...d, ms: Date.now() - t0 }); } };

    try {
      const u = new URL(rawUrl);
      const lib = u.protocol === 'https:' ? https : http;
      const req = lib.get({
        hostname: u.hostname,
        port: u.port || (u.protocol === 'https:' ? 443 : 80),
        path: u.pathname + u.search,
        headers: {
          'User-Agent': 'SupabaseGuard-SecurityAudit/3.1',
          'Accept': '*/*',
          ...(opts.headers || {})
        },
        rejectUnauthorized: false,
        timeout: opts.timeout || 5000
      }, res => {
        let body = '';
        res.on('data', c => body += c);
        res.on('end', () => {
          let json = null;
          try { json = JSON.parse(body); } catch {}
          finish({ status: res.statusCode, headers: res.headers, body, json, error: null });
        });
      });
      req.on('error', e => finish({ status: 0, headers: {}, body: '', json: null, error: e.message }));
      req.on('timeout', () => { req.destroy(); finish({ status: 0, headers: {}, body: '', json: null, error: 'timeout' }); });
    } catch (e) {
      finish({ status: 0, headers: {}, body: '', json: null, error: e.message });
    }
  });
}

function tcpPortCheck(host, port, timeoutMs = 3000) {
  return new Promise(resolve => {
    const socket = new net.Socket();
    let done = false;
    const finish = open => { if (!done) { done = true; socket.destroy(); resolve(open); } };

    socket.setTimeout(timeoutMs);
    socket.on('connect', () => finish(true));
    socket.on('error', () => finish(false));
    socket.on('timeout', () => finish(false));
    socket.connect(port, host);
  });
}

async function checkTailscaleNetwork(config, emit) {
  const baseUrl = config.projectUrl;
  const results = [];

  if (emit) emit({ type: 'progress-detail', message: '🌐 Tailscale: Iniciando análise de segurança de rede...' });

  let hostname = '';
  let resolvedIPs = [];

  try {
    const u = new URL(baseUrl);
    hostname = u.hostname;
    const resolved = await dns.resolve4(hostname).catch(() => []);
    const resolved6 = await dns.resolve6(hostname).catch(() => []);
    resolvedIPs = [...resolved, ...resolved6];
  } catch (e) {
    hostname = baseUrl.replace(/^https?:\/\//, '').split('/')[0].split(':')[0];
  }

  // ── 1. IP Analysis — Private/Tailscale IP Detection ──────────────
  if (emit) emit({ type: 'progress-detail', message: '🔍 Tailscale: Analisando IPs resolvidos...' });

  const tailscaleIPs = resolvedIPs.filter(isTailscaleIP);
  const privateIPs = resolvedIPs.filter(isPrivateIP);
  const publicIPs = resolvedIPs.filter(ip => !isPrivateIP(ip));

  if (tailscaleIPs.length > 0) {
    results.push({
      check: '🌐 Network — Tailscale IP Detectado',
      status: 'WARN',
      severity: 'high',
      message: `Endereço IP Tailscale (CGNAT 100.64.0.0/10) detectado: ${tailscaleIPs.join(', ')}. Serviço pode estar exposto via Tailscale.`,
      details: {
        tailscaleIPs,
        allIPs: resolvedIPs,
        recommendation: 'Verifique se a exposição via Tailscale é intencional. Serviços internos não devem ser acessíveis pela internet pública via Tailscale.'
      }
    });
  } else if (privateIPs.length > 0) {
    results.push({
      check: '🌐 Network — IP Privado Exposto',
      status: 'FAIL',
      severity: 'critical',
      message: `IP privado exposto publicamente: ${privateIPs.join(', ')}. Possível misconfiguration de NAT/proxy reverso.`,
      details: {
        privateIPs,
        allIPs: resolvedIPs,
        recommendation: 'URGENTE: IPs privados não devem ser acessíveis pela internet pública.'
      }
    });
  } else {
    results.push({
      check: '🌐 Network — Análise de IPs',
      status: 'PASS',
      severity: 'info',
      message: `IPs resolvidos são públicos: ${publicIPs.join(', ')}. Nenhum IP privado ou Tailscale exposto.`,
      details: { resolvedIPs, publicIPs }
    });
  }

  // ── 2. Tailscale Magic DNS Detection ─────────────────────────────
  if (emit) emit({ type: 'progress-detail', message: '🔮 Tailscale: Verificando Magic DNS...' });

  const isTailscaleDomain = TAILSCALE_PATTERNS.some(p => p.test(hostname));
  const hasTailscaleHeaders = false; // Will be populated below

  const mainRes = await httpGet(baseUrl, { timeout: 6000 });
  const headersStr = JSON.stringify(mainRes.headers || {}).toLowerCase();
  const bodyStr = (mainRes.body || '').toLowerCase();

  const tailscaleInHeaders = headersStr.includes('tailscale') || headersStr.includes('tailnet');
  const tailscaleInBody = bodyStr.includes('tailscale') || bodyStr.includes('100.') || bodyStr.includes('.ts.net');

  if (isTailscaleDomain) {
    results.push({
      check: '🔮 Network — Tailscale Magic DNS',
      status: 'WARN',
      severity: 'high',
      message: `Domínio parece ser Tailscale Magic DNS: ${hostname}. Serviço pode ser interno exposto via Tailscale.`,
      details: {
        hostname,
        isTailscaleDomain,
        recommendation: 'Verifique se este serviço deve ser acessível publicamente. Serviços internos via Tailscale devem usar ACLs restritivas.'
      }
    });
  } else if (tailscaleInHeaders || tailscaleInBody) {
    results.push({
      check: '🔮 Network — Referências Tailscale',
      status: 'INFO',
      severity: 'low',
      message: 'Referências ao Tailscale encontradas em headers/body da resposta.',
      details: {
        inHeaders: tailscaleInHeaders,
        inBody: tailscaleInBody,
        recommendation: 'Verifique se informações de infraestrutura Tailscale estão sendo expostas inadvertidamente.'
      }
    });
  } else {
    results.push({
      check: '🔮 Network — Tailscale Magic DNS',
      status: 'PASS',
      severity: 'info',
      message: 'Nenhuma referência Tailscale Magic DNS detectada no domínio ou respostas.',
      details: { hostname }
    });
  }

  // ── 3. WireGuard Port Detection ───────────────────────────────────
  if (emit) emit({ type: 'progress-detail', message: '🔌 Tailscale: Verificando portas WireGuard...' });

  const openWireGuardPorts = [];

  for (const port of WIREGUARD_PORTS) {
    const isOpen = await tcpPortCheck(hostname, port, 2000);
    if (isOpen) {
      openWireGuardPorts.push(port);
    }
  }

  if (openWireGuardPorts.length > 0) {
    results.push({
      check: '🔌 Network — WireGuard Ports',
      status: 'WARN',
      severity: 'medium',
      message: `Porta(s) WireGuard/Tailscale detectada(s) abertas: ${openWireGuardPorts.join(', ')}. VPN pode estar exposta.`,
      details: {
        openPorts: openWireGuardPorts,
        recommendation: 'Restrinja o acesso às portas WireGuard (UDP) apenas a IPs autorizados via firewall.'
      }
    });
  } else {
    results.push({
      check: '🔌 Network — WireGuard Ports',
      status: 'PASS',
      severity: 'info',
      message: `Portas WireGuard padrão (${WIREGUARD_PORTS.join(', ')}) não detectadas abertas.`,
      details: { portsChecked: WIREGUARD_PORTS }
    });
  }

  // ── 4. VPN/Network Management Endpoint Discovery ─────────────────
  if (emit) emit({ type: 'progress-detail', message: '🗺️ Tailscale: Descobrindo endpoints de gerenciamento de rede...' });

  const exposedVPNPaths = [];

  const baseline = await httpGet(baseUrl + '/this-path-does-not-exist-xyzzy123', { timeout: 4000 });
  const baseline404Hash = (baseline.body || '').length;

  for (let i = 0; i < VPN_PATHS.length; i += 5) {
    const batch = VPN_PATHS.slice(i, i + 5);
    const batchResults = await Promise.all(batch.map(async path => {
      const res = await httpGet(baseUrl + path, { timeout: 4000 });
      return { path, res };
    }));

    for (const { path, res } of batchResults) {
      if (res.status === 0 || res.status === 404) continue;
      if (res.status >= 200 && res.status < 300 && (res.body || '').length === baseline404Hash) continue;

      if (res.status === 200 || res.status === 401 || res.status === 403) {
        const isNetworkTool = (res.body || '').toLowerCase().match(
          /(tailscale|wireguard|vpn|prometheus|grafana|portainer|netdata|network|peer|tunnel)/
        );

        exposedVPNPaths.push({
          path,
          status: res.status,
          requiresAuth: res.status === 401 || res.status === 403,
          isNetworkTool: !!isNetworkTool,
          server: res.headers['server'] || null
        });
      }
    }
  }

  if (exposedVPNPaths.length > 0) {
    const unprotected = exposedVPNPaths.filter(p => !p.requiresAuth);
    const protected_ = exposedVPNPaths.filter(p => p.requiresAuth);

    results.push({
      check: '🗺️ Network — VPN/Mgmt Endpoints',
      status: unprotected.length > 0 ? 'FAIL' : 'WARN',
      severity: unprotected.length > 0 ? 'high' : 'medium',
      message: `${exposedVPNPaths.length} endpoint(s) de rede/VPN encontrado(s). ${unprotected.length} sem autenticação.`,
      details: {
        total: exposedVPNPaths.length,
        unprotected,
        protected: protected_,
        recommendation: 'Endpoints de gerenciamento de rede/VPN devem estar atrás de autenticação forte e restritos por IP.'
      }
    });
  } else {
    results.push({
      check: '🗺️ Network — VPN/Mgmt Endpoints',
      status: 'PASS',
      severity: 'info',
      message: 'Nenhum endpoint de gerenciamento de VPN/rede exposto detectado.',
      details: { pathsTested: VPN_PATHS.length }
    });
  }

  // ── 5. Network Segmentation Headers Check ────────────────────────
  if (emit) emit({ type: 'progress-detail', message: '🔒 Tailscale: Verificando segmentação de rede via headers...' });

  const networkHeaders = {
    'X-Forwarded-For': mainRes.headers['x-forwarded-for'],
    'X-Real-IP': mainRes.headers['x-real-ip'],
    'X-Forwarded-Host': mainRes.headers['x-forwarded-host'],
    'X-Forwarded-Proto': mainRes.headers['x-forwarded-proto'],
    'Via': mainRes.headers['via'],
    'X-Internal-IP': mainRes.headers['x-internal-ip'],
    'X-Cluster-Client-IP': mainRes.headers['x-cluster-client-ip'],
    'X-Client-IP': mainRes.headers['x-client-ip'],
  };

  const leakedInternalIPs = [];

  for (const [header, value] of Object.entries(networkHeaders)) {
    if (!value) continue;
    const ips = value.match(/(?:\d{1,3}\.){3}\d{1,3}/g) || [];
    for (const ip of ips) {
      if (isPrivateIP(ip)) {
        leakedInternalIPs.push({ header, ip, isTailscale: isTailscaleIP(ip) });
      }
    }
  }

  if (leakedInternalIPs.length > 0) {
    const tailscaleLeaks = leakedInternalIPs.filter(l => l.isTailscale);
    results.push({
      check: '🔒 Network — IP Leakage via Headers',
      status: 'WARN',
      severity: tailscaleLeaks.length > 0 ? 'high' : 'medium',
      message: `${leakedInternalIPs.length} IP(s) interno(s) vazado(s) via headers HTTP. ${tailscaleLeaks.length > 0 ? 'IPs Tailscale detectados!' : ''}`,
      details: {
        leaks: leakedInternalIPs,
        tailscaleLeaks,
        recommendation: 'Remova ou filtre headers que expõem IPs internos da infraestrutura (X-Forwarded-For com IPs privados).'
      }
    });
  } else {
    results.push({
      check: '🔒 Network — IP Leakage via Headers',
      status: 'PASS',
      severity: 'info',
      message: 'Nenhum IP interno ou Tailscale vazado via headers HTTP.',
      details: { headersChecked: Object.keys(networkHeaders) }
    });
  }

  // ── 6. Tailscale DERP Relay Exposure ─────────────────────────────
  if (emit) emit({ type: 'progress-detail', message: '📡 Tailscale: Verificando exposição de DERP relays...' });

  // Check if main page references Tailscale DERP
  const derpReferences = [];
  const allBody = (mainRes.body || '') + JSON.stringify(mainRes.headers || {});

  for (const derp of TAILSCALE_DERP_REGIONS) {
    if (allBody.includes(derp.host)) {
      derpReferences.push(derp);
    }
  }

  if (derpReferences.length > 0) {
    results.push({
      check: '📡 Network — Tailscale DERP Exposure',
      status: 'INFO',
      severity: 'low',
      message: `Referências a ${derpReferences.length} servidor(es) DERP do Tailscale encontradas nas respostas.`,
      details: {
        derpServers: derpReferences,
        recommendation: 'Referências a infraestrutura DERP do Tailscale podem revelar que a rede usa Tailscale. Verifique se esta informação deve ser pública.'
      }
    });
  }

  // ── 7. Network Security Score ─────────────────────────────────────
  const criticalIssues = results.filter(r => r.status === 'FAIL' && ['critical', 'high'].includes(r.severity)).length;
  const warnIssues = results.filter(r => r.status === 'WARN').length;

  let networkScore, networkStatus, networkSev;
  if (criticalIssues > 0) {
    networkStatus = 'FAIL'; networkSev = 'high';
    networkScore = `${criticalIssues} problema(s) crítico(s) de segmentação de rede detectado(s).`;
  } else if (warnIssues > 2) {
    networkStatus = 'WARN'; networkSev = 'medium';
    networkScore = `${warnIssues} alerta(s) de rede detectado(s). Revisar configuração de rede.`;
  } else {
    networkStatus = 'PASS'; networkSev = 'info';
    networkScore = 'Segmentação de rede parece adequada. Nenhuma exposição crítica de VPN/Tailscale detectada.';
  }

  results.push({
    check: '🌐 Network — Análise Geral de Segmentação',
    status: networkStatus,
    severity: networkSev,
    message: networkScore,
    details: {
      criticalIssues,
      warnIssues,
      tailscaleDetected: tailscaleIPs.length > 0 || isTailscaleDomain,
      recommendation: 'Implemente firewall rules, VPN ACLs e monitore continuamente a exposição de rede.'
    }
  });

  return results;
}

module.exports = { checkTailscaleNetwork };
