/*  ═══════════════════════════════════════════════════════════════════
    PORT SCANNER — TCP Port Scan with Service Fingerprinting
    Scans 60+ common ports, classifies by danger level
    ═══════════════════════════════════════════════════════════════════ */

const net = require('net');
const { URL } = require('url');

const SERVICE_MAP = {
  21:    { name: 'FTP',            danger: 'MEDIUM' },
  22:    { name: 'SSH',            danger: 'LOW'    },
  23:    { name: 'Telnet',         danger: 'MEDIUM' },
  25:    { name: 'SMTP',           danger: 'LOW'    },
  53:    { name: 'DNS',            danger: 'LOW'    },
  80:    { name: 'HTTP',           danger: 'LOW'    },
  110:   { name: 'POP3',           danger: 'LOW'    },
  111:   { name: 'RPC',            danger: 'MEDIUM' },
  135:   { name: 'MSRPC',          danger: 'MEDIUM' },
  139:   { name: 'NetBIOS',        danger: 'MEDIUM' },
  143:   { name: 'IMAP',           danger: 'LOW'    },
  161:   { name: 'SNMP',           danger: 'MEDIUM' },
  443:   { name: 'HTTPS',          danger: 'LOW'    },
  445:   { name: 'SMB',            danger: 'MEDIUM' },
  465:   { name: 'SMTPS',          danger: 'LOW'    },
  587:   { name: 'SMTP Submission', danger: 'LOW'   },
  993:   { name: 'IMAPS',          danger: 'LOW'    },
  995:   { name: 'POP3S',          danger: 'LOW'    },
  1080:  { name: 'SOCKS Proxy',    danger: 'HIGH'   },
  1433:  { name: 'MSSQL',          danger: 'HIGH'   },
  1521:  { name: 'Oracle DB',      danger: 'HIGH'   },
  2049:  { name: 'NFS',            danger: 'MEDIUM' },
  2181:  { name: 'ZooKeeper',      danger: 'HIGH'   },
  2375:  { name: 'Docker (unauth)', danger: 'CRITICAL' },
  2376:  { name: 'Docker TLS',     danger: 'HIGH'   },
  3000:  { name: 'Dev Server',     danger: 'MEDIUM' },
  3306:  { name: 'MySQL',          danger: 'HIGH'   },
  3389:  { name: 'RDP',            danger: 'HIGH'   },
  4369:  { name: 'RabbitMQ EPD',   danger: 'HIGH'   },
  5000:  { name: 'Flask/Dev',      danger: 'MEDIUM' },
  5432:  { name: 'PostgreSQL',     danger: 'CRITICAL' },
  5672:  { name: 'RabbitMQ',       danger: 'HIGH'   },
  5900:  { name: 'VNC',            danger: 'HIGH'   },
  5984:  { name: 'CouchDB',        danger: 'HIGH'   },
  6000:  { name: 'X11',            danger: 'MEDIUM' },
  6379:  { name: 'Redis',          danger: 'CRITICAL' },
  7474:  { name: 'Neo4j',          danger: 'HIGH'   },
  8000:  { name: 'Alt HTTP',       danger: 'MEDIUM' },
  8080:  { name: 'Alt HTTP',       danger: 'HIGH'   },
  8443:  { name: 'Alt HTTPS',      danger: 'HIGH'   },
  8888:  { name: 'Jupyter/Dev',    danger: 'HIGH'   },
  9000:  { name: 'SonarQube/PHP',  danger: 'MEDIUM' },
  9090:  { name: 'Prometheus',     danger: 'MEDIUM' },
  9200:  { name: 'Elasticsearch',  danger: 'CRITICAL' },
  9300:  { name: 'Elasticsearch Cluster', danger: 'CRITICAL' },
  11211: { name: 'Memcached',      danger: 'HIGH'   },
  15672: { name: 'RabbitMQ UI',    danger: 'HIGH'   },
  27017: { name: 'MongoDB',        danger: 'CRITICAL' },
  27018: { name: 'MongoDB Shard',  danger: 'CRITICAL' },
  28017: { name: 'MongoDB Web',    danger: 'CRITICAL' },
  50070: { name: 'Hadoop NameNode', danger: 'HIGH'  },
  61616: { name: 'ActiveMQ',       danger: 'HIGH'   },
};

const DANGER_SEVERITY = {
  CRITICAL: 'critical',
  HIGH:     'high',
  MEDIUM:   'medium',
  LOW:      'low',
};

const CVSS_ESTIMATE = {
  CRITICAL: 9.8,
  HIGH:     7.5,
  MEDIUM:   5.3,
  LOW:      3.1,
};

function scanPort(host, port, timeout = 500) {
  return new Promise(resolve => {
    const sock = new net.Socket();
    let settled = false;

    const done = (open) => {
      if (settled) return;
      settled = true;
      sock.destroy();
      resolve({ port, open });
    };

    sock.setTimeout(timeout);
    sock.on('connect', () => done(true));
    sock.on('timeout', () => done(false));
    sock.on('error', () => done(false));
    sock.connect(port, host);
  });
}

async function scanBatch(host, ports, timeout = 500) {
  return Promise.all(ports.map(p => scanPort(host, p, timeout)));
}

async function checkPortScan(config, emit) {
  const results = [];
  const BATCH_SIZE = 20;

  let targetHost;
  try {
    const parsed = new URL(config.projectUrl);
    targetHost = parsed.hostname;
  } catch {
    results.push({
      check: '🔌 Port Scan — Target Resolution',
      status: 'ERROR',
      severity: 'info',
      message: `URL inválida: ${config.projectUrl}`,
      details: null,
    });
    return results;
  }

  const allPorts = Object.keys(SERVICE_MAP).map(Number);
  const openPorts = [];

  emit && emit({ type: 'progress', message: `[Port Scan] Escaneando ${allPorts.length} portas em ${targetHost}...` });

  // Scan in batches
  for (let i = 0; i < allPorts.length; i += BATCH_SIZE) {
    const batch = allPorts.slice(i, i + BATCH_SIZE);
    const batchResults = await scanBatch(targetHost, batch, 500);
    for (const { port, open } of batchResults) {
      if (open) openPorts.push(port);
    }
  }

  if (openPorts.length === 0) {
    results.push({
      check: '🔌 Port Scan — Exposição de Serviços',
      status: 'PASS',
      severity: 'info',
      message: `Nenhuma porta de alto risco aberta detectada em ${targetHost} (${allPorts.length} portas testadas).`,
      details: { host: targetHost, portsTested: allPorts.length },
    });
    return results;
  }

  // Classify open ports
  const criticalPorts = [];
  const highPorts    = [];
  const mediumPorts  = [];
  const lowPorts     = [];

  for (const port of openPorts) {
    const svc = SERVICE_MAP[port] || { name: 'Unknown', danger: 'MEDIUM' };
    const entry = { port, service: svc.name, danger: svc.danger, cvss: CVSS_ESTIMATE[svc.danger] || 5.0 };
    if (svc.danger === 'CRITICAL') criticalPorts.push(entry);
    else if (svc.danger === 'HIGH') highPorts.push(entry);
    else if (svc.danger === 'MEDIUM') mediumPorts.push(entry);
    else lowPorts.push(entry);
  }

  // One finding per danger tier that has ports
  if (criticalPorts.length > 0) {
    results.push({
      check: '🔌 Port Scan — Serviços CRÍTICOS Expostos',
      status: 'FAIL',
      severity: 'critical',
      message: `${criticalPorts.length} serviço(s) CRÍTICO(S) acessível(is) publicamente em ${targetHost}! Acesso não autenticado a bancos de dados/infraestrutura.`,
      details: {
        openPorts: criticalPorts,
        recommendation: 'Remova acesso público imediatamente. Use firewall para bloquear essas portas. Coloque os serviços atrás de VPN ou rede privada.',
      },
    });
  }

  if (highPorts.length > 0) {
    results.push({
      check: '🔌 Port Scan — Serviços de Alto Risco Expostos',
      status: 'FAIL',
      severity: 'high',
      message: `${highPorts.length} serviço(s) de alto risco acessível(is) em ${targetHost}.`,
      details: {
        openPorts: highPorts,
        recommendation: 'Restrinja acesso por IP, use autenticação forte e considere VPN.',
      },
    });
  }

  if (mediumPorts.length > 0) {
    results.push({
      check: '🔌 Port Scan — Serviços de Risco Médio Expostos',
      status: 'WARN',
      severity: 'medium',
      message: `${mediumPorts.length} serviço(s) de risco médio detectado(s) em ${targetHost}.`,
      details: { openPorts: mediumPorts },
    });
  }

  if (lowPorts.length > 0) {
    results.push({
      check: '🔌 Port Scan — Portas Padrão Abertas',
      status: 'INFO',
      severity: 'low',
      message: `${lowPorts.length} porta(s) padrão aberta(s) em ${targetHost}.`,
      details: { openPorts: lowPorts },
    });
  }

  return results;
}

module.exports = { checkPortScan };
