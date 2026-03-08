/*  ═══════════════════════════════════════════════════════════════════
    SSL/TLS ANALYSIS — Certificate & Protocol Security Check
    Inspects TLS cert expiry, self-signed, CN mismatch, HSTS,
    deprecated protocol probing (TLS 1.0/1.1)
    ═══════════════════════════════════════════════════════════════════ */

const tls   = require('tls');
const https = require('https');
const http  = require('http');
const { URL } = require('url');

function tlsConnect(host, port, options = {}) {
  return new Promise((resolve, reject) => {
    const timeout = options.timeout || 8000;
    const socket = tls.connect({ host, port, servername: host, rejectUnauthorized: false, ...options }, () => {
      const cert = socket.getPeerCertificate(true);
      const protocol = socket.getProtocol();
      socket.destroy();
      resolve({ cert, protocol });
    });
    socket.setTimeout(timeout);
    socket.on('timeout', () => { socket.destroy(); reject(new Error('TLS connect timeout')); });
    socket.on('error', (err) => reject(err));
  });
}

function httpsGet(url, timeout = 8000) {
  return new Promise(resolve => {
    const req = https.get(url, { rejectUnauthorized: false }, res => {
      const headers = res.headers;
      res.destroy();
      resolve({ status: res.statusCode, headers });
    });
    req.setTimeout(timeout, () => { req.destroy(); resolve({ status: 0, headers: {} }); });
    req.on('error', () => resolve({ status: 0, headers: {} }));
  });
}

function httpGet(url, timeout = 5000) {
  return new Promise(resolve => {
    const req = http.get(url, res => {
      resolve({ status: res.statusCode, headers: res.headers });
      res.destroy();
    });
    req.setTimeout(timeout, () => { req.destroy(); resolve({ status: 0, headers: {} }); });
    req.on('error', () => resolve({ status: 0, headers: {} }));
  });
}

async function checkSSL(config, emit) {
  const results = [];

  let host, port, isHttps;
  try {
    const parsed = new URL(config.projectUrl);
    host = parsed.hostname;
    port = parsed.port ? parseInt(parsed.port) : (parsed.protocol === 'https:' ? 443 : 80);
    isHttps = parsed.protocol === 'https:';
  } catch {
    results.push({
      check: '🔒 SSL/TLS — Configuração',
      status: 'ERROR',
      severity: 'info',
      message: `URL inválida: ${config.projectUrl}`,
      details: null,
    });
    return results;
  }

  if (!isHttps) {
    results.push({
      check: '🔒 SSL/TLS — Protocolo Seguro',
      status: 'FAIL',
      severity: 'high',
      message: `O site não usa HTTPS! Dados são transmitidos em texto puro para ${host}.`,
      details: { url: config.projectUrl, recommendation: 'Migre para HTTPS imediatamente. Use Let\'s Encrypt para certificado gratuito.' },
    });
    return results;
  }

  emit && emit({ type: 'progress', message: `[SSL] Analisando certificado TLS de ${host}:${port}...` });

  // Grab certificate info
  let cert, protocol;
  try {
    ({ cert, protocol } = await tlsConnect(host, port));
  } catch (err) {
    results.push({
      check: '🔒 SSL/TLS — Conexão',
      status: 'FAIL',
      severity: 'high',
      message: `Não foi possível estabelecer conexão TLS com ${host}:${port}: ${err.message}`,
      details: null,
    });
    return results;
  }

  const now = Date.now();

  // 1. Certificate expiry
  if (cert && cert.valid_to) {
    const expiry = new Date(cert.valid_to).getTime();
    const daysLeft = Math.floor((expiry - now) / 86400000);

    if (daysLeft < 0) {
      results.push({
        check: '🔒 SSL/TLS — Certificado Expirado',
        status: 'FAIL',
        severity: 'critical',
        message: `Certificado TLS EXPIRADO há ${Math.abs(daysLeft)} dia(s)! Conexões mostrarão erro de segurança.`,
        details: { expiredAt: cert.valid_to, daysOverdue: Math.abs(daysLeft) },
      });
    } else if (daysLeft < 14) {
      results.push({
        check: '🔒 SSL/TLS — Certificado Quase Expirado',
        status: 'FAIL',
        severity: 'high',
        message: `Certificado expira em ${daysLeft} dia(s) (${cert.valid_to}). Renove com urgência.`,
        details: { expiresAt: cert.valid_to, daysLeft },
      });
    } else if (daysLeft < 30) {
      results.push({
        check: '🔒 SSL/TLS — Certificado Expirando em Breve',
        status: 'WARN',
        severity: 'medium',
        message: `Certificado expira em ${daysLeft} dias. Programe a renovação.`,
        details: { expiresAt: cert.valid_to, daysLeft },
      });
    } else {
      results.push({
        check: '🔒 SSL/TLS — Validade do Certificado',
        status: 'PASS',
        severity: 'info',
        message: `Certificado válido por mais ${daysLeft} dias (expira: ${cert.valid_to}).`,
        details: { expiresAt: cert.valid_to, daysLeft },
      });
    }
  }

  // 2. Self-signed detection
  if (cert && cert.issuer && cert.subject) {
    const issuerCN = cert.issuer.CN || cert.issuer.O || '';
    const subjectCN = cert.subject.CN || '';
    const selfSigned = issuerCN === subjectCN || cert.issuerCertificate?.fingerprint === cert.fingerprint;

    if (selfSigned) {
      results.push({
        check: '🔒 SSL/TLS — Certificado Auto-Assinado',
        status: 'FAIL',
        severity: 'high',
        message: `Certificado auto-assinado detectado em ${host}. Browsers mostrarão aviso de segurança.`,
        details: { issuer: issuerCN, subject: subjectCN, recommendation: 'Use um certificado de uma CA confiável (Let\'s Encrypt, DigiCert, etc.).' },
      });
    }
  }

  // 3. CN mismatch
  if (cert && cert.subject) {
    const cn = cert.subject.CN || '';
    const altNames = cert.subjectaltname || '';
    const hostMatch = cn === host || cn === `*.${host.split('.').slice(1).join('.')}` ||
      altNames.split(',').some(n => n.trim().replace(/^DNS:/, '') === host);

    if (!hostMatch && cn) {
      results.push({
        check: '🔒 SSL/TLS — CN Mismatch',
        status: 'FAIL',
        severity: 'high',
        message: `Common Name do certificado ("${cn}") não corresponde ao host "${host}".`,
        details: { certCN: cn, requestedHost: host, altNames },
      });
    }
  }

  // 4. Protocol version
  if (protocol) {
    const deprecated = ['TLSv1', 'TLSv1.1', 'SSLv2', 'SSLv3'];
    if (deprecated.includes(protocol)) {
      results.push({
        check: '🔒 SSL/TLS — Protocolo Obsoleto',
        status: 'FAIL',
        severity: 'high',
        message: `Protocolo TLS obsoleto em uso: ${protocol}. Vulnerável a ataques POODLE, BEAST.`,
        details: { protocol, recommendation: 'Desabilite TLS 1.0/1.1. Use apenas TLS 1.2+.' },
      });
    } else {
      results.push({
        check: '🔒 SSL/TLS — Versão do Protocolo',
        status: 'PASS',
        severity: 'info',
        message: `Protocolo TLS seguro em uso: ${protocol}.`,
        details: { protocol },
      });
    }
  }

  // 5. HSTS header
  const res = await httpsGet(config.projectUrl);
  const hsts = res.headers['strict-transport-security'];

  if (!hsts) {
    results.push({
      check: '🔒 SSL/TLS — HSTS Ausente',
      status: 'WARN',
      severity: 'medium',
      message: `Header Strict-Transport-Security (HSTS) não encontrado em ${host}. Usuários podem ser redirecionados para HTTP.`,
      details: { recommendation: 'Adicione: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' },
    });
  } else {
    const maxAgeMatch = hsts.match(/max-age=(\d+)/i);
    const maxAge = maxAgeMatch ? parseInt(maxAgeMatch[1]) : 0;
    if (maxAge < 2592000) { // < 30 days
      results.push({
        check: '🔒 SSL/TLS — HSTS max-age Baixo',
        status: 'WARN',
        severity: 'low',
        message: `HSTS configurado mas max-age=${maxAge}s é muito baixo (< 30 dias).`,
        details: { hsts, recommendation: 'Use max-age=31536000 (1 ano) ou mais.' },
      });
    } else {
      results.push({
        check: '🔒 SSL/TLS — HSTS Configurado',
        status: 'PASS',
        severity: 'info',
        message: `HSTS ativo com max-age=${maxAge}s.`,
        details: { hsts },
      });
    }
  }

  // 6. Issuer info
  if (cert && cert.issuer) {
    const issuerOrg = cert.issuer.O || cert.issuer.CN || 'Desconhecido';
    results.push({
      check: '🔒 SSL/TLS — Emissor do Certificado',
      status: 'INFO',
      severity: 'info',
      message: `Certificado emitido por: ${issuerOrg}. Profundidade da chain: ${cert.fingerprint ? 'OK' : 'N/A'}.`,
      details: { issuer: cert.issuer, subject: cert.subject },
    });
  }

  return results;
}

module.exports = { checkSSL };
