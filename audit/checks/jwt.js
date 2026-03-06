/*  CHECK: JWT Configuration
    Analyzes JWT tokens for security issues */

const { safeFetch, supabaseHeaders } = require('../helpers/http');

async function checkJWTConfig(config) {
  const results = [];

  if (!config.anonKey) {
    results.push({
      check: 'JWT — Analysis',
      status: 'INFO',
      severity: 'info',
      message: 'Nenhuma anon key fornecida para análise JWT.',
      details: null
    });
    return results;
  }

  try {
    const parts = config.anonKey.split('.');
    if (parts.length !== 3) {
      results.push({
        check: 'JWT — Format',
        status: 'WARN',
        severity: 'medium',
        message: 'A chave fornecida não parece ser um JWT válido.',
        details: null
      });
      return results;
    }

    const header = JSON.parse(Buffer.from(parts[0], 'base64').toString());
    const payload = JSON.parse(Buffer.from(parts[1], 'base64').toString());

    // Check algorithm
    if (header.alg === 'none') {
      results.push({
        check: 'JWT — Algorithm None',
        status: 'FAIL',
        severity: 'critical',
        message: 'JWT usa algoritmo "none"! Tokens podem ser forjados.',
        details: { algorithm: header.alg }
      });
    } else if (header.alg === 'HS256') {
      results.push({
        check: 'JWT — Algorithm',
        status: 'INFO',
        severity: 'info',
        message: `JWT usa algoritmo ${header.alg} (padrão Supabase).`,
        details: { algorithm: header.alg, type: header.typ }
      });
    }

    // Check role
    results.push({
      check: 'JWT — Role',
      status: payload.role === 'service_role' ? 'FAIL' : 'PASS',
      severity: payload.role === 'service_role' ? 'critical' : 'info',
      message: payload.role === 'service_role' 
        ? 'JWT é uma SERVICE_ROLE key! Não deve ser usada em clientes.'
        : `JWT role: "${payload.role}" ✓`,
      details: { role: payload.role }
    });

    // Check expiration
    if (payload.exp) {
      const expDate = new Date(payload.exp * 1000);
      const now = new Date();
      const daysUntilExpiry = (expDate - now) / (1000 * 60 * 60 * 24);

      if (daysUntilExpiry < 0) {
        results.push({
          check: 'JWT — Expiration',
          status: 'WARN',
          severity: 'medium',
          message: `JWT expirou em ${expDate.toISOString()}.`,
          details: { exp: expDate.toISOString() }
        });
      } else if (daysUntilExpiry > 365 * 5) {
        results.push({
          check: 'JWT — Long Expiry',
          status: 'WARN',
          severity: 'low',
          message: `JWT tem expiração muito longa (${Math.round(daysUntilExpiry / 365)} anos).`,
          details: { exp: expDate.toISOString(), daysUntilExpiry: Math.round(daysUntilExpiry) }
        });
      }
    }

    // Check issuer
    if (payload.iss) {
      results.push({
        check: 'JWT — Issuer',
        status: 'INFO',
        severity: 'info',
        message: `JWT issuer: ${payload.iss}`,
        details: { iss: payload.iss, ref: payload.ref }
      });
    }

  } catch (err) {
    results.push({
      check: 'JWT — Parse Error',
      status: 'ERROR',
      severity: 'info',
      message: `Erro ao analisar JWT: ${err.message}`,
      details: null
    });
  }

  return results;
}

module.exports = { checkJWTConfig };
