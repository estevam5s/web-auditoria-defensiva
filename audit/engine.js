/*  ═══════════════════════════════════════════════════════════════════
    AUDIT ENGINE — Orchestrator
    Runs all security checks in sequence, streams results via SSE
    ═══════════════════════════════════════════════════════════════════ */

const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');

const { checkRESTExposure } = require('./checks/rest');
const { checkRPCExposure } = require('./checks/rpc');
const { checkGraphQLExposure } = require('./checks/graphql');
const { checkStorageExposure } = require('./checks/storage');
const { checkEdgeFunctions } = require('./checks/edge-functions');
const { checkRealtimeExposure } = require('./checks/realtime');
const { checkAuthEndpoints } = require('./checks/auth');
const { checkEnvExposure } = require('./checks/env-exposure');
const { checkRLSStatus } = require('./checks/rls');
const { checkCORSConfig } = require('./checks/cors-headers');
const { checkServiceKeyLeak } = require('./checks/service-key');
const { checkOpenSignup } = require('./checks/open-signup');
const { checkJWTConfig } = require('./checks/jwt');
const { checkDNSInfo } = require('./checks/dns');

// ── Deep Analysis Modules ────────────────────────────────────────
const { deepSourceCodeAnalysis } = require('./checks/source-code');
const { deepRouteDiscovery } = require('./checks/route-discovery');
const { deepVulnerabilityScanner } = require('./checks/vulnerability-scanner');
const { deepSensitiveDataDetector } = require('./checks/sensitive-data');
const { deepErrorDetector } = require('./checks/error-detector');

// ── Deep Analysis v2 — Targeted Security Modules ─────────────────
const { deepRLSCheck } = require('./checks/rls-deep');
const { deepRESTRPCLeakCheck } = require('./checks/rest-rpc-leak');
const { deepEdgeFunctionCheck } = require('./checks/edge-deep');
const { deepBundleKeyScanner } = require('./checks/bundle-keys');
const { deepStorageCheck } = require('./checks/storage-deep');
const { deepCredentialPIIDetector } = require('./checks/credential-pii');
const { detectStack } = require('./checks/stack-detector');

// ── Evidence signing ─────────────────────────────────────────────
function signEvidence(data) {
  const payload = JSON.stringify(data);
  const hash = crypto.createHash('sha256').update(payload).digest('hex');
  return {
    ...data,
    evidence: {
      sha256: hash,
      timestamp: new Date().toISOString(),
      auditId: uuidv4()
    }
  };
}

// ── Severity scoring ─────────────────────────────────────────────
function calculateScore(results) {
  let score = 100;
  const penalties = {
    critical: 25,
    high: 15,
    medium: 8,
    low: 3,
    info: 0
  };

  for (const result of results) {
    if (result.status === 'FAIL' || result.status === 'WARN') {
      score -= penalties[result.severity] || 5;
    }
  }

  return Math.max(0, Math.min(100, score));
}

function getScoreGrade(score) {
  if (score >= 90) return { grade: 'A', color: '#00ff41', label: 'Excelente' };
  if (score >= 75) return { grade: 'B', color: '#7fff00', label: 'Bom' };
  if (score >= 60) return { grade: 'C', color: '#ffff00', label: 'Atenção' };
  if (score >= 40) return { grade: 'D', color: '#ff8c00', label: 'Risco' };
  return { grade: 'F', color: '#ff0040', label: 'Crítico' };
}

// ── Main audit runner ────────────────────────────────────────────
async function runFullAudit(config, emit) {
  const auditStart = Date.now();
  const results = [];

  const checks = [
    { name: 'DNS & Connectivity', fn: checkDNSInfo, enabled: true },
    { name: 'REST API Exposure', fn: checkRESTExposure, enabled: config.options.checkREST },
    { name: 'RPC Exposure', fn: checkRPCExposure, enabled: config.options.checkRPC },
    { name: 'GraphQL Exposure', fn: checkGraphQLExposure, enabled: config.options.checkGraphQL },
    { name: 'Storage Buckets', fn: checkStorageExposure, enabled: config.options.checkStorage },
    { name: 'Edge Functions', fn: checkEdgeFunctions, enabled: config.options.checkEdgeFunctions },
    { name: 'Realtime Channels', fn: checkRealtimeExposure, enabled: config.options.checkRealtime },
    { name: 'Auth Endpoints', fn: checkAuthEndpoints, enabled: config.options.checkAuth },
    { name: '.env / Key Exposure', fn: checkEnvExposure, enabled: config.options.checkEnvExposure },
    { name: 'RLS Policy Check', fn: checkRLSStatus, enabled: config.options.checkRLS },
    { name: 'CORS Headers', fn: checkCORSConfig, enabled: config.options.checkCORS },
    { name: 'Service Key Leak', fn: checkServiceKeyLeak, enabled: true },
    { name: 'Open Signup', fn: checkOpenSignup, enabled: true },
    { name: 'JWT Configuration', fn: checkJWTConfig, enabled: true },
    // ── Deep Analysis Modules (emit-aware) ──
    { name: '🔬 Deep Source Code Analysis', fn: deepSourceCodeAnalysis, enabled: config.options.checkDeepSource !== false, usesEmit: true },
    { name: '🗺️ Hidden Route Discovery', fn: deepRouteDiscovery, enabled: config.options.checkDeepRoutes !== false, usesEmit: true },
    { name: '🛡️ Vulnerability Scanner', fn: deepVulnerabilityScanner, enabled: config.options.checkDeepVuln !== false, usesEmit: true },
    { name: '🔍 Sensitive Data Detector', fn: deepSensitiveDataDetector, enabled: config.options.checkDeepSensitive !== false, usesEmit: true },
    { name: '🐛 Error Detector', fn: deepErrorDetector, enabled: config.options.checkDeepErrors !== false, usesEmit: true },
    // ── Deep Analysis v2 — Targeted Security ──
    { name: '🔒 Deep RLS Misconfiguration', fn: deepRLSCheck, enabled: config.options.checkDeepRLS !== false, usesEmit: true },
    { name: '🔓 REST/RPC Data Leak (GUEST/USER)', fn: deepRESTRPCLeakCheck, enabled: config.options.checkDeepRESTRPC !== false, usesEmit: true },
    { name: '⚡ Edge Function Role Control', fn: deepEdgeFunctionCheck, enabled: config.options.checkDeepEdge !== false, usesEmit: true },
    { name: '🔑 Bundle Key Scanner', fn: deepBundleKeyScanner, enabled: config.options.checkDeepBundleKeys !== false, usesEmit: true },
    { name: '📦 Deep Storage Abuse', fn: deepStorageCheck, enabled: config.options.checkDeepStorage !== false, usesEmit: true },
    { name: '🕵️ Credential & PII Detector', fn: deepCredentialPIIDetector, enabled: config.options.checkDeepCredPII !== false, usesEmit: true },
    { name: '🔧 Stack Detection', fn: detectStack, enabled: true, usesEmit: true },
  ];

  const enabledChecks = checks.filter(c => c.enabled);

  emit({
    type: 'info',
    message: `Executando ${enabledChecks.length} verificações de segurança...`,
    total: enabledChecks.length
  });

  for (let i = 0; i < enabledChecks.length; i++) {
    const check = enabledChecks[i];
    
    emit({
      type: 'progress',
      message: `[${i + 1}/${enabledChecks.length}] Verificando: ${check.name}...`,
      step: i + 1,
      total: enabledChecks.length
    });

    try {
      const result = check.usesEmit
        ? await check.fn(config, emit)
        : await check.fn(config);
      const items = Array.isArray(result) ? result : [result];
      
      for (const item of items) {
        results.push(item);
        emit({
          type: 'result',
          data: item
        });
      }
    } catch (err) {
      const errorResult = {
        check: check.name,
        status: 'ERROR',
        severity: 'info',
        message: `Erro ao executar: ${err.message}`,
        details: null
      };
      results.push(errorResult);
      emit({ type: 'result', data: errorResult });
    }

    // Small delay between checks for readability
    await new Promise(r => setTimeout(r, 300));
  }

  const score = calculateScore(results);
  const grade = getScoreGrade(score);
  const duration = ((Date.now() - auditStart) / 1000).toFixed(1);

  const summary = {
    projectUrl: config.projectUrl,
    projectRef: config.projectRef,
    score,
    grade,
    totalChecks: results.length,
    passed: results.filter(r => r.status === 'PASS').length,
    failed: results.filter(r => r.status === 'FAIL').length,
    warnings: results.filter(r => r.status === 'WARN').length,
    errors: results.filter(r => r.status === 'ERROR').length,
    info: results.filter(r => r.status === 'INFO').length,
    duration: `${duration}s`,
    results
  };

  return signEvidence(summary);
}

module.exports = { runFullAudit };
