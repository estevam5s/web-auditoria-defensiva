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

// ── New Advanced Modules ───────────────────────────────────────────────
const { runAutoDetect } = require('./checks/auto-detect');
const { openAPIIntrospection } = require('./checks/openapi-introspection');
const { restScanDeep } = require('./checks/rest-scan-deep');
const { relationshipRLSScan } = require('./checks/relationship-rls');
const { graphqlScan } = require('./checks/graphql-scan');
const { authSettingsScan } = require('./checks/auth-settings');
const { hardeningCheck } = require('./checks/hardening-check');

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
// Scoring logic v2:
//  - Semantic grouping: combines related checks (RLS Policy + Deep RLS + Relationship RLS → group 'rls')
//  - Weighted penalties: security-critical categories (RLS, Service Key) penalize more
//  - Bonus: +1/+2 for key controls that pass
//  - Stack Detection never penalizes (informational only)
//  - Floor 5, Cap 98
function calculateScore(results) {
  // Semantic groups map related checks to one domain, keeping only the worst result
  const SEMANTIC_GROUPS = [
    { group: 'rls',         pattern: /RLS|Row Level/i,           weight: 1.6, keyControl: true },
    { group: 'service-key', pattern: /Service Key/i,             weight: 1.8, keyControl: true },
    { group: 'auth',        pattern: /Auth(?!or)|Open Signup/i,  weight: 1.3, keyControl: true },
    { group: 'jwt',         pattern: /JWT/i,                     weight: 1.2, keyControl: true },
    { group: 'bundle-keys', pattern: /Bundle Key/i,              weight: 1.4, keyControl: true },
    { group: 'credential',  pattern: /Credential|PII/i,          weight: 1.3, keyControl: true },
    { group: 'env',         pattern: /\.env|Key Exposure/i,      weight: 1.3, keyControl: true },
    { group: 'rest',        pattern: /REST|RPC/i,                weight: 1.1 },
    { group: 'cors',        pattern: /CORS/i,                    weight: 1.1, keyControl: true },
    { group: 'storage',     pattern: /Storage/i,                 weight: 1.0 },
    { group: 'graphql',     pattern: /GraphQL/i,                 weight: 0.9 },
    { group: 'edge',        pattern: /Edge/i,                    weight: 1.0 },
    { group: 'vuln',        pattern: /Vulnerability/i,           weight: 1.0 },
    { group: 'routes',      pattern: /Route|Hidden/i,            weight: 0.7 },
    { group: 'source',      pattern: /Source Code/i,             weight: 0.9 },
    { group: 'sensitive',   pattern: /Sensitive Data/i,          weight: 1.0 },
    { group: 'hardening',   pattern: /Hardening|Rate Limit/i,    weight: 0.8 },
    { group: 'stack',       pattern: /Stack/i,                   weight: 0.0 }, // never penalizes
    { group: 'dns',         pattern: /DNS/i,                     weight: 0.5 },
    { group: 'realtime',    pattern: /Realtime/i,                weight: 0.8 },
  ];

  const failPenalties = { critical: 25, high: 14, medium: 7, low: 2, info: 0 };
  const warnPenalties = { critical:  8, high:  4, medium: 2, low: 1, info: 0 };
  const severityRank  = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
  const statusRank    = { FAIL: 2, WARN: 1 };

  function getGroup(check) {
    if (!check) return 'other';
    for (const { group, pattern } of SEMANTIC_GROUPS) {
      if (pattern.test(check)) return group;
    }
    // Fallback: strip emoji and use prefix before " — "
    const raw = check.replace(/^[^\w]*/u, '');
    return raw.split(' — ')[0].trim() || 'other';
  }

  // Aggregate: keep worst result per semantic group
  const groupedResults = {};
  for (const result of results) {
    const s = result.status;
    if (s !== 'FAIL' && s !== 'WARN') continue;

    const group = getGroup(result.check);
    const rank = (statusRank[s] || 0) * 10 + (severityRank[result.severity] || 0);
    if (!groupedResults[group] || rank > groupedResults[group].rank) {
      groupedResults[group] = { result, rank, group };
    }
  }

  // Apply weighted penalties
  let score = 100;
  for (const [group, { result }] of Object.entries(groupedResults)) {
    const basePenalty = result.status === 'FAIL'
      ? (failPenalties[result.severity] ?? 5)
      : (warnPenalties[result.severity] ?? 1);

    const groupDef = SEMANTIC_GROUPS.find(g => g.group === group);
    const weight = groupDef?.weight ?? 1.0;
    if (weight === 0) continue; // e.g. stack detection

    score -= Math.round(basePenalty * weight);
  }

  // Bonus for key controls that pass
  const KEY_PASS_BONUSES = [
    { pattern: /RLS Policy/i, bonus: 2 },
    { pattern: /Service Key/i, bonus: 2 },
    { pattern: /JWT/i, bonus: 1 },
    { pattern: /CORS/i, bonus: 1 },
    { pattern: /Auth Endpoints/i, bonus: 1 },
  ];
  for (const { pattern, bonus } of KEY_PASS_BONUSES) {
    const passing = results.filter(r => pattern.test(r.check || '') && r.status === 'PASS');
    if (passing.length > 0) score += bonus;
  }

  return Math.max(5, Math.min(98, Math.round(score)));
}

function getScoreGrade(score) {
  if (score >= 92) return { grade: 'A', color: '#00ff41', label: 'Excelente' };
  if (score >= 78) return { grade: 'B', color: '#7fff00', label: 'Bom' };
  if (score >= 60) return { grade: 'C', color: '#ffff00', label: 'Atenção' };
  if (score >= 40) return { grade: 'D', color: '#ff8c00', label: 'Risco Elevado' };
  return { grade: 'F', color: '#ff0040', label: 'Crítico — Ação Imediata' };
}

// ── Main audit runner ────────────────────────────────────────────
async function runFullAudit(config, emit) {
  const auditStart = Date.now();
  const results = [];

  // Store original website URL before auto-detect may override projectUrl with supabase URL
  config._websiteUrl = config.projectUrl;

  const checks = [
    { name: '🔑 Auto-Detect Credentials', fn: runAutoDetect, enabled: config.options.checkAutoDetect !== false, usesEmit: true },
    { name: 'DNS & Connectivity', fn: checkDNSInfo, enabled: true },
    { name: 'REST API Exposure', fn: checkRESTExposure, enabled: config.options.checkREST },
    { name: 'RPC Exposure', fn: checkRPCExposure, enabled: config.options.checkRPC },
    { name: 'GraphQL Exposure', fn: checkGraphQLExposure, enabled: config.options.checkGraphQL },
    { name: '🔷 GraphQL Deep Scan', fn: graphqlScan, enabled: config.options.checkGraphQLDeep !== false, usesEmit: true },
    { name: 'Storage Buckets', fn: checkStorageExposure, enabled: config.options.checkStorage },
    { name: 'Edge Functions', fn: checkEdgeFunctions, enabled: config.options.checkEdgeFunctions },
    { name: 'Realtime Channels', fn: checkRealtimeExposure, enabled: config.options.checkRealtime },
    { name: 'Auth Endpoints', fn: checkAuthEndpoints, enabled: config.options.checkAuth },
    { name: '🔐 Auth Settings Deep', fn: authSettingsScan, enabled: config.options.checkAuthDeep !== false, usesEmit: true },
    { name: '.env / Key Exposure', fn: checkEnvExposure, enabled: config.options.checkEnvExposure },
    { name: 'RLS Policy Check', fn: checkRLSStatus, enabled: config.options.checkRLS },
    { name: 'CORS Headers', fn: checkCORSConfig, enabled: config.options.checkCORS },
    { name: 'Service Key Leak', fn: checkServiceKeyLeak, enabled: true },
    { name: 'Open Signup', fn: checkOpenSignup, enabled: true },
    { name: 'JWT Configuration', fn: checkJWTConfig, enabled: true },
    // ── Advanced Supabase Modules (dependem de credenciais) ──
    { name: '📡 OpenAPI Introspection', fn: openAPIIntrospection, enabled: config.options.checkOpenAPI !== false, usesEmit: true },
    { name: '🔍 REST Scan Deep', fn: restScanDeep, enabled: config.options.checkRESTDeep !== false, usesEmit: true },
    { name: '🔗 Relationship RLS Scan', fn: relationshipRLSScan, enabled: config.options.checkRelationshipRLS !== false, usesEmit: true },
    { name: '⚙️ Hardening & Rate Limiting', fn: hardeningCheck, enabled: config.options.checkHardening !== false, usesEmit: true },
    // ── Deep Analysis Modules — use _websiteUrl for web checks ──
    { name: '🔬 Deep Source Code Analysis', fn: deepSourceCodeAnalysis, enabled: config.options.checkDeepSource !== false, usesEmit: true, useWebsiteUrl: true },
    { name: '🗺️ Hidden Route Discovery', fn: deepRouteDiscovery, enabled: config.options.checkDeepRoutes !== false, usesEmit: true, useWebsiteUrl: true },
    { name: '🛡️ Vulnerability Scanner', fn: deepVulnerabilityScanner, enabled: config.options.checkDeepVuln !== false, usesEmit: true, useWebsiteUrl: true },
    { name: '🔍 Sensitive Data Detector', fn: deepSensitiveDataDetector, enabled: config.options.checkDeepSensitive !== false, usesEmit: true, useWebsiteUrl: true },
    { name: '🐛 Error Detector', fn: deepErrorDetector, enabled: config.options.checkDeepErrors !== false, usesEmit: true, useWebsiteUrl: true },
    // ── Deep Analysis v2 — Targeted Security ──
    { name: '🔒 Deep RLS Misconfiguration', fn: deepRLSCheck, enabled: config.options.checkDeepRLS !== false, usesEmit: true },
    { name: '🔓 REST/RPC Data Leak (GUEST/USER)', fn: deepRESTRPCLeakCheck, enabled: config.options.checkDeepRESTRPC !== false, usesEmit: true },
    { name: '⚡ Edge Function Role Control', fn: deepEdgeFunctionCheck, enabled: config.options.checkDeepEdge !== false, usesEmit: true },
    { name: '🔑 Bundle Key Scanner', fn: deepBundleKeyScanner, enabled: config.options.checkDeepBundleKeys !== false, usesEmit: true, useWebsiteUrl: true },
    { name: '📦 Deep Storage Abuse', fn: deepStorageCheck, enabled: config.options.checkDeepStorage !== false, usesEmit: true },
    { name: '🕵️ Credential & PII Detector', fn: deepCredentialPIIDetector, enabled: config.options.checkDeepCredPII !== false, usesEmit: true, useWebsiteUrl: true },
    { name: '🔧 Stack Detection', fn: detectStack, enabled: true, usesEmit: true, useWebsiteUrl: true },
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
      // Web-focused checks should analyze the original website URL, not the Supabase API URL
      const checkConfig = check.useWebsiteUrl && config._websiteUrl && config._websiteUrl !== config.projectUrl
        ? { ...config, projectUrl: config._websiteUrl }
        : config;

      const result = check.usesEmit
        ? await check.fn(checkConfig, emit)
        : await check.fn(checkConfig);
      
      let items = [];
      let catalogData = null;
      
      if (result && typeof result === 'object') {
        if (Array.isArray(result)) {
          items = result;
        } else if (result.results) {
          items = Array.isArray(result.results) ? result.results : [result.results];
          catalogData = result;
        } else if (result.detected) {
          items = Array.isArray(result.results) ? result.results : [result];
          catalogData = result;
        }
      } else {
        items = [result];
      }
      
      for (const item of items) {
        results.push(item);
        emit({
          type: 'result',
          data: item
        });
      }
      
      if (catalogData) {
        if (catalogData.catalog) config._catalog = catalogData.catalog;
        if (catalogData.tableTests) config._restScanResults = catalogData.tableTests;
        if (catalogData.findings) config._relationshipResults = catalogData.findings;
        if (catalogData.schema) config._graphqlResults = catalogData.schema;
        if (catalogData.detected) {
          if (catalogData.detected.supabaseUrl) {
            // Update projectUrl to the Supabase API URL for subsequent Supabase checks
            // _websiteUrl keeps the original website URL for web-focused checks
            config.projectUrl = catalogData.detected.supabaseUrl;
            config._supabaseUrl = catalogData.detected.supabaseUrl;
          }
          if (catalogData.detected.anonKey) config.anonKey = catalogData.detected.anonKey;
          if (catalogData.detected.serviceRoleKey) config._serviceRoleKey = catalogData.detected.serviceRoleKey;
        }
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
    results,
    catalogData: {
      openapi: config._catalog,
      restScan: config._restScanResults,
      relationship: config._relationshipResults,
      graphql: config._graphqlResults,
      edgeFunctions: config._edgeFunctionsResults,
      allResults: results
    }
  };

  return signEvidence(summary);
}

module.exports = { runFullAudit };
