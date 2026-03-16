/*  ═══════════════════════════════════════════════════════════════════
    SUPABASE DATABASE INTEGRATION
    Saves audit results to Supabase database
    ═══════════════════════════════════════════════════════════════════ */

const fetch = require('node-fetch');

const getSupabaseConfig = () => {
  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_ANON_KEY;
  if (!url || !key) return null;
  return { url, key };
};

const supabaseFetch = async (endpoint, options = {}) => {
  const config = getSupabaseConfig();
  if (!config) return { success: false, error: 'Supabase não configurado' };

  const url = `${config.url}/rest/v1/${endpoint}`;
  const headers = {
    'Content-Type': 'application/json',
    'apikey': config.key,
    'Authorization': `Bearer ${config.key}`,
    'Prefer': options.prefer || 'return=representation',
    ...options.headers
  };

  try {
    const response = await fetch(url, { ...options, headers });
    const data = await response.json();
    if (!response.ok) throw new Error(data.message || `HTTP ${response.status}`);
    return { success: true, data };
  } catch (error) {
    console.error('[Supabase] Fetch error:', error.message);
    return { success: false, error: error.message };
  }
};

const getClientInfo = (userAgent) => {
  const info = {
    machine: 'Unknown',
    os: 'Unknown',
    browser: 'Unknown',
    region: 'Unknown'
  };

  if (!userAgent) return info;

  // OS Detection
  if (userAgent.includes('Windows')) {
    info.os = 'Windows';
    info.machine = 'PC';
  } else if (userAgent.includes('Mac')) {
    info.os = 'macOS';
    info.machine = 'Mac';
  } else if (userAgent.includes('Linux')) {
    info.os = 'Linux';
    info.machine = 'PC';
  } else if (userAgent.includes('Android')) {
    info.os = 'Android';
    info.machine = 'Mobile';
  } else if (userAgent.includes('iOS') || userAgent.includes('iPhone') || userAgent.includes('iPad')) {
    info.os = 'iOS';
    info.machine = 'iPhone/iPad';
  }

  // Browser Detection
  if (userAgent.includes('Chrome')) {
    info.browser = 'Chrome';
  } else if (userAgent.includes('Firefox')) {
    info.browser = 'Firefox';
  } else if (userAgent.includes('Safari')) {
    info.browser = 'Safari';
  } else if (userAgent.includes('Edge')) {
    info.browser = 'Edge';
  }

  return info;
};

// Strip rawContent from result details before persisting (prevents credential leakage in DB)
function stripSensitiveFromResults(results) {
  return (results || []).map(r => {
    if (!r.details?.rawContent) return r;
    const { rawContent, ...safeDetails } = r.details;
    return { ...r, details: safeDetails };
  });
}

async function saveAuditToSupabase(auditData, userIp, userAgent) {
  const config = getSupabaseConfig();
  if (!config) {
    console.log('[Supabase] Não configurado — pulando persistência.');
    return { success: false, error: 'Supabase não configurado' };
  }

  const clientInfo = getClientInfo(userAgent);
  const safeResults = stripSensitiveFromResults(auditData.results);

  const auditRecord = {
    audit_id: auditData.evidence?.auditId || `audit-${Date.now()}`,
    project_url: auditData.projectUrl,
    project_ref: auditData.projectRef || null,
    score: auditData.score || 0,
    grade: auditData.grade?.grade || 'F',
    grade_label: auditData.grade?.label || 'Crítico',
    total_checks: auditData.totalChecks || 0,
    passed_count: auditData.passed || 0,
    failed_count: auditData.failed || 0,
    warnings_count: auditData.warnings || 0,
    errors_count: auditData.errors || 0,
    info_count: auditData.info || 0,
    duration: auditData.duration,
    evidence_sha256: auditData.evidence?.sha256 || null,
    evidence_timestamp: auditData.evidence?.timestamp || new Date().toISOString(),
    results_json: safeResults,
    catalog_data_json: auditData.catalogData || {},
    user_ip: userIp || null,
    user_machine: clientInfo.machine,
    user_os: clientInfo.os,
    user_browser: clientInfo.browser,
    user_region: clientInfo.region,
    status: 'completed'
  };

  const result = await supabaseFetch('audits', {
    method: 'POST',
    body: JSON.stringify(auditRecord)
  });

  if (result.success && result.data && result.data[0]) {
    const auditId = result.data[0].id;

    if (safeResults.length > 0) {
      const resultsToInsert = safeResults.map(r => ({
        audit_id: auditId,
        check_name: r.check,
        status: r.status,
        severity: r.severity,
        message: r.message,
        details_json: r.details || {}
      }));
      await supabaseFetch('audit_results', { method: 'POST', body: JSON.stringify(resultsToInsert) });
    }

    const vulnerabilities = safeResults.filter(r =>
      r.status === 'FAIL' && ['critical', 'high'].includes(r.severity)
    );
    if (vulnerabilities.length > 0) {
      const vulnToInsert = vulnerabilities.map(v => ({
        audit_id: auditId,
        severity: v.severity,
        category: v.check?.split('—')[0]?.trim() || 'general',
        title: v.check,
        description: v.message,
        details_json: v.details || {}
      }));
      await supabaseFetch('vulnerabilities', { method: 'POST', body: JSON.stringify(vulnToInsert) });
    }

    return { success: true, auditId };
  }

  return { success: false, error: result.error };
}

async function getAuditHistory(limit = 50) {
  const result = await supabaseFetch(`audits?select=*&order=created_at.desc&limit=${limit}`);
  return result;
}

async function getAuditById(auditId) {
  const result = await supabaseFetch(`audits?audit_id=eq.${auditId}&select=*`);
  if (result.success && result.data && result.data.length > 0) {
    return { success: true, data: result.data[0] };
  }
  return { success: false, error: 'Audit not found' };
}

async function getVulnerabilitiesByAudit(auditDbId) {
  const result = await supabaseFetch(
    `vulnerabilities?audit_id=eq.${auditDbId}&order=severity.asc`
  );
  return result;
}

module.exports = {
  saveAuditToSupabase,
  getAuditHistory,
  getAuditById,
  getVulnerabilitiesByAudit,
  supabaseFetch
};
