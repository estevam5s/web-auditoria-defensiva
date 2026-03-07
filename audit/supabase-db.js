/*  ═══════════════════════════════════════════════════════════════════
    SUPABASE DATABASE INTEGRATION
    Saves audit results to Supabase database
    ═══════════════════════════════════════════════════════════════════ */

const fetch = require('node-fetch');

const getSupabaseConfig = () => ({
  url: process.env.SUPABASE_URL || 'https://qmrceufksvlfdwnwftst.supabase.co',
  key: process.env.SUPABASE_ANON_KEY || 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InFtcmNldWZrc3ZsZmR3bndmdHN0Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzI4NzQ0ODEsImV4cCI6MjA4ODQ1MDQ4MX0.NXX4jvBXumkAp2L8z56q5pLXoXJaVUNPnjBwn4XUPPE'
});

const supabaseFetch = async (endpoint, options = {}) => {
  const config = getSupabaseConfig();
  const url = `${config.url}/rest/v1/${endpoint}`;
  const headers = {
    'Content-Type': 'application/json',
    'apikey': config.key,
    'Authorization': `Bearer ${config.key}`,
    'Prefer': options.prefer || 'return=representation',
    ...options.headers
  };

  console.log('Supabase fetch to:', url);
  console.log('Has key:', !!config.key);

  try {
    const response = await fetch(url, {
      ...options,
      headers
    });

    const data = await response.json();
    
    console.log('Response status:', response.status);
    console.log('Response data:', JSON.stringify(data).substring(0, 200));
    
    if (!response.ok) {
      throw new Error(data.message || `HTTP ${response.status}`);
    }

    return { success: true, data };
  } catch (error) {
    console.error('Supabase fetch error:', error.message);
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

async function saveAuditToSupabase(auditData, userIp, userAgent) {
  console.log('\n========== SAVE AUDIT TO SUPABASE ==========');
  console.log('auditData:', JSON.stringify({
    auditId: auditData.evidence?.auditId,
    projectUrl: auditData.projectUrl,
    score: auditData.score,
    grade: auditData.grade,
    totalChecks: auditData.totalChecks,
    hasResults: !!auditData.results,
    resultsCount: auditData.results?.length || 0,
    hasCatalogData: !!auditData.catalogData
  }, null, 2));
  
  const clientInfo = getClientInfo(userAgent);
  console.log('Client Info:', clientInfo);
  console.log('User IP:', userIp);

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
    results_json: auditData.results || [],
    catalog_data_json: auditData.catalogData || {},
    user_ip: userIp || null,
    user_machine: clientInfo.machine,
    user_os: clientInfo.os,
    user_browser: clientInfo.browser,
    user_region: clientInfo.region,
    status: 'completed'
  };

  console.log('Attempting to insert into audits table...');
  console.log('Record keys:', Object.keys(auditRecord));
  
  const result = await supabaseFetch('audits', {
    method: 'POST',
    body: JSON.stringify(auditRecord)
  });

  console.log('Insert result:', result);

  if (result.success && result.data && result.data[0]) {
    const auditId = result.data[0].id;
    console.log('✅ Audit saved successfully! ID:', auditId);

    // Save individual results
    if (auditData.results && auditData.results.length > 0) {
      console.log(`Saving ${auditData.results.length} individual results...`);
      const resultsToInsert = auditData.results.map(r => ({
        audit_id: auditId,
        check_name: r.check,
        status: r.status,
        severity: r.severity,
        message: r.message,
        details_json: r.details || {}
      }));

      const resultsResult = await supabaseFetch('audit_results', {
        method: 'POST',
        body: JSON.stringify(resultsToInsert)
      });
      console.log('Results save result:', resultsResult);
    }

    // Save vulnerabilities
    const vulnerabilities = auditData.results?.filter(r => 
      r.status === 'FAIL' && ['critical', 'high'].includes(r.severity)
    ) || [];

    if (vulnerabilities.length > 0) {
      console.log(`Saving ${vulnerabilities.length} vulnerabilities...`);
      const vulnToInsert = vulnerabilities.map(v => ({
        audit_id: auditId,
        severity: v.severity,
        category: v.check?.split('—')[0]?.trim() || 'general',
        title: v.check,
        description: v.message,
        details_json: v.details || {}
      }));

      const vulnResult = await supabaseFetch('vulnerabilities', {
        method: 'POST',
        body: JSON.stringify(vulnToInsert)
      });
      console.log('Vulnerabilities save result:', vulnResult);
    }

    console.log('========== SAVE COMPLETE ==========\n');
    return { success: true, auditId: auditId };
  }

  console.error('❌ Failed to save audit:', result.error);
  console.log('========== SAVE FAILED ==========\n');
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

async function getVulnerabilitiesByAudit(auditId) {
  const result = await supabaseFetch(
    `vulnerabilities?audit_id=eq.${auditId}&order=severity asc`
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
