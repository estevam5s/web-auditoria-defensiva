/*  ═══════════════════════════════════════════════════════════════════
    RELATIONSHIP RLS SCAN: Indirect Data Leak Detection
    Tests joins between tables to identify indirect data exposure
    Verifies if RLS can be bypassed through foreign key relationships
    ═══════════════════════════════════════════════════════════════════ */

const { safeFetch, supabaseHeaders } = require('../helpers/http');

const SENSITIVE_COLUMNS = [
  'password', 'password_hash', 'token', 'secret', 'api_key',
  'ssn', 'cpf', 'document', 'credit_card', 'cvv',
  'address', 'phone', 'mobile', 'birth_date', 'balance'
];

const RELATIONSHIP_PATTERNS = [
  { source: 'posts', target: 'users', via: 'user_id', aliases: ['author', 'creator', 'owner'] },
  { source: 'orders', target: 'users', via: 'user_id', aliases: ['customer', 'client'] },
  { source: 'comments', target: 'users', via: 'user_id', aliases: ['author', 'user'] },
  { source: 'profiles', target: 'users', via: 'id', aliases: ['user', 'account'] },
  { source: 'payments', target: 'users', via: 'user_id', aliases: ['payer', 'customer'] },
  { source: 'messages', target: 'users', via: 'sender_id', aliases: ['from', 'author'] },
  { source: 'messages', target: 'users', via: 'receiver_id', aliases: ['to', 'recipient'] },
  { source: 'products', target: 'users', via: 'created_by', aliases: ['creator', 'owner'] },
  { source: 'files', target: 'users', via: 'user_id', aliases: ['owner', 'uploader'] },
  { source: 'notifications', target: 'users', via: 'user_id', aliases: ['recipient', 'target'] },
  { source: 'sessions', target: 'users', via: 'user_id', aliases: ['user', 'account'] },
  { source: 'accounts', target: 'users', via: 'user_id', aliases: ['user', 'owner'] },
  { source: 'addresses', target: 'users', via: 'user_id', aliases: ['user', 'owner'] },
  { source: 'reviews', target: 'users', via: 'user_id', aliases: ['reviewer', 'author'] },
  { source: 'transactions', target: 'users', via: 'user_id', aliases: ['user', 'customer'] },
  { source: 'invoices', target: 'users', via: 'user_id', aliases: ['customer', 'payer'] },
  { source: 'subscriptions', target: 'users', via: 'user_id', aliases: ['subscriber', 'customer'] },
  { source: 'activities', target: 'users', via: 'user_id', aliases: ['user', 'actor'] },
];

async function relationshipRLSScan(config, emit, tableTests = []) {
  const results = [];
  const baseUrl = config.projectUrl;
  const anonKey = config.anonKey;
  const headers = supabaseHeaders(anonKey);

  const findings = [];
  const testedJoins = [];

  emit({ type: 'log', level: 'info', message: '[Relationship RLS] Iniciando verificação de vazamentos via joins...' });

  const tablesToAnalyze = tableTests && tableTests.length > 0
    ? tableTests.filter(t => t.readable).map(t => t.table)
    : ['users', 'profiles', 'posts', 'orders', 'comments', 'payments', 'messages', 'files'];

  const relationshipTests = [];

  for (const rel of RELATIONSHIP_PATTERNS) {
    if (tablesToAnalyze.includes(rel.source) && tablesToAnalyze.includes(rel.target)) {
      relationshipTests.push(rel);
    }
  }

  if (relationshipTests.length === 0) {
    emit({ type: 'log', level: 'info', message: '[Relationship RLS] Poucas tabelas expostas para testar relações' });
  }

  const BATCH_SIZE = 6;
  let tested = 0;

  for (let i = 0; i < relationshipTests.length; i += BATCH_SIZE) {
    const batch = relationshipTests.slice(i, i + BATCH_SIZE);
    const promises = batch.map(async (rel) => {
      const testResult = {
        sourceTable: rel.source,
        targetTable: rel.target,
        viaColumn: rel.via,
        accessible: false,
        exposedFields: [],
        sensitiveFieldsExposed: false,
        severity: 'low'
      };

      const joinUrl = `${baseUrl}/rest/v1/${rel.source}?select=*${encodeURIComponent(',')}${rel.target}:${rel.target}(*)&limit=3`;

      const res = await safeFetch(joinUrl, { headers, timeout: 8000 });

      if (res.ok && Array.isArray(res.json) && res.json.length > 0) {
        testResult.accessible = true;

        const firstRecord = res.json[0];
        const targetData = firstRecord[rel.target];

        if (targetData && typeof targetData === 'object') {
          testResult.exposedFields = Object.keys(targetData);

          const sensitiveExposed = testResult.exposedFields.filter(field =>
            SENSITIVE_COLUMNS.some(s => field.toLowerCase().includes(s.toLowerCase()))
          );

          if (sensitiveExposed.length > 0) {
            testResult.sensitiveFieldsExposed = true;
            testResult.severity = 'critical';
            testResult.sensitiveFields = sensitiveExposed;
          } else {
            testResult.severity = 'high';
          }
        }
      }

      for (const alias of rel.aliases) {
        const aliasUrl = `${baseUrl}/rest/v1/${rel.source}?select=*${encodeURIComponent(',')}${alias}:${rel.target}(*)&limit=3`;
        const aliasRes = await safeFetch(aliasUrl, { headers, timeout: 8000 });

        if (aliasRes.ok && Array.isArray(aliasRes.json) && aliasRes.json.length > 0) {
          testResult.accessible = true;

          const aliasData = aliasRes.json[0][alias];
          if (aliasData && typeof aliasData === 'object') {
            const aliasFields = Object.keys(aliasData);
            testResult.exposedFields = [...new Set([...testResult.exposedFields, ...aliasFields])];

            const sensitiveExposed = aliasFields.filter(field =>
              SENSITIVE_COLUMNS.some(s => field.toLowerCase().includes(s.toLowerCase()))
            );

            if (sensitiveExposed.length > 0) {
              testResult.sensitiveFieldsExposed = true;
              testResult.severity = 'critical';
              testResult.sensitiveFields = [...new Set([...(testResult.sensitiveFields || []), ...sensitiveExposed])];
            }
          }
        }
      }

      return testResult;
    });

    const batchResults = await Promise.all(promises);
    for (const result of batchResults) {
      tested++;
      testedJoins.push(result);

      if (result.accessible) {
        findings.push(result);
      }
    }

    if (tested % 12 === 0) {
      emit({ type: 'log', level: 'info', message: `[Relationship RLS] ${tested} relações testadas...` });
    }
  }

  emit({ type: 'log', level: 'info', message: `[Relationship RLS] ${findings.length} joins acessíveis encontrados` });

  if (findings.length > 0) {
    const criticalFindings = findings.filter(f => f.severity === 'critical');
    const highFindings = findings.filter(f => f.severity === 'high');

    results.push({
      check: 'Relationship RLS — Indirect Data Leak',
      status: criticalFindings.length > 0 ? 'FAIL' : 'WARN',
      severity: criticalFindings.length > 0 ? 'critical' : 'high',
      message: `${findings.length} relação(ões) permite(m) acesso a dados de outras tabelas via joins!`,
      details: {
        totalJoinsAccessible: findings.length,
        criticalLeaks: criticalFindings.length,
        relationships: findings.map(f => ({
          from: f.sourceTable,
          to: f.targetTable,
          via: f.viaColumn,
          accessible: f.accessible,
          exposedFields: f.exposedFields,
          sensitiveFields: f.sensitiveFields || [],
          severity: f.severity
        })),
        recommendation: 'Crie políticas RLS restritivas para prevenir acesso via FK. Use SELECT com colunas específicas.'
      }
    });

    const sensitiveLeaks = findings.filter(f => f.sensitiveFieldsExposed);
    if (sensitiveLeaks.length > 0) {
      results.push({
        check: 'Relationship RLS — Sensitive Data via Joins',
        status: 'FAIL',
        severity: 'critical',
        message: `Dados SENSÍVEIS acessíveis via relationships! (${sensitiveLeaks.length} tabelas)`,
        details: {
          leaks: sensitiveLeaks.map(l => ({
            from: l.sourceTable,
            to: l.targetTable,
            sensitiveColumns: l.sensitiveFields
          })),
          recommendation: 'URGENTE: Bloqueie acesso a colunas sensíveis em relações. Use políticas de coluna específica.'
        }
      });
    }
  } else {
    results.push({
      check: 'Relationship RLS — Indirect Access',
      status: 'PASS',
      severity: 'info',
      message: 'Nenhum vazamento indireto via relacionamentos detectado.',
      details: { joinsTested: tested }
    });
  }

  return { results, findings };
}

module.exports = { relationshipRLSScan };
