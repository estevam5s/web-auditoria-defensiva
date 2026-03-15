/*  ═══════════════════════════════════════════════════════════════════
    SAAS CUSTOMER DATA EXPOSURE CHECK
    Detects PII/sensitive customer data exposed in Supabase tables
    without Row Level Security — covers Brasil + International patterns
    ═══════════════════════════════════════════════════════════════════ */

const { safeFetch } = require('../helpers/http');

// ── PII column name patterns ──────────────────────────────────────
const PII_PATTERNS = [
  // Critical — credentials / payment / identity
  { pattern: /senha|password|passwd|secret|cvv|cvc|pin\b|ssn|social_security/i,           severity: 'critical', label: 'Credencial/Senha' },
  { pattern: /cpf|cnpj|cc_number|card_number|numero_cartao|cartao_credito|passport|passaporte/i, severity: 'critical', label: 'Documento/Cartão' },
  // High — personal identifiers
  { pattern: /email|e_mail|telefone|phone|celular|mobile|nascimento|birth_date|dob|data_nascimento/i, severity: 'high', label: 'Contato/Nascimento' },
  { pattern: /\bname\b|full_name|nome_completo|nome_cliente|customer_name|\brg\b|pis\b|pasep|pix_key|chave_pix|\bnif\b/i, severity: 'high', label: 'Nome/Documento' },
  // Medium — location / tracking
  { pattern: /endereco|logradouro|\bcep\b|zip_code|postal_code|address|cidade|city|estado\b|state\b/i, severity: 'medium', label: 'Endereço' },
  { pattern: /ip_address|user_agent|device_id|session_id|tracking_id/i,                   severity: 'medium', label: 'Rastreamento' },
];

// Severity ranking for comparison
const SEV_RANK = { critical: 3, high: 2, medium: 1, info: 0 };

function detectPiiColumns(columns) {
  const found = [];
  for (const col of columns) {
    for (const { pattern, severity, label } of PII_PATTERNS) {
      if (pattern.test(col)) {
        found.push({ name: col, piiType: label, severity });
        break; // Only match first pattern per column
      }
    }
  }
  return found;
}

async function saasCustomerDataCheck(config, emit) {
  const baseUrl = (config._supabaseUrl || config.projectUrl).replace(/\/$/, '');
  const results = [];

  emit && emit({ type: 'log', level: 'info', message: '[SaaS PII] Verificando exposição de dados de clientes...' });

  // ── 1. Get OpenAPI schema (lists tables + columns) ────────────
  const schemaRes = await safeFetch(`${baseUrl}/rest/v1/`, {
    timeout: 10000,
    headers: { Accept: 'application/openapi+json' }
  });

  if (!schemaRes.ok || !schemaRes.text) {
    results.push({
      check: '🧑‍💼 SaaS Customer Data Exposure',
      status: 'INFO',
      severity: 'info',
      message: 'Não foi possível acessar o schema OpenAPI para verificar dados de clientes.',
      details: { reason: 'OpenAPI endpoint não acessível' }
    });
    return results;
  }

  let schema;
  try {
    schema = JSON.parse(schemaRes.text);
  } catch {
    results.push({
      check: '🧑‍💼 SaaS Customer Data Exposure',
      status: 'INFO',
      severity: 'info',
      message: 'Schema OpenAPI retornado não é JSON válido.',
      details: {}
    });
    return results;
  }

  // ── 2. Extract table definitions from OpenAPI paths ───────────
  const paths = schema.paths || {};
  const definitions = schema.definitions || schema.components?.schemas || {};

  const tableDefs = [];

  // PostgREST OpenAPI: definitions contain table schemas
  for (const [defName, def] of Object.entries(definitions)) {
    if (!def.properties) continue;
    const columns = Object.keys(def.properties);
    tableDefs.push({ table: defName, columns });
  }

  // Fallback: extract table names from paths
  if (tableDefs.length === 0) {
    for (const path of Object.keys(paths)) {
      const tableName = path.replace(/^\//, '');
      if (tableName && !tableName.includes('/') && !tableName.includes('{')) {
        tableDefs.push({ table: tableName, columns: [] });
      }
    }
  }

  if (tableDefs.length === 0) {
    results.push({
      check: '🧑‍💼 SaaS Customer Data Exposure',
      status: 'PASS',
      severity: 'info',
      message: 'Nenhuma tabela encontrada no schema para verificar.',
      details: {}
    });
    return results;
  }

  emit && emit({ type: 'log', level: 'info', message: `[SaaS PII] Analisando ${tableDefs.length} tabela(s)...` });

  // ── 3. Check which tables are accessible without auth ─────────
  const exposedTables = [];
  const anonKey = config.anonKey;

  for (const { table, columns } of tableDefs) {
    const tableUrl = `${baseUrl}/rest/v1/${table}?limit=1`;
    const headers = anonKey
      ? { apikey: anonKey, Authorization: `Bearer ${anonKey}` }
      : {};

    const res = await safeFetch(tableUrl, { timeout: 8000, headers });

    const isAccessible = res.ok && res.text && res.text.trim().startsWith('[');
    if (!isAccessible) continue;

    const piiCols = detectPiiColumns(columns);
    if (piiCols.length === 0) continue;

    exposedTables.push({ table, piiColumns: piiCols });
    emit && emit({
      type: 'log', level: 'warn',
      message: `[SaaS PII] Tabela "${table}" exposta com ${piiCols.length} campo(s) PII: ${piiCols.map(c => c.name).join(', ')}`
    });
  }

  // ── 4. Build result ───────────────────────────────────────────
  if (exposedTables.length === 0) {
    results.push({
      check: '🧑‍💼 SaaS Customer Data Exposure',
      status: 'PASS',
      severity: 'info',
      message: `Nenhum dado de cliente exposto publicamente. ${tableDefs.length} tabela(s) verificada(s).`,
      details: { tablesChecked: tableDefs.length }
    });
    return results;
  }

  // Determine overall severity (worst found)
  const worstSeverity = exposedTables
    .flatMap(t => t.piiColumns)
    .reduce((worst, col) => SEV_RANK[col.severity] > SEV_RANK[worst] ? col.severity : worst, 'medium');

  const totalPiiColumns = exposedTables.reduce((sum, t) => sum + t.piiColumns.length, 0);

  results.push({
    check: '🧑‍💼 SaaS Customer Data Exposure',
    status: 'FAIL',
    severity: worstSeverity,
    message: `${exposedTables.length} tabela(s) com dados de clientes acessível(is) publicamente — ${totalPiiColumns} campo(s) PII exposto(s) sem autenticação!`,
    details: {
      exposedTables: exposedTables.map(t => ({
        table: t.table,
        piiColumns: t.piiColumns,
        worstSeverity: t.piiColumns.reduce((w, c) => SEV_RANK[c.severity] > SEV_RANK[w] ? c.severity : w, 'medium')
      })),
      totalPiiColumns,
      recommendation: 'URGENTE: Ative RLS (Row Level Security) em todas as tabelas que contêm dados de clientes. Execute: ALTER TABLE <tabela> ENABLE ROW LEVEL SECURITY; e defina políticas de acesso adequadas no Supabase Dashboard → Authentication → Policies.'
    }
  });

  return results;
}

module.exports = { saasCustomerDataCheck };
