/*  ═══════════════════════════════════════════════════════════════════
    SUPABASE CATALOG REPORT: Dynamic Schema Documentation
    Generates comprehensive catalog of all discovered Supabase resources
    ═══════════════════════════════════════════════════════════════════ */

function generateSupabaseCatalog(config, data) {
  const catalog = {
    generatedAt: new Date().toISOString(),
    projectUrl: config.projectUrl,
    projectRef: config.projectRef,
    summary: {
      totalTables: 0,
      totalRPCs: 0,
      totalEdgeFunctions: 0,
      totalGraphQLTypes: 0,
      totalStorageBuckets: 0
    },
    tables: [],
    rpcFunctions: [],
    graphql: {
      types: [],
      queries: [],
      mutations: []
    },
    edgeFunctions: [],
    storage: {
      public: [],
      private: []
    },
    relationships: [],
    vulnerabilities: {
      critical: [],
      high: [],
      medium: [],
      low: []
    }
  };

  if (data.openapi) {
    catalog.tables = data.openapi.tables || [];
    catalog.rpcFunctions = data.openapi.rpcFunctions || [];
    catalog.summary.totalTables = catalog.tables.length;
    catalog.summary.totalRPCs = catalog.rpcFunctions.length;
  }

  if (data.graphql) {
    catalog.graphql.types = data.graphql.userTypes || [];
    catalog.graphql.queries = data.graphql.queries || [];
    catalog.graphql.mutations = data.graphql.mutations || [];
    catalog.summary.totalGraphQLTypes = catalog.graphql.types.length;
  }

  if (data.restScan) {
    catalog.tables = catalog.tables.map(table => {
      const testResult = data.restScan.find(t => t.table === table.name);
      return testResult ? { ...table, ...testResult } : table;
    });
  }

  if (data.relationship) {
    catalog.relationships = data.relationship.map(r => ({
      from: r.sourceTable,
      to: r.targetTable,
      via: r.viaColumn,
      accessible: r.accessible,
      exposedFields: r.exposedFields,
      severity: r.severity
    }));
  }

  if (data.edgeFunctions) {
    catalog.edgeFunctions = data.edgeFunctions;
    catalog.summary.totalEdgeFunctions = data.edgeFunctions.length;
  }

  if (data.storage) {
    catalog.storage = data.storage;
    catalog.summary.totalStorageBuckets = (catalog.storage.public?.length || 0) + (catalog.storage.private?.length || 0);
  }

  const allResults = data.allResults || [];
  for (const result of allResults) {
    if (result.severity === 'critical' && result.status !== 'PASS') {
      catalog.vulnerabilities.critical.push({ check: result.check, message: result.message });
    } else if (result.severity === 'high' && result.status !== 'PASS') {
      catalog.vulnerabilities.high.push({ check: result.check, message: result.message });
    } else if (result.severity === 'medium' && result.status !== 'PASS') {
      catalog.vulnerabilities.medium.push({ check: result.check, message: result.message });
    } else if (result.severity === 'low' && result.status !== 'PASS') {
      catalog.vulnerabilities.low.push({ check: result.check, message: result.message });
    }
  }

  return catalog;
}

function generateCatalogHTML(catalog) {
  const { summary, tables, rpcFunctions, graphql, relationships, vulnerabilities } = catalog;

  let html = `
<!DOCTYPE html>
<html lang="pt-BR">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Supabase Catalog — ${catalog.projectUrl}</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0d1117; color: #c9d1d9; line-height: 1.6; }
    .container { max-width: 1400px; margin: 0 auto; padding: 20px; }
    h1, h2, h3 { color: #58a6ff; margin-bottom: 15px; }
    h1 { border-bottom: 2px solid #30363d; padding-bottom: 10px; margin-bottom: 30px; }
    .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 30px; }
    .card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px; }
    .card h3 { font-size: 14px; color: #8b949e; margin-bottom: 8px; }
    .card .number { font-size: 32px; font-weight: bold; color: #58a6ff; }
    .section { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px; margin-bottom: 20px; }
    table { width: 100%; border-collapse: collapse; margin-top: 10px; }
    th, td { padding: 10px; text-align: left; border-bottom: 1px solid #30363d; }
    th { color: #8b949e; font-weight: 600; }
    .badge { display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 12px; margin-right: 5px; }
    .badge-critical { background: #da3633; color: #fff; }
    .badge-high { background: #d29922; color: #000; }
    .badge-medium { background: #58a6ff; color: #000; }
    .badge-low { background: #3fb950; color: #000; }
    .badge-pass { background: #238636; color: #fff; }
    code { background: #21262d; padding: 2px 6px; border-radius: 4px; font-size: 13px; }
    .vuln-list { list-style: none; }
    .vuln-list li { padding: 8px 0; border-bottom: 1px solid #30363d; }
    .vuln-list li:last-child { border-bottom: none; }
    .timestamp { color: #8b949e; font-size: 14px; }
  </style>
</head>
<body>
  <div class="container">
    <h1>📦 Supabase Catalog — ${catalog.projectUrl}</h1>
    <p class="timestamp">Gerado em: ${catalog.generatedAt}</p>
    
    <div class="summary">
      <div class="card">
        <h3>Tabelas</h3>
        <div class="number">${summary.totalTables}</div>
      </div>
      <div class="card">
        <h3>Funções RPC</h3>
        <div class="number">${summary.totalRPCs}</div>
      </div>
      <div class="card">
        <h3>Tipos GraphQL</h3>
        <div class="number">${summary.totalGraphQLTypes}</div>
      </div>
      <div class="card">
        <h3>Edge Functions</h3>
        <div class="number">${summary.totalEdgeFunctions}</div>
      </div>
      <div class="card">
        <h3>Storage Buckets</h3>
        <div class="number">${summary.totalStorageBuckets}</div>
      </div>
      <div class="card">
        <h3>Vulnerabilidades</h3>
        <div class="number">${vulnerabilities.critical.length + vulnerabilities.high.length + vulnerabilities.medium.length + vulnerabilities.low.length}</div>
      </div>
    </div>

    ${vulnerabilities.critical.length > 0 ? `
    <div class="section">
      <h2>🔴 Vulnerabilidades Críticas</h2>
      <ul class="vuln-list">
        ${vulnerabilities.critical.map(v => `<li><span class="badge badge-critical">CRITICAL</span> <strong>${v.check}</strong>: ${v.message}</li>`).join('')}
      </ul>
    </div>
    ` : ''}

    ${vulnerabilities.high.length > 0 ? `
    <div class="section">
      <h2>🟠 Vulnerabilidades Altas</h2>
      <ul class="vuln-list">
        ${vulnerabilities.high.map(v => `<li><span class="badge badge-high">HIGH</span> <strong>${v.check}</strong>: ${v.message}</li>`).join('')}
      </ul>
    </div>
    ` : ''}

    <div class="section">
      <h2>📊 Tabelas do Banco de Dados</h2>
      <table>
        <thead>
          <tr>
            <th>Tabela</th>
            <th>Colunas</th>
            <th>Leitura</th>
            <th>Gravação</th>
            <th>Severity</th>
          </tr>
        </thead>
        <tbody>
          ${tables.slice(0, 50).map(t => `
          <tr>
            <td><code>${t.name}</code></td>
            <td>${t.columnCount || t.columns?.length || 0}</td>
            <td>${t.readable !== undefined ? (t.readable ? '✓' : '✗') : '-'}</td>
            <td>${t.writable !== undefined ? (t.writable ? '✓' : '✗') : '-'}</td>
            <td>${t.severity ? `<span class="badge badge-${t.severity}">${t.severity.toUpperCase()}</span>` : '-'}</td>
          </tr>
          `).join('')}
        </tbody>
      </table>
      ${tables.length > 50 ? `<p style="margin-top:10px;color:#8b949e">... e mais ${tables.length - 50} tabelas</p>` : ''}
    </div>

    ${rpcFunctions.length > 0 ? `
    <div class="section">
      <h2>⚡ Funções RPC</h2>
      <table>
        <thead>
          <tr>
            <th>Função</th>
            <th>Argumentos</th>
            <th>Tipo de Retorno</th>
          </tr>
        </thead>
        <tbody>
          ${rpcFunctions.slice(0, 30).map(f => `
          <tr>
            <td><code>${f.name}</code></td>
            <td>${f.args?.length || 0}</td>
            <td>${f.returnType || 'unknown'}</td>
          </tr>
          `).join('')}
        </tbody>
      </table>
    </div>
    ` : ''}

    ${graphql.types.length > 0 ? `
    <div class="section">
      <h2>🔷 Tipos GraphQL</h2>
      <table>
        <thead>
          <tr>
            <th>Tipo</th>
            <th>Campos</th>
          </tr>
        </thead>
        <tbody>
          ${graphql.types.slice(0, 30).map(t => `
          <tr>
            <td><code>${t.name}</code></td>
            <td>${t.fields?.length || 0}</td>
          </tr>
          `).join('')}
        </tbody>
      </table>
    </div>
    ` : ''}

    ${relationships.length > 0 ? `
    <div class="section">
      <h2>🔗 Relacionamentos Detectados</h2>
      <table>
        <thead>
          <tr>
            <th>De</th>
            <th>Para</th>
            <th>Via</th>
            <th>Acessível</th>
            <th>Campos Expostos</th>
            <th>Severity</th>
          </tr>
        </thead>
        <tbody>
          ${relationships.map(r => `
          <tr>
            <td><code>${r.from}</code></td>
            <td><code>${r.to}</code></td>
            <td><code>${r.via}</code></td>
            <td>${r.accessible ? '✓' : '✗'}</td>
            <td>${r.exposedFields?.slice(0, 5).join(', ') || '-'}</td>
            <td>${r.severity ? `<span class="badge badge-${r.severity}">${r.severity.toUpperCase()}</span>` : '-'}</td>
          </tr>
          `).join('')}
        </tbody>
      </table>
    </div>
    ` : ''}
  </div>
</body>
</html>
  `;

  return html;
}

module.exports = { generateSupabaseCatalog, generateCatalogHTML };
