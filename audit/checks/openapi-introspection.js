/*  ═══════════════════════════════════════════════════════════════════
    OPENAPI INTROSPECTION: Schema Discovery
    Scans /rest/v1/ to identify all tables, columns, RPC functions
    Generates dynamic catalog of available routes
    ═══════════════════════════════════════════════════════════════════ */

const { safeFetch, supabaseHeaders } = require('../helpers/http');

const COMMON_TABLE_NAMES = [
  'users', 'profiles', 'accounts', 'posts', 'orders', 'payments',
  'products', 'customers', 'messages', 'notifications', 'settings',
  'admin', 'logs', 'sessions', 'tokens', 'documents', 'files',
  'comments', 'roles', 'permissions', 'api_keys', 'secrets',
  'categories', 'tags', 'media', 'attachments', 'events', 'audit_logs',
  'analytics', 'reports', 'subscriptions', 'invoices', 'transactions',
  'addresses', 'contacts', 'companies', 'teams', 'members', 'invitations',
  'verifications', 'password_resets', 'activities', 'bookmarks', 'likes',
  'followers', 'following', 'conversations', 'threads', 'replies',
  'schemas', 'tables', 'columns', 'constraints', 'views', 'functions',
  'triggers', 'indexes', 'migrations', 'backups', 'configurations',
  'features', 'plans', 'pricing', 'billing', 'checkout', 'cart',
  'items', 'inventory', 'stock', 'warehouses', 'suppliers', 'shipping',
  'deliveries', 'returns', 'refunds', 'disputes', 'reviews', 'ratings',
  'faq', 'pages', 'sections', 'components', 'templates', 'themes',
  'assets', 'resources', 'cache', 'jobs', 'queues', 'workers'
];

async function openAPIIntrospection(config, emit) {
  const results = [];
  const baseUrl = config.projectUrl;
  const anonKey = config.anonKey;
  const headers = supabaseHeaders(anonKey);

  const catalog = {
    tables: [],
    rpcFunctions: [],
    totalTables: 0,
    totalRPCs: 0,
    scannedAt: new Date().toISOString()
  };

  emit({ type: 'log', level: 'info', message: '[OpenAPI] Iniciando introspection do schema...' });

  const restUrl = `${baseUrl}/rest/v1/`;
  const schemaRes = await safeFetch(restUrl, { headers, timeout: 15000 });

  if (schemaRes.ok && schemaRes.json) {
    const schemaData = schemaRes.json;

    if (typeof schemaData === 'object' && !Array.isArray(schemaData)) {
      const tables = Object.keys(schemaData).filter(k => !k.startsWith('_'));

      emit({ type: 'log', level: 'info', message: `[OpenAPI] ${tables.length} tabelas encontradas no schema` });

      for (const tableName of tables) {
        const tableInfo = schemaData[tableName];
        const columns = [];

        if (tableInfo && typeof tableInfo === 'object') {
          for (const [colName, colInfo] of Object.entries(tableInfo)) {
            columns.push({
              name: colName,
              type: colInfo.type || 'unknown',
              nullable: colInfo.nullable !== false,
              default: colInfo.default || null,
              isArray: colInfo.is_array || false,
              references: colInfo.references || null
            });
          }
        }

        catalog.tables.push({
          name: tableName,
          columns,
          columnCount: columns.length
        });
      }

      catalog.totalTables = catalog.tables.length;

      results.push({
        check: 'OpenAPI — Schema Exposure',
        status: catalog.totalTables > 0 ? 'WARN' : 'PASS',
        severity: catalog.totalTables > 20 ? 'high' : 'medium',
        message: `${catalog.totalTables} tabela(s) descoberta(s) via OpenAPI introspection.`,
        details: {
          url: restUrl,
          tables: catalog.tables.slice(0, 50).map(t => ({
            name: t.name,
            columns: t.columnCount,
            sampleColumns: t.columns.slice(0, 5).map(c => c.name)
          })),
          recommendation: 'Restrinja o acesso ao schema via Dashboard > API Settings > Expose schemas'
        }
      });
    }
  }

  emit({ type: 'log', level: 'info', message: '[OpenAPI] Testando tabela por tabela para descobrir mais...' });

  const foundTables = new Set(catalog.tables.map(t => t.name));
  const BATCH_SIZE = 10;

  for (let i = 0; i < COMMON_TABLE_NAMES.length; i += BATCH_SIZE) {
    const batch = COMMON_TABLE_NAMES.slice(i, i + BATCH_SIZE);
    const promises = batch.map(async (tableName) => {
      if (foundTables.has(tableName)) return null;

      const tableUrl = `${baseUrl}/rest/v1/${tableName}?select=*&limit=1`;
      const res = await safeFetch(tableUrl, { headers, timeout: 5000 });

      if (res.ok && res.json !== null) {
        const columns = Array.isArray(res.json) && res.json.length > 0
          ? Object.keys(res.json[0])
          : [];

        foundTables.add(tableName);
        return {
          name: tableName,
          columns: columns.map(c => ({ name: c, type: 'unknown', nullable: true })),
          columnCount: columns.length,
          hasData: Array.isArray(res.json) && res.json.length > 0
        };
      }
      return null;
    });

    const batchResults = await Promise.all(promises);
    for (const result of batchResults) {
      if (result) {
        catalog.tables.push(result);
      }
    }

    if (i % 30 === 0) {
      emit({ type: 'log', level: 'info', message: `[OpenAPI] ${foundTables.size} tabelas descobertas...` });
    }
  }

  catalog.totalTables = catalog.tables.length;

  emit({ type: 'log', level: 'info', message: '[OpenAPI] Verificando funções RPC...' });

  const rpcEndpoints = [
    `${baseUrl}/rest/v1/rpc/`,
    `${baseUrl}/rpc/`
  ];

  for (const rpcBase of rpcEndpoints) {
    const rpcRes = await safeFetch(rpcBase, { headers, timeout: 10000 });
    if (rpcRes.ok && rpcRes.json) {
      const rpcData = rpcRes.json;
      if (Array.isArray(rpcData)) {
        for (const func of rpcData) {
          catalog.rpcFunctions.push({
            name: func.name || func,
            args: func.args || [],
            returnType: func.return_type || 'unknown'
          });
        }
      }
    }
  }

  catalog.totalRPCs = catalog.rpcFunctions.length;

  if (catalog.totalTables > 0) {
    results.push({
      check: 'OpenAPI — Complete Catalog',
      status: 'INFO',
      severity: 'info',
      message: `Catálogo gerado: ${catalog.totalTables} tabelas, ${catalog.totalRPCs} funções RPC.`,
      details: {
        totalTables: catalog.totalTables,
        totalRPCs: catalog.totalRPCs,
        tablesList: catalog.tables.map(t => t.name),
        rpcList: catalog.rpcFunctions.map(f => f.name),
        recommendation: 'Use este catálogo para testes detalhados de cada tabela.'
      }
    });
  }

  return { results, catalog };
}

module.exports = { openAPIIntrospection };
