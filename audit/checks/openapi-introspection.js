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
    totalRoutes: 0,
    scannedAt: new Date().toISOString()
  };

  emit({ type: 'log', level: 'info', message: '[OpenAPI] Iniciando introspection do schema...' });

  const restUrl = `${baseUrl}/rest/v1/`;

  // Try with OpenAPI Accept headers (Supabase supports this)
  const schemaRes = await safeFetch(restUrl, {
    headers: { ...headers, 'Accept': 'application/openapi+json' },
    timeout: 15000
  });

  // Also try without special Accept to get JSON directly
  const schemaRes2 = schemaRes.ok ? null : await safeFetch(restUrl, { headers, timeout: 15000 });
  const activeRes = schemaRes.ok ? schemaRes : schemaRes2;

  if (activeRes && activeRes.ok && activeRes.json) {
    const schemaData = activeRes.json;

    // Supabase returns OpenAPI 2.0 / 3.0 format with "paths" and "definitions"/"components"
    if (schemaData.paths) {
      const allPaths = Object.keys(schemaData.paths);
      catalog.totalRoutes = allPaths.length;

      // Extract tables (non-RPC paths)
      const tablePaths = allPaths.filter(p => !p.includes('/rpc/'));
      const rpcPaths = allPaths.filter(p => p.includes('/rpc/'));

      for (const tablePath of tablePaths) {
        const tableName = tablePath.replace(/^\//, '');
        if (!tableName || tableName.includes('/')) continue;

        const columns = [];
        // Try to get column info from definitions (OpenAPI 2.0)
        const def = schemaData.definitions?.[tableName] || schemaData.components?.schemas?.[tableName];
        if (def?.properties) {
          for (const [colName, colInfo] of Object.entries(def.properties)) {
            columns.push({
              name: colName,
              type: colInfo.type || colInfo.format || 'unknown',
              nullable: !def.required?.includes(colName),
            });
          }
        }

        catalog.tables.push({
          name: tableName,
          columns,
          columnCount: columns.length
        });
      }

      for (const rpcPath of rpcPaths) {
        const rpcName = rpcPath.replace('/rpc/', '').replace(/^\//, '');
        if (rpcName) {
          catalog.rpcFunctions.push({ name: rpcName, args: [], returnType: 'unknown' });
        }
      }

      catalog.totalTables = catalog.tables.length;
      catalog.totalRPCs = catalog.rpcFunctions.length;

      emit({ type: 'log', level: 'info', message: `[OpenAPI] /rest/v1/ -> 200 (tables=${catalog.totalTables}, rpcs=${catalog.totalRPCs}, total_routes=${catalog.totalRoutes})` });

      if (catalog.totalTables > 0 || catalog.totalRPCs > 0) {
        results.push({
          check: 'OpenAPI — Schema Exposure',
          status: 'FAIL',
          severity: catalog.totalTables > 20 ? 'high' : 'medium',
          message: `OpenAPI expõe catálogo público: ${catalog.totalTables} tabelas, ${catalog.totalRPCs} RPCs (${catalog.totalRoutes} rotas totais).`,
          details: {
            url: restUrl,
            totalRoutes: catalog.totalRoutes,
            tables: catalog.totalTables,
            rpcs: catalog.totalRPCs,
            tablesList: catalog.tables.map(t => t.name).slice(0, 50),
            rpcList: catalog.rpcFunctions.map(f => f.name),
            recommendation: 'Restrinja o acesso ao schema via Dashboard > API Settings > Expose schemas'
          }
        });
      }
    } else if (typeof schemaData === 'object' && !Array.isArray(schemaData)) {
      // Legacy format: direct key=table mapping
      const tables = Object.keys(schemaData).filter(k => !k.startsWith('_') && !['swagger', 'info', 'host', 'basePath', 'schemes', 'consumes', 'produces'].includes(k));

      for (const tableName of tables) {
        catalog.tables.push({ name: tableName, columns: [], columnCount: 0 });
      }
      catalog.totalTables = catalog.tables.length;
      catalog.totalRoutes = catalog.totalTables;

      if (catalog.totalTables > 0) {
        emit({ type: 'log', level: 'info', message: `[OpenAPI] ${catalog.totalTables} tabelas encontradas (formato legado)` });
      }
    }
  }

  // If no tables found via OpenAPI, discover via direct probing
  if (catalog.tables.length === 0) {
    emit({ type: 'log', level: 'info', message: '[OpenAPI] Testando tabela por tabela para descobrir mais...' });

    const foundTables = new Set(catalog.tables.map(t => t.name));
    const BATCH_SIZE = 10;
    let batchCount = 0;

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
        if (result) catalog.tables.push(result);
      }

      batchCount++;
      if (batchCount % 3 === 0) {
        emit({ type: 'log', level: 'info', message: `[OpenAPI] ${foundTables.size} tabelas descobertas...` });
      }
    }

    catalog.totalTables = catalog.tables.length;
  }

  // Discover RPC functions via /rest/v1/rpc/ if not already found
  if (catalog.rpcFunctions.length === 0) {
    emit({ type: 'log', level: 'info', message: '[OpenAPI] Verificando funções RPC...' });

    const rpcBase = `${baseUrl}/rest/v1/rpc/`;
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
        catalog.totalRPCs = catalog.rpcFunctions.length;
      }
    }
  }

  if (catalog.totalTables > 0) {
    results.push({
      check: 'OpenAPI — Complete Catalog',
      status: 'INFO',
      severity: 'info',
      message: `Catálogo gerado: ${catalog.totalTables} tabelas, ${catalog.totalRPCs} funções RPC.`,
      details: {
        totalTables: catalog.totalTables,
        totalRPCs: catalog.totalRPCs,
        totalRoutes: catalog.totalRoutes,
        tablesList: catalog.tables.map(t => t.name),
        rpcList: catalog.rpcFunctions.map(f => f.name),
        recommendation: 'Use este catálogo para testes detalhados de cada tabela.'
      }
    });
  }

  return { results, catalog };
}

module.exports = { openAPIIntrospection };
