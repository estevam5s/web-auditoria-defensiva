/*  ═══════════════════════════════════════════════════════════════════
    GRAPHQL SCAN: Comprehensive GraphQL Analysis
    Extended introspection with full schema mapping
    Tests queries, mutations without authentication
    ═══════════════════════════════════════════════════════════════════ */

const { safeFetch, supabaseHeaders } = require('../helpers/http');

const INTROSPECTION_QUERY = `
  query IntrospectionQuery {
    __schema {
      queryType { name }
      mutationType { name }
      subscriptionType { name }
      types {
        ...FullType
      }
      directives {
        name
        description
        locations
        args {
          ...InputValue
        }
      }
    }
  }
  fragment FullType on __Type {
    kind
    name
    description
    fields(includeDeprecated: true) {
      name
      description
      args {
        ...InputValue
      }
      type {
        ...TypeRef
      }
      isDeprecated
      deprecationReason
    }
    inputFields {
      ...InputValue
    }
    interfaces {
      ...TypeRef
    }
    enumValues(includeDeprecated: true) {
      name
      description
      isDeprecated
      deprecationReason
    }
    possibleTypes {
      ...TypeRef
    }
  }
  fragment InputValue on __InputValue {
    name
    description
    type {
      ...TypeRef
    }
    defaultValue
  }
  fragment TypeRef on __Type {
    kind
    name
    ofType {
      kind
      name
      ofType {
        kind
        name
        ofType {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
                ofType {
                  kind
                  name
                }
              }
            }
          }
        }
      }
    }
  }
`;

const SENSITIVE_FIELDS = [
  'password', 'token', 'secret', 'apiKey', 'ssn', 'cpf', 'creditCard',
  'cvv', 'balance', 'address', 'phone', 'birthDate'
];

async function graphqlScan(config = {}, emit) {
  const results = [];
  const baseUrl = config.projectUrl;
  const anonKey = config.anonKey;
  const headers = supabaseHeaders(anonKey);

  const graphqlUrl = `${baseUrl}/graphql/v1`;

  const schema = {
    types: [],
    queries: [],
    mutations: [],
    subscriptions: [],
    totalTypes: 0,
    userTypes: []
  };

  emit({ type: 'log', level: 'info', message: '[GraphQL] Iniciando introspection completa...' });

  const introspectionRes = await safeFetch(graphqlUrl, {
    method: 'POST',
    headers: { ...headers, 'Content-Type': 'application/json' },
    body: JSON.stringify({ query: INTROSPECTION_QUERY }),
    timeout: 15000
  });

  if (introspectionRes.status === 0 || introspectionRes.status === 404) {
    results.push({
      check: 'GraphQL — Endpoint',
      status: 'PASS',
      severity: 'info',
      message: 'Endpoint GraphQL não encontrado.',
      details: { url: graphqlUrl, status: introspectionRes.status }
    });
    return { results, schema: null };
  }

  if (!introspectionRes.ok) {
    results.push({
      check: 'GraphQL — Endpoint',
      status: 'WARN',
      severity: 'medium',
      message: `GraphQL endpoint retornou status ${introspectionRes.status}`,
      details: { url: graphqlUrl }
    });
    return { results, schema: null };
  }

  const introspectionData = introspectionRes.json?.data?.__schema;

  if (!introspectionData) {
    results.push({
      check: 'GraphQL — Introspection',
      status: 'WARN',
      severity: 'medium',
      message: 'Introspection GraphQL não disponível.',
      details: { response: introspectionRes.json }
    });
    return { results, schema: null };
  }

  schema.types = introspectionData.types || [];
  schema.totalTypes = schema.types.length;

  const queryType = introspectionData.queryType?.name;
  const mutationType = introspectionData.mutationType?.name;
  const subscriptionType = introspectionData.subscriptionType?.name;

  if (queryType) {
    const queryTypeObj = schema.types.find(t => t.name === queryType);
    if (queryTypeObj?.fields) {
      schema.queries = queryTypeObj.fields.map(f => ({
        name: f.name,
        description: f.description,
        args: f.args?.map(a => a.name) || []
      }));
    }
  }

  if (mutationType) {
    const mutationTypeObj = schema.types.find(t => t.name === mutationType);
    if (mutationTypeObj?.fields) {
      schema.mutations = mutationTypeObj.fields.map(f => ({
        name: f.name,
        description: f.description,
        args: f.args?.map(a => a.name) || []
      }));
    }
  }

  if (subscriptionType) {
    const subTypeObj = schema.types.find(t => t.name === subscriptionType);
    if (subTypeObj?.fields) {
      schema.subscriptions = subTypeObj.fields.map(f => f.name);
    }
  }

  schema.userTypes = schema.types.filter(t =>
    !t.name.startsWith('__') &&
    !['Query', 'Mutation', 'Subscription', 'String', 'Int', 'Float', 'Boolean', 'ID'].includes(t.name) &&
    t.kind === 'OBJECT'
  );

  emit({ type: 'log', level: 'info', message: `[GraphQL] ${schema.userTypes.length} tipos de dados, ${schema.queries.length} queries, ${schema.mutations.length} mutations` });

  results.push({
    check: 'GraphQL — Schema Exposure',
    status: schema.userTypes.length > 0 ? 'FAIL' : 'PASS',
    severity: schema.userTypes.length > 10 ? 'critical' : 'high',
    message: `${schema.userTypes.length} tipo(s) de dados exposto(s) via GraphQL introspection.`,
    details: {
      url: graphqlUrl,
      totalTypes: schema.totalTypes,
      userTypes: schema.userTypes.length,
      queries: schema.queries.map(q => q.name),
      mutations: schema.mutations.map(m => m.name),
      recommendation: 'Desabilite introspection em produção: pg_graphql.hide_all_types = true'
    }
  });

  emit({ type: 'log', level: 'info', message: '[GraphQL] Testando acesso a dados sem autenticação...' });

  const noAuthHeaders = { 'Content-Type': 'application/json' };
  const noAuthIntrospection = await safeFetch(graphqlUrl, {
    method: 'POST',
    headers: noAuthHeaders,
    body: JSON.stringify({ query: INTROSPECTION_QUERY }),
    timeout: 10000
  });

  if (noAuthIntrospection.ok && noAuthIntrospection.json?.data?.__schema) {
    results.push({
      check: 'GraphQL — No Auth Introspection',
      status: 'FAIL',
      severity: 'critical',
      message: 'Introspection GraphQL funciona SEM autenticação!',
      details: { severity: 'critical', recommendation: 'URGENTE: Bloqueie acesso anónimo ao GraphQL' }
    });
  }

  // Test all queryable Collection fields — use catalog tables if available, else use schema types
  const catalogTables = (config?._catalog?.tables || []).map(t => t.name);
  const typesToTest = catalogTables.length > 0
    ? catalogTables.map(name => ({
        name: name.charAt(0).toUpperCase() + name.slice(1),
        collectionName: name + 'Collection',
        fields: null
      }))
    : schema.userTypes.map(t => ({
        name: t.name,
        collectionName: t.name.charAt(0).toLowerCase() + t.name.slice(1) + 'Collection',
        fields: t.fields
      }));

  const queryableCollections = [];
  const notQueryableCollections = [];

  emit({ type: 'log', level: 'info', message: `[GraphQL] Testando ${Math.min(typesToTest.length, 40)} collections...` });

  for (const typeInfo of typesToTest.slice(0, 40)) {
    const collectionName = typeInfo.collectionName;
    const dataQuery = { query: `{ ${collectionName}(first: 3) { edges { node { __typename } } } }` };

    const dataRes = await safeFetch(graphqlUrl, {
      method: 'POST',
      headers,
      body: JSON.stringify(dataQuery),
      timeout: 6000
    });

    const isCallable = dataRes.ok && dataRes.json?.data !== undefined && !dataRes.json?.errors?.some(e => e.message?.includes('Unknown'));
    const hasData = isCallable && (dataRes.json?.data?.[collectionName]?.edges?.length > 0);

    emit({ type: 'log', level: 'info', message: `[GraphQL PROBE] field=${collectionName} -> ${dataRes.status} callable=${isCallable ? 'yes' : 'no'} data=${hasData ? 'yes' : 'no'}` });

    if (isCallable) {
      queryableCollections.push({ name: typeInfo.name, collection: collectionName, hasData });
    } else {
      notQueryableCollections.push(collectionName);
    }

    if (hasData) {
      results.push({
        check: 'GraphQL — Data Access',
        status: 'FAIL',
        severity: 'high',
        message: `Dados acessíveis via GraphQL: ${typeInfo.name} (${dataRes.json?.data?.[collectionName]?.edges?.length} registros)`,
        details: {
          type: typeInfo.name,
          query: collectionName,
          hasData: true,
          sampleCount: dataRes.json?.data?.[collectionName]?.edges?.length
        }
      });
    }
  }

  if (queryableCollections.length > 0) {
    results.push({
      check: 'GraphQL — Campos Queryable',
      status: 'WARN',
      severity: 'high',
      message: `${queryableCollections.length} collection(s) queryable para GUEST via GraphQL.`,
      details: {
        queryable: queryableCollections.map(c => ({ name: c.name, hasData: c.hasData })),
        withData: queryableCollections.filter(c => c.hasData).map(c => c.name),
        recommendation: 'Verifique RLS em todas as tabelas expostas via GraphQL. Considere desabilitar introspection em produção.'
      }
    });
  }

  if (schema.mutations.length > 0) {
    results.push({
      check: 'GraphQL — Mutations Available',
      status: 'WARN',
      severity: 'medium',
      message: `${schema.mutations.length} mutation(s) disponível(s). Verifique permissões.`,
      details: {
        mutations: schema.mutations.map(m => m.name).slice(0, 20),
        recommendation: 'Teste mutations com anon key para verificar permissões'
      }
    });
  }

  return { results, schema };
}

module.exports = { graphqlScan };
