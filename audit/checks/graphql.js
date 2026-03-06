/*  CHECK: GraphQL Exposure
    Tests if pg_graphql is exposed and leaks schema */

const { safeFetch, supabaseHeaders } = require('../helpers/http');

async function checkGraphQLExposure(config) {
  const results = [];
  const baseUrl = config.projectUrl;
  const headers = supabaseHeaders(config.anonKey);

  // 1. Check GraphQL endpoint
  const graphqlUrl = `${baseUrl}/graphql/v1`;
  
  // Introspection query — reveals entire schema
  const introspectionQuery = {
    query: `{
      __schema {
        types {
          name
          kind
          fields {
            name
            type { name kind }
          }
        }
        queryType { name }
        mutationType { name }
      }
    }`
  };

  const res = await safeFetch(graphqlUrl, {
    method: 'POST',
    headers: { ...headers, 'Content-Type': 'application/json' },
    body: JSON.stringify(introspectionQuery)
  });

  if (res.status === 0 || res.status === 404) {
    results.push({
      check: 'GraphQL — Endpoint',
      status: 'PASS',
      severity: 'info',
      message: 'Endpoint GraphQL não encontrado ou desabilitado.',
      details: { url: graphqlUrl, status: res.status }
    });
    return results;
  }

  if (res.ok && res.json?.data?.__schema) {
    const schema = res.json.data.__schema;
    const userTypes = schema.types.filter(t => 
      !t.name.startsWith('__') && 
      t.kind === 'OBJECT' &&
      !['Query', 'Mutation', 'Subscription', 'PageInfo'].includes(t.name)
    );

    results.push({
      check: 'GraphQL — Introspection',
      status: 'FAIL',
      severity: 'critical',
      message: `Introspection GraphQL habilitada! ${userTypes.length} tipos de dados expostos.`,
      details: {
        url: graphqlUrl,
        typesExposed: userTypes.map(t => ({
          name: t.name,
          fields: t.fields?.map(f => f.name) || []
        })),
        recommendation: 'Desabilite introspection em produção via Supabase Dashboard ou pg_graphql config.'
      }
    });

    // 2. Try to query data through GraphQL
    if (userTypes.length > 0) {
      const firstType = userTypes[0];
      const collectionName = firstType.name.charAt(0).toLowerCase() + firstType.name.slice(1) + 'Collection';
      
      const dataQuery = {
        query: `{ ${collectionName}(first: 1) { edges { node { __typename } } } }`
      };

      const dataRes = await safeFetch(graphqlUrl, {
        method: 'POST',
        headers: { ...headers, 'Content-Type': 'application/json' },
        body: JSON.stringify(dataQuery)
      });

      if (dataRes.ok && dataRes.json?.data) {
        results.push({
          check: 'GraphQL — Data Access',
          status: 'FAIL',
          severity: 'high',
          message: 'Dados podem ser consultados via GraphQL sem autenticação adicional.',
          details: {
            query: dataQuery.query,
            hasResults: true
          }
        });
      }
    }
  } else if (res.ok) {
    results.push({
      check: 'GraphQL — Endpoint Active',
      status: 'WARN',
      severity: 'medium',
      message: 'Endpoint GraphQL está ativo mas introspection pode estar desabilitada.',
      details: { url: graphqlUrl, status: res.status }
    });
  }

  // 3. Check GraphQL without auth
  const noAuthRes = await safeFetch(graphqlUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(introspectionQuery)
  });

  if (noAuthRes.ok && noAuthRes.json?.data?.__schema) {
    results.push({
      check: 'GraphQL — No Auth Introspection',
      status: 'FAIL',
      severity: 'critical',
      message: 'Introspection GraphQL funciona sem autenticação!',
      details: { status: noAuthRes.status }
    });
  }

  return results;
}

module.exports = { checkGraphQLExposure };
