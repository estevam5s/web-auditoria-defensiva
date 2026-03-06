/*  CHECK: Storage Buckets Exposure
    Tests if storage buckets are publicly accessible */

const { safeFetch, supabaseHeaders } = require('../helpers/http');

async function checkStorageExposure(config) {
  const results = [];
  const baseUrl = config.projectUrl;
  const headers = supabaseHeaders(config.anonKey);

  // 1. List all buckets
  const bucketsUrl = `${baseUrl}/storage/v1/bucket`;
  const bucketsRes = await safeFetch(bucketsUrl, { headers });

  if (bucketsRes.status === 0 || bucketsRes.status === 404) {
    results.push({
      check: 'Storage — Endpoint',
      status: 'INFO',
      severity: 'info',
      message: 'Endpoint de Storage não acessível.',
      details: { url: bucketsUrl, status: bucketsRes.status }
    });
    return results;
  }

  if (bucketsRes.ok && Array.isArray(bucketsRes.json)) {
    const buckets = bucketsRes.json;
    
    if (buckets.length === 0) {
      results.push({
        check: 'Storage — Buckets',
        status: 'PASS',
        severity: 'info',
        message: 'Nenhum bucket de storage encontrado.',
        details: null
      });
      return results;
    }

    const publicBuckets = buckets.filter(b => b.public);
    const privateBuckets = buckets.filter(b => !b.public);

    results.push({
      check: 'Storage — Bucket Listing',
      status: 'WARN',
      severity: 'medium',
      message: `${buckets.length} bucket(s) listável(is). ${publicBuckets.length} público(s), ${privateBuckets.length} privado(s).`,
      details: {
        buckets: buckets.map(b => ({
          name: b.name,
          public: b.public,
          createdAt: b.created_at,
          fileSizeLimit: b.file_size_limit,
          allowedMimeTypes: b.allowed_mime_types
        }))
      }
    });

    // 2. Try to list files in each public bucket
    for (const bucket of publicBuckets) {
      const listUrl = `${baseUrl}/storage/v1/object/list/${bucket.name}`;
      const listRes = await safeFetch(listUrl, {
        method: 'POST',
        headers,
        body: JSON.stringify({ prefix: '', limit: 20, offset: 0 })
      });

      if (listRes.ok && Array.isArray(listRes.json) && listRes.json.length > 0) {
        const files = listRes.json;
        const sensitiveExtensions = ['.env', '.key', '.pem', '.sql', '.csv', '.json', '.bak', '.log'];
        const sensitiveFiles = files.filter(f => 
          sensitiveExtensions.some(ext => f.name?.toLowerCase().endsWith(ext))
        );

        results.push({
          check: `Storage — Bucket "${bucket.name}" Files`,
          status: 'FAIL',
          severity: sensitiveFiles.length > 0 ? 'critical' : 'high',
          message: `Bucket público "${bucket.name}" contém ${files.length} arquivo(s) listáveis.${sensitiveFiles.length > 0 ? ` ${sensitiveFiles.length} arquivo(s) sensível(is) detectado(s)!` : ''}`,
          details: {
            bucket: bucket.name,
            fileCount: files.length,
            files: files.slice(0, 10).map(f => ({
              name: f.name,
              size: f.metadata?.size,
              mimetype: f.metadata?.mimetype,
              lastModified: f.updated_at
            })),
            sensitiveFiles: sensitiveFiles.map(f => f.name),
            recommendation: 'Revise a política de acesso do bucket. Evite armazenar dados sensíveis em buckets públicos.'
          }
        });
      }
    }

    // 3. Check if bucket listing works without auth
    const noAuthRes = await safeFetch(bucketsUrl, {
      headers: { 'Content-Type': 'application/json' }
    });

    if (noAuthRes.ok && Array.isArray(noAuthRes.json)) {
      results.push({
        check: 'Storage — No Auth Listing',
        status: 'FAIL',
        severity: 'high',
        message: 'Buckets podem ser listados sem autenticação.',
        details: { bucketCount: noAuthRes.json.length }
      });
    }

  } else if (bucketsRes.status === 401 || bucketsRes.status === 403) {
    results.push({
      check: 'Storage — Bucket Listing',
      status: 'PASS',
      severity: 'info',
      message: 'Listagem de buckets requer autenticação. ✓',
      details: { status: bucketsRes.status }
    });
  }

  // 4. Check common public file paths
  const commonPaths = [
    'avatars', 'uploads', 'images', 'documents', 'public', 'files',
    'backups', 'exports', 'media', 'assets'
  ];

  for (const path of commonPaths) {
    const publicUrl = `${baseUrl}/storage/v1/object/public/${path}/`;
    const res = await safeFetch(publicUrl, { timeout: 5000 });
    
    if (res.ok || (res.status >= 200 && res.status < 400)) {
      results.push({
        check: `Storage — Public Path "${path}"`,
        status: 'WARN',
        severity: 'medium',
        message: `Caminho público de storage acessível: /storage/v1/object/public/${path}/`,
        details: { url: publicUrl, status: res.status }
      });
    }
  }

  return results;
}

module.exports = { checkStorageExposure };
