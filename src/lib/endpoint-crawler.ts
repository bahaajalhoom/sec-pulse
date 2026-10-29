// ============================================================================
// AUTOMATED ENDPOINT DISCOVERY & API SPIDER ENGINE (DEEP BUNDLE SCAN)
// ============================================================================
import { DiscoveredEndpoint, EndpointDiscoveryResult } from '@/types/security';

const BROWSER_USER_AGENT =
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36';

function cleanUrl(url: string): string {
  let trimmed = url.trim();
  if (!/^https?:\/\//i.test(trimmed)) {
    trimmed = `https://${trimmed}`;
  }
  return trimmed.replace(/\/+$/, '');
}

export function buildResolvedUrl(baseUrl: string, targetPath: string): string {
  if (/^https?:\/\//i.test(targetPath)) return targetPath;
  const cleanBase = baseUrl.trim().replace(/\/+$/, '');
  const cleanPath = targetPath.startsWith('/') ? targetPath : `/${targetPath}`;
  return `${cleanBase}${cleanPath}`;
}

/**
 * Validates whether an API base responds as an active server (either at root or at /health)
 */
async function verifyCandidateApiBase(candidateUrl: string): Promise<boolean> {
  const checkPaths = ['', '/health', '/api', '/api/health'];

  for (const sub of checkPaths) {
    try {
      const pingUrl = sub ? buildResolvedUrl(candidateUrl, sub) : candidateUrl;
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 4000);

      const res = await fetch(pingUrl, {
        method: 'GET',
        headers: {
          'Accept': 'application/json, text/plain, */*',
          'User-Agent': BROWSER_USER_AGENT,
        },
        signal: controller.signal,
        cache: 'no-store',
      });
      clearTimeout(timeout);

      const contentType = res.headers.get('content-type') || '';
      const hasApiHeader =
        res.headers.has('x-security-policy') ||
        res.headers.has('x-backend-engine') ||
        res.headers.has('x-request-id') ||
        res.headers.has('access-control-allow-credentials');

      // If it returned JSON or an API header, it is definitely a live API server!
      if (contentType.includes('application/json') || hasApiHeader) {
        return true;
      }

      // If status is 200, 401, 403, or 405 (and not an HTML 404 page)
      if (res.status === 200 || res.status === 401 || res.status === 403 || res.status === 405) {
        if (!contentType.includes('text/html')) {
          return true;
        }
      }
    } catch {
      // Continue to next checkPath
    }
  }

  return false;
}

/**
 * Crawls target web application: scans ALL script chunks using browser headers
 * to avoid bot blocking and extract real API base URLs and actual API endpoints dynamically.
 */
export async function crawlAndDiscoverEndpoints(
  targetUrl: string
): Promise<EndpointDiscoveryResult> {
  const normalizedTarget = cleanUrl(targetUrl);
  const endpoints: DiscoveredEndpoint[] = [];
  const candidateApiBases = new Set<string>();
  const discoveredPaths = new Set<string>();
  const discoveredSupabaseTables = new Set<string>();
  const detectedSupabaseBases = new Set<string>();

  let crawledScriptsCount = 0;

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 8000);

    // 1. Fetch main page HTML using standard browser User-Agent
    const pageResponse = await fetch(normalizedTarget, {
      signal: controller.signal,
      headers: {
        'User-Agent': BROWSER_USER_AGENT,
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        'Accept-Language': 'ar,en-US;q=0.9,en;q=0.8',
      },
      cache: 'no-store',
    });
    clearTimeout(timeoutId);

    const html = await pageResponse.text();

    // 2. Extract ALL script tags
    const scriptSrcMatches = [
      ...html.matchAll(/src=["']([^"']+\.js[^"']*)["']/gi),
    ].map((m) => m[1]);

    // 3. Scan HTML body directly for API URLs
    const htmlApiMatches = [
      ...html.matchAll(/https?:\/\/[a-zA-Z0-9_\-\.]+(?::[0-9]+)?\/api[a-zA-Z0-9_\-\/]*/gi),
    ].map((m) => m[0]);

    htmlApiMatches.forEach((api) => {
      const lower = api.toLowerCase();
      if (
        !lower.includes('google') &&
        !lower.includes('cloudflare') &&
        !lower.includes('gstatic') &&
        !lower.includes('facebook') &&
        !lower.includes('analytics')
      ) {
        candidateApiBases.add(cleanUrl(api));
      }
    });

    // 4. Download and inspect all JavaScript chunks (up to 30 chunks in parallel)
    const scriptsToScan = scriptSrcMatches.slice(0, 30);
    crawledScriptsCount = scriptsToScan.length;

    await Promise.all(
      scriptsToScan.map(async (src) => {
        try {
          const resolvedScriptUrl = buildResolvedUrl(normalizedTarget, src);
          const scriptCtrl = new AbortController();
          const scriptTimeout = setTimeout(() => scriptCtrl.abort(), 6000);

          const scriptRes = await fetch(resolvedScriptUrl, {
            signal: scriptCtrl.signal,
            headers: { 'User-Agent': BROWSER_USER_AGENT },
            cache: 'no-store',
          });
          clearTimeout(scriptTimeout);

          if (!scriptRes.ok) return;
          const jsContent = await scriptRes.text();

          // Extract absolute API URLs (e.g. https://taskflow-taqat.apps.taqat.academy/api)
          const apis = [
            ...jsContent.matchAll(
              /https?:\/\/[a-zA-Z0-9_\-\.]+(?::[0-9]+)?\/api[a-zA-Z0-9_\-\/]*/gi
            ),
          ].map((m) => m[0]);

          apis.forEach((a) => {
            const lower = a.toLowerCase();
            if (
              !lower.includes('google') &&
              !lower.includes('cloudflare') &&
              !lower.includes('localhost') &&
              !lower.includes('analytics') &&
              !lower.includes('gstatic')
            ) {
              candidateApiBases.add(cleanUrl(a));
            }
          });

          // Extract Supabase BaaS project URLs
          const supaMatches = [
            ...jsContent.matchAll(/https:\/\/[a-z0-9_\-]+\.supabase\.co/gi),
          ].map((m) => m[0]);
          supaMatches.forEach((s) => detectedSupabaseBases.add(cleanUrl(s)));

          // Extract Supabase Database Tables (.from("table_name"))
          const tableMatches = [
            ...jsContent.matchAll(/\.from\(["']([a-zA-Z0-9_\-]+)["']\)/gi),
          ].map((m) => m[1]);
          tableMatches.forEach((t) => {
            if (t.length > 2 && !t.includes('/') && !t.includes('.')) {
              discoveredSupabaseTables.add(t);
            }
          });

          // Extract rich application routes (including Next.js App Router dynamic routes & feature pages)
          const routes = [
            ...jsContent.matchAll(
              /["'`](\/(?:api|auth|courses|books|library|enrollments|attendance|exams|dashboard|admin|projects|tasks|metrics|health|settings|users|students|teachers|messages|chat|notifications|upload|checkout|profile|login|register)[a-zA-Z0-9_\-\/]*)/gi
            ),
          ].map((m) => m[1]);

          routes.forEach((r) => {
            if (
              !r.endsWith('.js') &&
              !r.endsWith('.css') &&
              !r.endsWith('.png') &&
              !r.endsWith('.jpg') &&
              !r.endsWith('.svg') &&
              !r.endsWith('.webp') &&
              !r.includes('static') &&
              r !== '/'
            ) {
              discoveredPaths.add(r.replace(/\/+$/, ''));
            }
          });
        } catch {
          // Ignore
        }
      })
    );

    // 5. Determine Architecture & API Base
    let apiArchitecture: 'external_backend' | 'co_located_serverless' | 'supabase_baas' | 'frontend_only' = 'frontend_only';
    let confirmedApiBaseUrl: string | undefined = undefined;

    // A. Priority 1: Supabase Backend-as-a-Service (BaaS)
    if (detectedSupabaseBases.size > 0 && discoveredSupabaseTables.size > 0) {
      confirmedApiBaseUrl = Array.from(detectedSupabaseBases)[0];
      apiArchitecture = 'supabase_baas';
    }

    // B. Priority 2: External REST API candidate
    if (!confirmedApiBaseUrl) {
      for (const cand of Array.from(candidateApiBases)) {
        const isAlive = await verifyCandidateApiBase(cand);
        if (isAlive) {
          confirmedApiBaseUrl = cand;
          apiArchitecture = 'external_backend';
          break;
        }
      }
    }

    if (!confirmedApiBaseUrl && candidateApiBases.size > 0) {
      confirmedApiBaseUrl = Array.from(candidateApiBases)[0];
      apiArchitecture = 'external_backend';
    }

    // C. Priority 3: Co-located targetUrl/api alive
    if (!confirmedApiBaseUrl) {
      const targetApiCandidate = `${normalizedTarget}/api`;
      const isTargetApiAlive = await verifyCandidateApiBase(targetApiCandidate);
      if (isTargetApiAlive) {
        confirmedApiBaseUrl = targetApiCandidate;
        apiArchitecture = 'co_located_serverless';
      }
    }

    // D. Priority 4: Modern Next.js Serverless Routes on same host
    const hasInternalApiRoutes = Array.from(discoveredPaths).some(
      (p) => p.startsWith('/api') || p.startsWith('/auth') || p.startsWith('/v1')
    );

    if (!confirmedApiBaseUrl && hasInternalApiRoutes) {
      confirmedApiBaseUrl = normalizedTarget;
      apiArchitecture = 'co_located_serverless';
    } else if (!confirmedApiBaseUrl) {
      apiArchitecture = 'frontend_only';
    }

    // 6. Assemble discovered endpoints
    // A. Assemble App & API routes
    discoveredPaths.forEach((path) => {
      let method: 'GET' | 'POST' = 'GET';
      if (
        path.includes('login') ||
        path.includes('register') ||
        path.includes('create') ||
        path.includes('reset') ||
        path.includes('change-password') ||
        path.includes('upload')
      ) {
        method = 'POST';
      }

      endpoints.push({
        id: `ep-${Math.random().toString(36).substring(2, 8)}`,
        path,
        method,
        source: 'js_bundle',
        tested: false,
        selected: true,
        description: `Discovered from frontend JavaScript code`,
      });
    });

    // B. Assemble Supabase BaaS Database Endpoints
    if (apiArchitecture === 'supabase_baas' || discoveredSupabaseTables.size > 0) {
      discoveredSupabaseTables.forEach((table) => {
        endpoints.push({
          id: `supa-${table}-${Math.random().toString(36).substring(2, 6)}`,
          path: `/rest/v1/${table}`,
          method: 'GET',
          source: 'supabase_table',
          tested: false,
          selected: true,
          description: `Supabase Table: ${table} (Row-Level Security & Public Access Audit)`,
        });
      });
    }

    return {
      targetUrl: normalizedTarget,
      detectedApiBaseUrl: confirmedApiBaseUrl,
      apiArchitecture,
      endpoints,
      crawledScriptsCount,
      status: 'success',
    };
  } catch (error) {
    return {
      targetUrl: normalizedTarget,
      detectedApiBaseUrl: undefined,
      apiArchitecture: 'frontend_only',
      endpoints: [],
      crawledScriptsCount: 0,
      status: 'failed',
      error: error instanceof Error ? error.message : 'Crawling interrupted',
    };
  }
}
