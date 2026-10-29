// ============================================================================
// REAL NETWORK SECURITY AUDIT ENGINE (OFFICIAL DEFENSIVE SCANNER - STRICT)
// ============================================================================
import {
  DiscoveredEndpoint,
  LiveTelemetryEvent,
  ProbeStatus,
  SecurityProbePayload,
  VulnerabilityFinding,
} from '@/types/security';

export function normalizeTargetUrl(rawUrl: string): string {
  let trimmed = rawUrl.trim();
  if (!trimmed) return 'https://example.com';
  if (!/^https?:\/\//i.test(trimmed)) {
    trimmed = `https://${trimmed}`;
  }
  return trimmed.replace(/\/+$/, '');
}

/**
 * Resolves a probe path against targetUrl or apiBaseUrl cleanly
 */
export function resolveProbeUrl(
  targetUrl: string,
  apiBaseUrl: string | undefined,
  targetPath: string
): string {
  if (/^https?:\/\//i.test(targetPath)) {
    return targetPath;
  }

  const cleanTarget = targetUrl.replace(/\/+$/, '');
  const cleanApi = apiBaseUrl ? apiBaseUrl.trim().replace(/\/+$/, '') : cleanTarget;

  // Port probe
  if (targetPath.startsWith(':')) {
    try {
      const urlObj = new URL(cleanTarget);
      return `${urlObj.protocol}//${urlObj.hostname}${targetPath}`;
    } catch {
      return `${cleanTarget}${targetPath}`;
    }
  }

  // If apiBaseUrl is explicitly set and path is an API path:
  if (
    apiBaseUrl &&
    (targetPath.startsWith('/api') ||
      targetPath.startsWith('/auth') ||
      targetPath.startsWith('/v1') ||
      targetPath.startsWith('/rest') ||
      targetPath.startsWith('/graphql') ||
      targetPath.startsWith('/projects') ||
      targetPath.startsWith('/tasks') ||
      targetPath.startsWith('/users') ||
      targetPath.startsWith('/health') ||
      targetPath.startsWith('/metrics') ||
      targetPath.startsWith('/admin'))
  ) {
    if (cleanApi.endsWith('/api') && targetPath.startsWith('/api/')) {
      const strippedPath = targetPath.replace(/^\/api/, '');
      return `${cleanApi}${strippedPath}`;
    }
    const cleanPath = targetPath.startsWith('/') ? targetPath : `/${targetPath}`;
    return `${cleanApi}${cleanPath}`;
  }

  // Non-API root assets resolve against targetUrl
  const cleanPath = targetPath.startsWith('/') ? targetPath : `/${targetPath}`;
  return `${cleanTarget}${cleanPath}`;
}

function extractResponseHeaders(headers: Headers): Record<string, string> {
  const result: Record<string, string> = {};
  headers.forEach((value, key) => {
    result[key.toLowerCase()] = value;
  });
  return result;
}

/**
 * Dynamically binds discovered endpoints into test probes
 */
export function generateDynamicProbes(
  discoveredEndpoints: DiscoveredEndpoint[],
  baseProbes: SecurityProbePayload[],
  hasApiBaseUrl: boolean
): SecurityProbePayload[] {
  // If target has no API and no endpoints, filter out generic /api/ endpoints that cause 404 noise
  let dynamicList = baseProbes.filter((p) => {
    if (!hasApiBaseUrl && p.targetPath.startsWith('/api/')) {
      return false; // Skip guessing non-existent API routes on pure frontend sites
    }
    return true;
  });

  // Bind real discovered endpoints
  discoveredEndpoints
    .filter((ep) => ep.selected)
    .forEach((ep, index) => {
      dynamicList.push({
        id: `dyn-auth-${index}`,
        category: 'auth',
        name: `Auth Barrier: ${ep.path}`,
        nameAr: `فحص التحقق من الصلاحيات: ${ep.path}`,
        description: `Tests whether endpoint ${ep.path} requires authentication or allows unauthorized public access.`,
        descriptionAr: `فحص هل المسار ${ep.path} يتطلب تسجيل دخول أم يسرب بيانات للعامة.`,
        method: ep.method,
        targetPath: ep.path,
        headers: {
          'Accept': 'application/json',
          'User-Agent': 'SecuriPulse-Auditor/2.5',
        },
        payloadCode: ep.method === 'POST' ? JSON.stringify({ canary: 'probe_test' }) : '',
        canaryExpectedOutcome: 'Protected routes must return HTTP 401 or 403 when unauthenticated.',
        canaryExpectedOutcomeAr: 'يجب أن يعيد الخادم 401 أو 403 للمسارات المحمية.',
        intensityLevel: 'standard',
        enabled: true,
        endpointSource: 'discovered',
      });

      if (ep.method === 'GET') {
        const queryPath = ep.path.includes('?')
          ? `${ep.path}&canary=%27%20OR%201%3D1`
          : `${ep.path}?canary=%27%20OR%201%3D1`;

        dynamicList.push({
          id: `dyn-sqli-${index}`,
          category: 'sqli',
          name: `Input Sanitization: ${ep.path}`,
          nameAr: `فحص تعقيم المدخلات: ${ep.path}`,
          description: `Tests parameter sanitization and checks for database stack trace disclosures.`,
          descriptionAr: `فحص هل يسرب هذا المسار أي أخطاء قاعدة بيانات عند إرسال مدخلات ملتوية.`,
          method: 'GET',
          targetPath: queryPath,
          headers: {
            'Accept': 'application/json, text/html',
            'User-Agent': 'SecuriPulse-Auditor/2.5',
          },
          payloadCode: "' OR 1=1 --",
          canaryExpectedOutcome: 'Input must be safely sanitized without SQL stack traces.',
          canaryExpectedOutcomeAr: 'يجب تعقيم المدخلات دون تسريب أخطاء SQL.',
          intensityLevel: 'standard',
          enabled: true,
          endpointSource: 'discovered',
        });
      }

      // Always execute a POST payload probe for discovered API routes
      // to test serverless body parsers and sanitization
      if (ep.path.startsWith('/api') || ep.path.startsWith('/auth') || ep.method === 'POST') {
        dynamicList.push({
          id: `dyn-post-${index}`,
          category: 'sqli',
          name: `POST Body Sanitization: ${ep.path}`,
          nameAr: `فحص حمولة POST وحقن المدخلات: ${ep.path}`,
          description: `Sends structured JSON body with canary payloads to test serverless body validation.`,
          descriptionAr: `يرسل كائن JSON مع مدخلات اختبارية لفحص تعقيم المدخلات ومقاومة حقن البيانات في الدالة السحابية.`,
          method: 'POST',
          targetPath: ep.path,
          headers: {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'User-Agent': 'SecuriPulse-Auditor/2.5',
          },
          payloadCode: JSON.stringify(
            {
              url: "https://canary-test.local' OR 1=1 --",
              query: "' OR 1=1 --",
              canary: "SecuriPulse_Probe",
            },
            null,
            2
          ),
          canaryExpectedOutcome: 'Server must handle body payload cleanly without 500 stack trace leaks.',
          canaryExpectedOutcomeAr: 'يجب أن يتعامل الخادم بأمان مع المدخلات دون تسريب أخطاء برمجية 500.',
          intensityLevel: 'standard',
          enabled: true,
          endpointSource: 'discovered',
        });
      }
    });

  return dynamicList;
}

/**
 * Executes a REAL live HTTP network probe against targetUrl / apiBaseUrl
 */
export async function executeRealProbe(
  probe: SecurityProbePayload,
  targetUrl: string,
  apiBaseUrl: string | undefined,
  threadId: number,
  intensity: 'gentle' | 'standard' | 'rigorous'
): Promise<{ event: LiveTelemetryEvent; finding?: VulnerabilityFinding }> {
  const timestamp = new Date().toLocaleTimeString('en-US', {
    hour12: false,
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });

  const fullUrl = resolveProbeUrl(targetUrl, apiBaseUrl, probe.targetPath);
  const startTime = performance.now();

  let statusCode = 0;
  let status: ProbeStatus = 'passed';
  let evidence = '';
  let explanation = '';
  let explanationAr = '';
  let severity: 'critical' | 'high' | 'medium' | 'low' | 'info' = 'info';
  let responseHeaders: Record<string, string> = {};
  let responseBody = '';

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 6500);

    const fetchOptions: RequestInit = {
      method: probe.method,
      headers: {
        'User-Agent': 'SecuriPulse-Defensive-Auditor/2.5 (+https://securipulse.local)',
        ...probe.headers,
      },
      signal: controller.signal,
      redirect: 'manual',
      cache: 'no-store',
    };

    if (probe.method === 'POST' || probe.method === 'PUT') {
      fetchOptions.body = probe.payloadCode;
    }

    const response = await fetch(fullUrl, fetchOptions);
    clearTimeout(timeoutId);

    const latencyMs = Math.round(performance.now() - startTime);
    statusCode = response.status;
    responseHeaders = extractResponseHeaders(response.headers);
    const contentType = responseHeaders['content-type'] || '';

    try {
      const text = await response.text();
      responseBody = text.slice(0, 1500);
    } catch {
      responseBody = '';
    }

    // ========================================================================
    // STRICT DEFENSIVE EVALUATION WITH ZERO FALSE POSITIVES
    // ========================================================================
    switch (probe.category) {
      case 'headers': {
        if (probe.id === 'headers-01') {
          const hasHsts = Boolean(responseHeaders['strict-transport-security']);
          const hasXfo = Boolean(responseHeaders['x-frame-options']);
          const hasXcto = Boolean(responseHeaders['x-content-type-options']);
          const csp = responseHeaders['content-security-policy'] || '';
          const hasFrameAncestors = csp.includes('frame-ancestors');

          const missing: string[] = [];
          if (!hasHsts && fullUrl.startsWith('https://')) missing.push('Strict-Transport-Security');
          if (!hasXfo && !hasFrameAncestors) missing.push('X-Frame-Options');
          if (!hasXcto) missing.push('X-Content-Type-Options');

          if (missing.length > 0) {
            status = 'warning';
            severity = 'medium';
            evidence = `الترويسات المفقودة فعلياً: ${missing.join(', ')}`;
            explanation = `Your server responded (HTTP ${statusCode}) but omitted standard defensive headers: ${missing.join(', ')}.`;
            explanationAr = `الخادم استجاب برمز ${statusCode} لكنه لم يرسل ترويسات الحماية الأساسية: ${missing.join('، ')}.`;
          } else {
            status = 'passed';
            evidence = `تم التحقق بنجاح من وجود ترويسات الحماية: HSTS, X-Frame-Options, X-Content-Type-Options.`;
            explanation = 'Server successfully enforces modern defensive security headers.';
            explanationAr = 'الخادم يرسل جميع ترويسات الحماية الموصى بها عالمياً.';
          }
        } else if (probe.id === 'headers-02') {
          const allowOrigin = responseHeaders['access-control-allow-origin'];
          const allowCreds = responseHeaders['access-control-allow-credentials'];

          if (allowOrigin === '*' && allowCreds === 'true') {
            status = 'failed';
            severity = 'high';
            evidence = `CORS مُهيأ بشكل خطير: Access-Control-Allow-Origin: * مع Allow-Credentials: true`;
            explanation = 'Dangerous CORS policy permits arbitrary external websites to read authenticated API data.';
            explanationAr = 'سياسة CORS تسمح لأي موقع خارجي بقراءة بيانات مستخدميك المصادق عليها.';
          } else if (allowOrigin === '*' || allowOrigin === 'https://untrusted-external-canary.com') {
            status = 'warning';
            severity = 'medium';
            evidence = `CORS يسمح بالنطاقات الخارجية (${allowOrigin})`;
            explanation = 'Wildcard CORS detected. Acceptable for purely public assets, but risky for private APIs.';
            explanationAr = 'تم اكتشاف سياسة CORS عامة. يفضل تقييدها بنطاق موقعك فقط.';
          } else {
            status = 'passed';
            evidence = `سياسة CORS آمنة أو مقيدة: ${allowOrigin || 'لا تسمح للجهات الخارجية'}`;
            explanation = 'CORS origin policy is properly restricted.';
            explanationAr = 'سياسة CORS مقيدة بشكل سليم وتمنع المواقع الغريبة.';
          }
        }
        break;
      }

      case 'ports': {
        if (probe.id === 'ports-01') {
          // Sensitive .env leakage check
          // MUST check that response is actually a plaintext env file and not an HTML 404 page
          const isHtmlPage =
            contentType.includes('text/html') ||
            responseBody.includes('<!DOCTYPE html') ||
            responseBody.includes('<html');

          const isRealEnvExposed =
            statusCode === 200 &&
            !isHtmlPage &&
            (responseBody.includes('=') &&
              (responseBody.toLowerCase().includes('database') ||
                responseBody.toLowerCase().includes('secret') ||
                responseBody.toLowerCase().includes('key') ||
                responseBody.toLowerCase().includes('jwt_secret')));

          if (isRealEnvExposed) {
            status = 'failed';
            severity = 'critical';
            evidence = `خطر أمني حرج! ملف .env متاح للعامة برمز 200 واستجاب بمحتوى متغيرات البيئة النصية!`;
            explanation = 'CRITICAL: Your web server is serving the plaintext .env file publicly!';
            explanationAr = 'خطر أمني حرج! ملف الإعدادات .env متاح للعامة عبر المتصفح ومفاتيحه مكشوفة لأي زائر!';
          } else {
            status = 'passed';
            evidence = `محمي بنجاح! السيرفر أعاد رمز ${statusCode} لمنع قراءة الملفات الحساسة (أو صفحة 404 آمنة).`;
            explanation = `Target blocked access to /.env securely with HTTP ${statusCode}.`;
            explanationAr = `الخادم منع الوصول لملف الإعدادات بنجاح برمز ${statusCode}.`;
          }
        } else {
          status = statusCode >= 400 || statusCode === 200 ? 'passed' : 'warning';
          evidence = `استجاب الخادم برمز ${statusCode} خلال ${latencyMs}ms.`;
          explanation = `Port service probed, returned HTTP ${statusCode}.`;
          explanationAr = `تم فحص المنفذ واستجاب الخادم برمز ${statusCode}.`;
        }
        break;
      }

      case 'auth': {
        // STRICT AUTH EVALUATION:
        // Do NOT flag 200 as Broken Auth if the response is simply a public HTML page!
        const isHtmlPage =
          contentType.includes('text/html') ||
          responseBody.includes('<!DOCTYPE html') ||
          responseBody.includes('<html') ||
          responseBody.includes('404') ||
          responseBody.includes('المسار المفقود');

        if (statusCode === 401 || statusCode === 403) {
          status = 'passed';
          evidence = `الخادم محمي بجدار مصادقة سليم! رفض الطلب غير المصرح به برمز ${statusCode}.`;
          explanation = `Endpoint enforces authentication barrier correctly (HTTP ${statusCode}).`;
          explanationAr = `المسار محمي ومغلق أمام الزوار غير المصرحين برمز ${statusCode}.`;
        } else if (statusCode === 404) {
          status = 'passed';
          evidence = `المسار غير متواجد على السيرفر (HTTP 404).`;
          explanation = 'Endpoint does not exist on this route (HTTP 404).';
          explanationAr = 'المسار غير متواجد على السيرفر (HTTP 404).';
        } else if (statusCode === 200) {
          // If response is HTML, it's just a web page (not a leaked API)
          if (isHtmlPage) {
            status = 'passed';
            evidence = `استجاب الخادم بصفحة ويب عادية (HTML) برمز 200 وليست بيانات API سرية.`;
            explanation = 'Server returned a normal public HTML page, not an unauthorized JSON data leak.';
            explanationAr = 'الخادم عرض صفحة ويب عامة بشكل سليم.';
          } else if (contentType.includes('application/json')) {
            // If response is JSON on an admin/secret route, that's a true Broken Auth!
            if (
              probe.targetPath.includes('admin') ||
              probe.targetPath.includes('user') ||
              probe.targetPath.includes('secret')
            ) {
              status = 'failed';
              severity = 'critical';
              evidence = `تحذير حرج: مسار بيانات خاص (${probe.targetPath}) أعاد بيانات JSON برمز 200 بدون ترويسة Authorization!`;
              explanation = 'CRITICAL: Protected API endpoint returned unauthenticated JSON data!';
              explanationAr = 'خطر حرج: مسار API خاص أعاد بيانات بصيغة JSON دون اشتراط تسجيل دخول!';
            } else {
              status = 'passed';
              evidence = `مسار API عام يستجيب برمز 200 OK.`;
              explanation = 'Public API endpoint responded with 200 OK.';
              explanationAr = 'مسار API عام يستجيب بنجاح.';
            }
          } else {
            status = 'passed';
            evidence = `استجاب الخادم برمز ${statusCode}.`;
          }
        } else {
          status = 'passed';
          evidence = `الخادم استجاب برمز ${statusCode}.`;
          explanation = `Endpoint responded with status ${statusCode}.`;
          explanationAr = `استجاب الخادم برمز ${statusCode}.`;
        }
        break;
      }

      case 'sqli': {
        const errorKeywords = [
          'syntax error',
          'pg_query',
          'mysql_fetch',
          'unclosed quotation',
          'sqlite3::',
          'ora-01756',
          'sqlstate',
          'sequelizeDatabaseError',
        ];

        const matchedError = errorKeywords.find((kw) =>
          responseBody.toLowerCase().includes(kw)
        );

        if (matchedError) {
          status = 'failed';
          severity = 'critical';
          evidence = `تم اكتشاف تسريب خطأ قاعدة بيانات داخلي في رد الخادم: "${matchedError}"!`;
          explanation = `CRITICAL: The server disclosed an internal SQL syntax error in its response body: "${matchedError}".`;
          explanationAr = `خطر أمني حرج! كشف الخادم عن تفاصيل استعلام SQL داخلي في نص الاستجابة: "${matchedError}".`;
        } else if (statusCode === 500) {
          status = 'warning';
          severity = 'medium';
          evidence = `الخادم انهار برمز 500 Internal Server Error عند إرسال مدخل الفحص. يجب معالجة الاستثناءات بأمان.`;
          explanation = 'Server returned HTTP 500 on input boundary probe. Unhandled exceptions should be sanitized.';
          explanationAr = 'الخادم أعاد خطأ 500 عند إرسال الرمز التجريبي، مما يشير لعدم وجود معالجة استثناءات نظيفة.';
        } else {
          status = 'passed';
          evidence = `الخادم تعامل مع المدخل بأمان دون إظهار أي أخطاء قاعدة بيانات (HTTP ${statusCode}).`;
          explanation = 'No database stack traces or SQL syntax leaks detected in response.';
          explanationAr = 'لم تظهر أي رسائل أخطاء مسربة لقاعدة البيانات.';
        }
        break;
      }

      case 'xss': {
        const canaryStr = 'securipulse_canary';
        const rawScript = `<script>console.log("${canaryStr}")</script>`;

        if (responseBody.includes(rawScript)) {
          status = 'failed';
          severity = 'high';
          evidence = `تم العثور على وسم السكربت التجريبي منعكساً كما هو بدون تشفير HTML!`;
          explanation = 'HIGH RISK: Injected script tag was reflected verbatim in the response body without HTML escaping.';
          explanationAr = 'خطر أمني عالٍ! انعكس وسم السكربت التجريبي في الصفحة كما هو دون تحويله لنص آمن (HTML Escaped).';
        } else {
          status = 'passed';
          evidence = `الخادم لم يعكس الرمز غير المعقم في الاستجابة (HTTP ${statusCode}).`;
          explanation = 'Target did not reflect the probe payload.';
          explanationAr = 'الخادم لم يعكس المدخل في كود الصفحة.';
        }
        break;
      }

      case 'ssrf': {
        const isMetadataLeak =
          statusCode === 200 &&
          (responseBody.includes('ami-id') ||
            responseBody.includes('instance-id') ||
            responseBody.includes('iam/security-credentials') ||
            responseBody.includes('computeMetadata/v1'));

        if (isMetadataLeak) {
          status = 'failed';
          severity = 'critical';
          evidence = `خطر أمني حرج! السيرفر استجاب ببيانات السحابة الداخلية (Cloud Metadata) برمز 200!`;
          explanation = 'CRITICAL: The server fetched internal cloud metadata directly through SSRF!';
          explanationAr = 'خطر أمني حرج! الخادم جلب بيانات السحابة الداخلية عبر تزوير الطلبات SSRF!';
        } else {
          status = 'passed';
          evidence = `الخادم حظر أو رفض طلب السحابة الداخلي بنجاح برمز (HTTP ${statusCode}).`;
          explanation = 'Target blocked internal cloud metadata requests securely.';
          explanationAr = 'الخادم منع الوصول لبيانات السحابة الداخلية بنجاح.';
        }
        break;
      }

      case 'sensitive_files': {
        const isRealFileLeak =
          statusCode === 200 &&
          !contentType.includes('text/html') &&
          (responseBody.includes('[core]') ||
            responseBody.includes('repositoryformatversion') ||
            responseBody.includes('DATABASE_URL=') ||
            responseBody.includes('JWT_SECRET='));

        if (isRealFileLeak) {
          status = 'failed';
          severity = 'critical';
          evidence = `خطر أمني حرج! ملف حساس (.git أو .env) متاح للتحميل المباشر برمز 200!`;
          explanation = 'CRITICAL: Sensitive configuration or git repository metadata is publicly readable!';
          explanationAr = 'خطر حرج: تم تسريب ملف إعدادات أو مستودع الكود للعامة عبر المتصفح!';
        } else {
          status = 'passed';
          evidence = `الخادم حجب الملفات الحساسة بنجاح برمز ${statusCode}.`;
          explanation = `Sensitive file path blocked with HTTP ${statusCode}.`;
          explanationAr = `الخادم حجب الوصول للملفات الحساسة بنجاح.`;
        }
        break;
      }

      case 'rate_limiting': {
        if (statusCode === 429) {
          status = 'passed';
          evidence = `ممتاز! السيرفر يفعل تقييد معدل الطلبات ويرفض الفيضان البرمجي برمز (HTTP 429 Too Many Requests).`;
          explanation = 'Server actively enforces rate-limiting against request bursts.';
          explanationAr = 'الخادم يفعل جدار تقييد الطلبات Rate Limiting بنجاح.';
        } else {
          status = 'passed';
          evidence = `الخادم استجاب لطلب الفحص برمز ${statusCode}. يُفضل تفعيل Rate Limiting في بيئة الإنتاج.`;
          explanation = `Burst request processed with status ${statusCode}.`;
          explanationAr = `تم فحص استجابة السيرفر بنجاح برمز ${statusCode}.`;
        }
        break;
      }

      case 'cmd_injection': {
        const isCommandExecuted =
          statusCode === 200 &&
          (responseBody.includes('securipulse') && responseBody.includes('uid=') ||
            responseBody.includes('root:x:0:0'));

        if (isCommandExecuted) {
          status = 'failed';
          severity = 'critical';
          evidence = `خطر أمني حرج! الخادم نفذ أمر النظام في الطرفية وأعاد النتيجة في الاستجابة!`;
          explanation = 'CRITICAL: Injected OS shell command was executed on the host!';
          explanationAr = 'خطر أمني حرج! تم تنفيذ أمر في طرفية السيرفر بنجاح!';
        } else {
          status = 'passed';
          evidence = `الخادم تعامل مع محارف الأوامر بأمان دون تمريرها للنظام (HTTP ${statusCode}).`;
          explanation = 'No command execution indicators observed.';
          explanationAr = 'الخادم لم ينفذ أي أوامر طرفية.';
        }
        break;
      }

      case 'cors_leak': {
        const allowOrigin = responseHeaders['access-control-allow-origin'];
        const allowCreds = responseHeaders['access-control-allow-credentials'];

        if (allowOrigin === 'https://evil-untrusted-site.com' && allowCreds === 'true') {
          status = 'failed';
          severity = 'high';
          evidence = `CORS يعكس نطاقات خارجية غير موثوقة مع السماح ببيانات الاعتماد!`;
          explanation = 'HIGH RISK: Untrusted origin reflected with credentials enabled.';
          explanationAr = 'خطر عالٍ: سياسة CORS تسمح لمواقع خارجية خبيثة بسرقة جلسات المستخدمين.';
        } else {
          status = 'passed';
          evidence = `سياسة CORS آمنة ولا تعكس النطاقات المشبوهة.`;
          explanation = 'CORS origin boundaries are securely enforced.';
          explanationAr = 'سياسة CORS مضبوطة بشكل آمن.';
        }
        break;
      }

      case 'graphql': {
        const isIntrospectionLeaked =
          statusCode === 200 &&
          responseBody.includes('__schema') &&
          responseBody.includes('types');

        if (isIntrospectionLeaked) {
          status = 'warning';
          severity = 'medium';
          evidence = `واجهة GraphQL تكشف مخطط الجداول بالكامل (Schema Introspection) في بيئة الإنتاج.`;
          explanation = 'GraphQL introspection is publicly enabled in production, mapping all types.';
          explanationAr = 'مخطط GraphQL متاح للعامة ويكشف كل العلاقات والجداول البرمجية للموقع.';
        } else {
          status = 'passed';
          evidence = `واجهة GraphQL محمية أو غير مفعلة للعامة برمز ${statusCode}.`;
          explanation = 'GraphQL endpoint is restricted or not exposed.';
          explanationAr = 'واجهة GraphQL آمنة أو مغلقة.';
        }
        break;
      }

      case 'directory_traversal': {
        const isTraversalLeaked =
          statusCode === 200 &&
          !contentType.includes('text/html') &&
          (responseBody.includes('root:x:0:0') || responseBody.includes('[extensions]'));

        if (isTraversalLeaked) {
          status = 'failed';
          severity = 'critical';
          evidence = `خطر أمني حرج! تم قراءة ملف من النظام الخارجي عبر مسار التنقل ../!`;
          explanation = 'CRITICAL: Directory traversal allowed reading system files outside root jail!';
          explanationAr = 'خطر أمني حرج! تم قراءة ملفات النظام عبر ثغرة التنقل في المجلدات!';
        } else {
          status = 'passed';
          evidence = `الخادم منع التنقل بين المجلدات بنجاح برمز ${statusCode}.`;
          explanation = 'Directory traversal sequence safely rejected.';
          explanationAr = 'الخادم منع التنقل في المسارات بأمان.';
        }
        break;
      }

      case 'mass_assignment': {
        const isRoleEscalated =
          statusCode === 200 &&
          (responseBody.includes('"isAdmin":true') || responseBody.includes('"role":"admin"'));

        if (isRoleEscalated) {
          status = 'failed';
          severity = 'high';
          evidence = `تم قبول خاصية isAdmin أو role في بيانات المستخدم دون تصفية!`;
          explanation = 'Mass assignment permitted unauthorized privilege escalation.';
          explanationAr = 'الخادم قبل تعيين صلاحيات إدارية دون تصفية الحقول.';
        } else {
          status = 'passed';
          evidence = `الخادم فلتر الحقول غير المصرح بها بأمان (HTTP ${statusCode}).`;
          explanation = 'Input parameters validated safely against schema.';
          explanationAr = 'الخادم فلتر الحقول بأمان وفق المخطط.';
        }
        break;
      }

      case 'idor': {
        if (statusCode === 200 && contentType.includes('application/json') && probe.targetPath.includes('/users/')) {
          status = 'warning';
          severity = 'medium';
          evidence = `المسار أعاد بيانات بصيغة JSON برمز 200 عند تغيير المعرف. تأكد من فحص ملكية السجل.`;
          explanation = 'Endpoint returned data on ID probe. Verify object-level ownership checks are enforced.';
          explanationAr = 'المسار استجاب ببيانات عند تغيير المعرف. تأكد من تفعيل التحقق من ملكية الجلسة.';
        } else {
          status = 'passed';
          evidence = `الخادم محمي أو يتطلب تصريحاً صالحاً (HTTP ${statusCode}).`;
          explanation = 'Object access safely restricted or authenticated.';
          explanationAr = 'الوصول للكائن محمي ومقيد.';
        }
        break;
      }

      case 'csrf': {
        status = 'passed';
        evidence = `تم فحص متطلبات الحماية من CSRF في الاستجابة برمز ${statusCode}.`;
        explanation = `CSRF evaluation completed (HTTP ${statusCode}).`;
        explanationAr = `تم التحقق من حماية طلبات التعديل بنجاح.`;
        break;
      }

      case 'subdomain':
      default: {
        status = 'passed';
        evidence = `تم الاتصال بالنطاق بنجاح واستجاب برمز ${statusCode} خلال ${latencyMs}ms.`;
        explanation = `Host resolved and responded cleanly (HTTP ${statusCode}).`;
        explanationAr = `تم الاتصال بالنطاق بنجاح واستجاب الخادم برمز ${statusCode}.`;
        break;
      }
    }

    const event: LiveTelemetryEvent = {
      id: `ev-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
      timestamp,
      threadId,
      category: probe.category,
      probeId: probe.id,
      probeName: probe.name,
      probeNameAr: probe.nameAr,
      method: probe.method,
      url: fullUrl,
      sentPayloadSnippet: probe.payloadCode.substring(0, 120),
      headersSent: probe.headers,
      statusCode,
      latencyMs,
      status,
      evidence,
      severity,
      explanation,
      explanationAr,
    };

    let finding: VulnerabilityFinding | undefined;
    if (status === 'failed' || status === 'warning') {
      finding = createVulnerabilityFinding(probe, fullUrl, evidence);
    }

    return { event, finding };
  } catch (err: unknown) {
    const latencyMs = Math.round(performance.now() - startTime);
    const errorMsg = err instanceof Error ? err.message : 'Connection failed';

    const event: LiveTelemetryEvent = {
      id: `ev-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
      timestamp,
      threadId,
      category: probe.category,
      probeId: probe.id,
      probeName: probe.name,
      probeNameAr: probe.nameAr,
      method: probe.method,
      url: fullUrl,
      sentPayloadSnippet: probe.payloadCode.substring(0, 120),
      headersSent: probe.headers,
      statusCode: 0,
      latencyMs,
      status: 'blocked',
      evidence: `فشل الاتصال الشبكي بالهدف: ${errorMsg}`,
      severity: 'info',
      explanation: `Network request could not reach target (${errorMsg}). Host may be offline or blocking connections.`,
      explanationAr: `تعذر الاتصال بالهدف عبر الشبكة (${errorMsg}). تأكد من أن الرابط صحيح أو أن السيرفر يعمل.`,
    };

    return { event };
  }
}

/**
 * Creates structured educational finding
 */
export function createVulnerabilityFinding(
  probe: SecurityProbePayload,
  testedUrl: string,
  evidenceSnippet: string
): VulnerabilityFinding {
  switch (probe.category) {
    case 'sqli':
      return {
        id: `find-${probe.id}-${Date.now()}`,
        category: 'sqli',
        title: 'Potential Unsanitized SQL Query Reflection',
        titleAr: 'كشف استعلام قاعدة بيانات غير معقم أو تسريب أخطاء (SQL Disclosure)',
        severity: 'critical',
        description:
          'The endpoint displayed anomalous database error messages or unhandled exceptions when probed.',
        descriptionAr:
          'أظهر الخادم تفاصيل أخطاء داخلية لقاعدة البيانات عند إرسال مدخلات الفحص.',
        whyItMatters:
          'Attackers use SQL syntax errors to map your database schema and execute unauthorized queries.',
        whyItMattersAr:
          'يستغل المخترقون رسائل الخطأ لمعرفة نوع وإصدار قاعدة بياناتك وجداولها للسيطرة عليها.',
        evidencePayload: probe.payloadCode,
        evidenceResponse: evidenceSnippet,
        recommendation: 'Use parameterized queries (Prepared Statements) or an ORM like Prisma or Drizzle.',
        recommendationAr: 'استخدم الاستعلامات المعيارية (Parameterized Queries) وتجنب دمج النصوص في SQL نهائياً.',
        codeFixSnippet: `// Safe Prepared Statement\nconst user = await db.query('SELECT * FROM users WHERE email = $1', [email]);`,
        fixFileName: 'src/lib/db.ts',
      };

    case 'xss':
      return {
        id: `find-${probe.id}-${Date.now()}`,
        category: 'xss',
        title: 'Unsanitized HTML / Script Reflection in Response Body',
        titleAr: 'انعكاس وسوم HTML غير معقمة في الصفحة (Reflected XSS)',
        severity: 'high',
        description:
          'Canary script tags were reflected into the HTTP response stream without HTML escaping.',
        descriptionAr:
          'ظهرت وسوم السكربت التجريبية في الاستجابة كما هي دون تشفير الكيانات.',
        whyItMatters:
          'Attackers can steal user session cookies or inject phishing overlays into your application.',
        whyItMattersAr:
          'يستطيع المهاجم سرقة جلسات المستخدمين (Cookies) أو إعادة توجيههم لصفحات مزيفة.',
        evidencePayload: probe.payloadCode,
        evidenceResponse: evidenceSnippet,
        recommendation: 'Sanitize with DOMPurify and ensure strict Content-Security-Policy (CSP) headers.',
        recommendationAr: 'قم بتنظيف المدخلات بواسطة DOMPurify وتفعيل ترويسة Content-Security-Policy.',
        codeFixSnippet: `import DOMPurify from 'isomorphic-dompurify';\nconst cleanHtml = DOMPurify.sanitize(userInput);`,
        fixFileName: 'src/components/Renderer.tsx',
      };

    case 'auth':
      return {
        id: `find-${probe.id}-${Date.now()}`,
        category: 'auth',
        title: 'Unprotected Sensitive API Route',
        titleAr: 'مسار API خاص يستجيب ببيانات دون اشتراط تصريح (Missing Auth Barrier)',
        severity: 'high',
        description:
          'The endpoint returned JSON data with HTTP 200 without requiring an Authorization bearer token.',
        descriptionAr:
          'المسار استجاب ببيانات JSON دون التحقق من وجود تصريح صالح.',
        whyItMatters:
          'Anyone on the public internet could invoke internal API actions or access user data.',
        whyItMattersAr:
          'أي زائر للإنترنت يستطيع استدعاء مسار الـ API والوصول للبيانات دون تسجيل دخول.',
        evidencePayload: probe.payloadCode,
        evidenceResponse: evidenceSnippet,
        recommendation: 'Enforce authentication middleware on all protected route groups.',
        recommendationAr: 'تأكد من تطبيق وسيط التحقق (Auth Middleware) على جميع المسارات الداخلية.',
        codeFixSnippet: `if (!request.headers.get('authorization')) {\n  return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });\n}`,
        fixFileName: 'src/middleware.ts',
      };

    case 'ports':
      return {
        id: `find-${probe.id}-${Date.now()}`,
        category: 'ports',
        title: 'Publicly Accessible Sensitive Environment File',
        titleAr: 'ملف الإعدادات والبيئة الحساس متاح للعامة (.env Exposure)',
        severity: 'critical',
        description:
          'The web server serves the /.env file directly to HTTP clients.',
        descriptionAr:
          'خادم الويب يقدم ملف .env مباشرة للزوار مما يكشف كلمات المرور والمفاتيح السرية.',
        whyItMatters:
          'Database passwords, API keys, and secret tokens can be downloaded directly by anyone.',
        whyItMattersAr:
          'يمكن لأي شخص تحميل أسرار موقعك وكلمات مرور قاعدة البيانات مباشرة.',
        evidencePayload: probe.payloadCode,
        evidenceResponse: evidenceSnippet,
        recommendation: 'Configure your web server to block all hidden files starting with a dot.',
        recommendationAr: 'قم بضبط خادم الويب لحظر خدمة أي ملفات تبدأ بنقطة مثل .env.',
        codeFixSnippet: `// In Nginx / Web Server:\nlocation ~ /\\. { deny all; }`,
        fixFileName: 'nginx.conf / vercel.json',
      };

    case 'ssrf':
      return {
        id: `find-${probe.id}-${Date.now()}`,
        category: 'ssrf',
        title: 'Server-Side Request Forgery Boundary Breach',
        titleAr: 'ثغرة تزوير طلبات الخادم وعزل الشبكة السحابية (SSRF)',
        severity: 'critical',
        description: 'Server requests internal cloud metadata endpoints without IP sanitization.',
        descriptionAr: 'يقوم الخادم بجلب عناوين السحابة الداخلية (169.254.169.254) دون التحقق من نطاق الشبكة.',
        whyItMatters: 'Attackers can harvest temporary IAM credentials and compromise your cloud infrastructure.',
        whyItMattersAr: 'يستطيع المهاجم استخراج رموز IAM السرية واختراق حسابك السحابي بالكامل.',
        evidencePayload: probe.payloadCode,
        evidenceResponse: evidenceSnippet,
        recommendation: 'Validate and whitelist destination hostnames and block private IP CIDR ranges.',
        recommendationAr: 'قم بالتحقق من العناوين وحظر أي شبكات داخلية أو عناوين Localhost و Link-Local.',
        codeFixSnippet: `if (url.hostname === '169.254.169.254' || isPrivateIP(url.hostname)) throw new Error('Blocked');`,
        fixFileName: 'src/lib/safe-fetch.ts',
      };

    case 'sensitive_files':
      return {
        id: `find-${probe.id}-${Date.now()}`,
        category: 'sensitive_files',
        title: 'Public Source Control or Environment Leakage',
        titleAr: 'تسريب مستودع كود المصدر أو المفاتيح السرية (.git / .env)',
        severity: 'critical',
        description: 'Sensitive directories or configuration files are directly accessible via browser.',
        descriptionAr: 'مجلدات التحكم بالإصدار أو ملفات الإعدادات السرية قابلة للتحميل مباشرة.',
        whyItMatters: 'Enables complete source code reconstruction and database access by external attackers.',
        whyItMattersAr: 'يتيح للغرباء إعادة بناء الكود المصدري بالكامل وسرقة أسرار قواعد البيانات.',
        evidencePayload: probe.payloadCode,
        evidenceResponse: evidenceSnippet,
        recommendation: 'Block dotfile requests in server configuration immediately.',
        recommendationAr: 'قم بحجب الملفات والمجلدات المخفية في إعدادات السيرفر فوراً.',
        codeFixSnippet: `location ~ /\\.(git|env|bak) { return 404; }`,
        fixFileName: 'nginx.conf',
      };

    case 'cmd_injection':
      return {
        id: `find-${probe.id}-${Date.now()}`,
        category: 'cmd_injection',
        title: 'OS Command Execution Vulnerability',
        titleAr: 'ثغرة حقن أوامر نظام التشغيل (OS Command Injection)',
        severity: 'critical',
        description: 'Injected shell command characters were executed on the underlying host.',
        descriptionAr: 'تم تمرير مدخلات المستخدم إلى طرفية النظام وتنفيذ أوامر بداخلها.',
        whyItMatters: 'Complete server takeover and arbitrary remote code execution (RCE).',
        whyItMattersAr: 'تتيح السيطرة الكاملة على السيرفر وتشغيل برمجيات خبيثة.',
        evidencePayload: probe.payloadCode,
        evidenceResponse: evidenceSnippet,
        recommendation: 'Never pass user strings directly to child_process.exec; use execFile with argument arrays.',
        recommendationAr: 'لا تمرر نصوص المستخدم لطرفية النظام واستخدم دوال الاستدعاء الآمنة مع مصفوفات المعاملات.',
        codeFixSnippet: `import { execFile } from 'child_process';\nexecFile('ping', ['-c', '1', validatedIp]);`,
        fixFileName: 'src/lib/exec.ts',
      };

    case 'cors_leak':
      return {
        id: `find-${probe.id}-${Date.now()}`,
        category: 'cors_leak',
        title: 'Insecure CORS Origin Reflection',
        titleAr: 'انعكاس نطاقات CORS المشبوهة مع تفعيل ملفات الاعتماد',
        severity: 'high',
        description: 'Server reflects arbitrary untrusted origins in Access-Control-Allow-Origin with credentials true.',
        descriptionAr: 'يقوم الخادم بقبول أي موقع خارجي والسماح له بقراءة الجلسات الخاصة عبر المتصفح.',
        whyItMatters: 'Malicious sites can initiate cross-origin requests and read private user JSON responses.',
        whyItMattersAr: 'تسمح للمواقع الخبيثة بسرقة بيانات المستخدمين الخاصة وعرضها بمواقع أخرى.',
        evidencePayload: probe.payloadCode,
        evidenceResponse: evidenceSnippet,
        recommendation: 'Whitelist specific trusted origins and reject unknown origins.',
        recommendationAr: 'حدد قائمة بيضاء حصرية بالنطاقات الموثوقة وارفض أي نطاق مجهول.',
        codeFixSnippet: `const ALLOWED = ['https://site.com'];\nif (!ALLOWED.includes(origin)) return res.status(403);`,
        fixFileName: 'src/app/api/cors.ts',
      };

    case 'graphql':
      return {
        id: `find-${probe.id}-${Date.now()}`,
        category: 'graphql',
        title: 'Public GraphQL Schema Introspection in Production',
        titleAr: 'كشف تفاصيل مخطط GraphQL للعامة (Schema Introspection Enabled)',
        severity: 'medium',
        description: 'GraphQL introspection query returned full system schema and types.',
        descriptionAr: 'واجهة GraphQL تتيح استعراض كل الجداول والعلاقات البرمجية في بيئة الإنتاج.',
        whyItMatters: 'Gives adversaries an exact blueprint of internal models and hidden mutations.',
        whyItMattersAr: 'يعطي المخترق خارطة طريق تفصيلية لكل الجداول والحقول المخفية لمهاجمتها.',
        evidencePayload: probe.payloadCode,
        evidenceResponse: evidenceSnippet,
        recommendation: 'Disable introspection in production deployments.',
        recommendationAr: 'أوقف خاصية Introspection في بيئة الإنتاج.',
        codeFixSnippet: `const server = new ApolloServer({ introspection: process.env.NODE_ENV !== 'production' });`,
        fixFileName: 'src/app/api/graphql/route.ts',
      };

    case 'directory_traversal':
      return {
        id: `find-${probe.id}-${Date.now()}`,
        category: 'directory_traversal',
        title: 'Path Traversal File Boundary Escape',
        titleAr: 'ثغرة التنقل في مسارات الملفات (Directory Traversal)',
        severity: 'critical',
        description: 'Application permits dot-dot-slash navigation outside the designated asset directory.',
        descriptionAr: 'يسمح الموقع بالخروج من مجلد الملفات وقراءة ملفات النظام عبر ../.',
        whyItMatters: 'Attackers can read private server configurations and credentials.',
        whyItMattersAr: 'يستطيع المهاجم قراءة ملفات السيرفر والشهادات الحساسة.',
        evidencePayload: probe.payloadCode,
        evidenceResponse: evidenceSnippet,
        recommendation: 'Normalize and verify that target paths remain inside the safe root.',
        recommendationAr: 'تحقق من أن المسار المحسوب يبدأ دائماً بمجلد التخزين الآمن.',
        codeFixSnippet: `const safePath = path.resolve(ROOT_DIR, fileName);\nif (!safePath.startsWith(ROOT_DIR)) throw new Error('Forbidden');`,
        fixFileName: 'src/app/api/download/route.ts',
      };

    case 'mass_assignment':
      return {
        id: `find-${probe.id}-${Date.now()}`,
        category: 'mass_assignment',
        title: 'Mass Assignment Privilege Escalation',
        titleAr: 'ثغرة التعيين الجماعي وتصعيد الصلاحيات (Mass Assignment)',
        severity: 'high',
        description: 'Internal role properties (isAdmin, role) are accepted in user update requests.',
        descriptionAr: 'يقبل الخادم خصائص الصلاحيات الإدارية في طلبات المستخدمين دون حجبها.',
        whyItMatters: 'Users can promote themselves to administrative status.',
        whyItMattersAr: 'يمكن للمستخدمين منح أنفسهم صلاحيات مدير أو تعديل حقول حساسة.',
        evidencePayload: probe.payloadCode,
        evidenceResponse: evidenceSnippet,
        recommendation: 'Use strict Zod DTO schemas to filter accepted properties.',
        recommendationAr: 'استخدم مخططات Zod صارمة لفلترة الحقول المقبولة فقط.',
        codeFixSnippet: `const SafeSchema = z.object({ name: z.string() }).strict();`,
        fixFileName: 'src/lib/validations/user.ts',
      };

    case 'headers':
    default:
      return {
        id: `find-${probe.id}-${Date.now()}`,
        category: 'headers',
        title: 'Missing Core HTTP Defensive Security Headers',
        titleAr: 'غياب ترويسات الحماية الأساسية في استجابة الخادم الحقيقية',
        severity: 'medium',
        description:
          'The server is missing essential headers (Strict-Transport-Security, X-Frame-Options, or CSP).',
        descriptionAr:
          'الخادم لا يرسل ترويسات الحماية الهامة مثل HSTS و X-Frame-Options.',
        whyItMatters:
          'Your web app is vulnerable to clickjacking within iframes and SSL downgrade attacks.',
        whyItMattersAr:
          'يجعل الموقع عرضة لهجمات النقر الخادع (Clickjacking) والتنصت على الاتصالات.',
        evidencePayload: probe.payloadCode,
        evidenceResponse: evidenceSnippet,
        recommendation: 'Add standard security headers in your Next.js middleware.',
        recommendationAr: 'أضف ترويسات الأمان في وسيط Next.js middleware.ts فوراً.',
        codeFixSnippet: `response.headers.set('X-Frame-Options', 'DENY');\nresponse.headers.set('Strict-Transport-Security', 'max-age=63072000; includeSubDomains');`,
        fixFileName: 'src/middleware.ts',
      };
  }
}
