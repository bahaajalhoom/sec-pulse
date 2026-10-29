// ============================================================================
// CONFIGURATION & CONSTANTS: ATTACK VECTORS, CANARY PAYLOADS & DESCRIPTIONS
// ============================================================================
import {
  AttackIntensity,
  SecurityProbePayload,
  VulnerabilityCategory,
} from '@/types/security';

export const APP_CONFIG = {
  name: 'SecuriPulse',
  nameAr: 'سيكيوريبلس - درع الأمان',
  version: '2.5.0',
  description: 'منصة محاكاة الهجمات الأمنية وفحص الثغرات التفاعلي لأصحاب المواقع والمطورين',
  descriptionEn: 'Interactive Defensive Threat Simulation & Security Posture Auditor for Web Developers',
} as const;

export const INTENSITY_PROFILES: Record<
  AttackIntensity,
  {
    labelAr: string;
    labelEn: string;
    descriptionAr: string;
    descriptionEn: string;
    badgeClass: string;
    probesCount: number;
    recommendedFor: string;
  }
> = {
  gentle: {
    labelAr: 'ضعيف (سطحي آمن)',
    labelEn: 'Gentle (Passive Baseline)',
    descriptionAr: 'فحص ترويسات الأمان (Headers)، فحص شهادة SSL، فحص ملف robots.txt، بدون إرسال استعلامات ضاغطة على الخادم.',
    descriptionEn: 'Passive metadata analysis, HTTP security headers, SSL/TLS validation, robots/sitemap inspection. Zero server stress.',
    badgeClass: 'bg-emerald-950/60 text-emerald-400 border border-emerald-800/40',
    probesCount: 6,
    recommendedFor: 'المواقع الحية على الإنترنت والإنتاج (Production)',
  },
  standard: {
    labelAr: 'وسط (اختبار متوازن)',
    labelEn: 'Standard (Balanced Audit)',
    descriptionAr: 'اختبارات حقن تجريبية آمنة (Canaries)، فحص مصادقة الرموز (Tokens)، فحص منافذ الويب الشائعة، وفحص تسريبات CORS.',
    descriptionEn: 'Safe canary parameter injection, auth token validation, standard exposed port probes, CORS policy checks.',
    badgeClass: 'bg-blue-950/60 text-blue-400 border border-blue-800/40',
    probesCount: 14,
    recommendedFor: 'بيئات الاختبار والمواقع التجريبية (Staging & Dev)',
  },
  rigorous: {
    labelAr: 'صعب (فحص مكثف واختبار صمود)',
    labelEn: 'Rigorous (Deep Stress & Fuzzing)',
    descriptionAr: 'محاكاة هجمات مركبة، تشويش المدخلات (Fuzzing)، فحص صمود الخادم أمام المعدل العالي، فحص مسارات الاستحواذ على النطاق.',
    descriptionEn: 'Advanced parameter fuzzing, boundary tampering, rate-limiting resilience test, dangling subdomain discovery.',
    badgeClass: 'bg-rose-950/60 text-rose-400 border border-rose-800/40',
    probesCount: 22,
    recommendedFor: 'السيرفرات المحلية واختبارات الجاهزية قبل الإطلاق (Pre-launch)',
  },
};

export const CATEGORY_METADATA: Record<
  VulnerabilityCategory,
  {
    nameAr: string;
    nameEn: string;
    icon: string;
    shortDescAr: string;
    shortDescEn: string;
  }
> = {
  sqli: {
    nameAr: 'حقن قواعد البيانات (SQLi)',
    nameEn: 'SQL Injection Canaries',
    icon: 'Database',
    shortDescAr: 'محاكاة إرسال رموز استعلام ملتوية لمعرفة هل يعالج الخادم المدخلات مباشرة بدون تشفير',
    shortDescEn: 'Tests whether database queries safely sanitize inputs using parameterization',
  },
  xss: {
    nameAr: 'حقن النصوص البرمجية (XSS)',
    nameEn: 'Cross-Site Scripting (XSS)',
    icon: 'CodeXml',
    shortDescAr: 'إرسال وسوم نصية تجريبية للتأكد من قيام المتصفح بتنظيفها ومنع سرقة ملفات الارتباط (Cookies)',
    shortDescEn: 'Validates that user inputs are encoded and sanitized before rendering in DOM',
  },
  auth: {
    nameAr: 'كسر المصادقة والجلسات (Broken Auth)',
    nameEn: 'Broken Authentication',
    icon: 'KeyRound',
    shortDescAr: 'محاكاة إرسال طلبات بدون تصريح أو برؤوس JWT مزيفة للتأكد من حماية المسارات السرية',
    shortDescEn: 'Audits endpoint protection against missing tokens, replay, and token tampering',
  },
  ports: {
    nameAr: 'فحص المنافذ والملفات المكشوفة (Open Ports)',
    nameEn: 'Open Ports & Exposed Files',
    icon: 'Radio',
    shortDescAr: 'فحص هل المنافذ الحساسة (مثل 5432 أو 6379 أو 8080) أو ملفات مثل .env مكشوفة للعامة',
    shortDescEn: 'Discovers exposed database ports, admin panels, or leaked .env configuration',
  },
  subdomain: {
    nameAr: 'الاستحواذ على النطاق الفرعي (Subdomain Takeover)',
    nameEn: 'Subdomain Takeover & DNS',
    icon: 'Globe',
    shortDescAr: 'فحص سجلات CNAME المعلقة التي تشير إلى منصات محذوفة تمكن المهاجم من سرقة نطاقك',
    shortDescEn: 'Checks dangling CNAME records pointing to unclaimed hosting services',
  },
  headers: {
    nameAr: 'ترويسات الحماية وسياسة CORS (Security Headers)',
    nameEn: 'Security Headers & CORS',
    icon: 'ShieldCheck',
    shortDescAr: 'التحقق من ترويسات HSTS و CSP و X-Frame-Options لمنع هجمات التضمين والنقر الخبيث',
    shortDescEn: 'Audits essential defensive HTTP headers preventing iframe clickjacking and mime sniffing',
  },
};

// ============================================================================
// DEFAULT EDITABLE CANARY PROBES (PRE-ATTACK INSPECTOR CATALOG)
// ============================================================================
export const INITIAL_PROBES: SecurityProbePayload[] = [
  // --- SQL INJECTION PROBES ---
  {
    id: 'sqli-01',
    category: 'sqli',
    name: 'SQL Tautology Canary Test',
    nameAr: 'اختبار الحشو المنطقي لقواعد البيانات (Tautology 1=1)',
    description: 'Sends a benign tautological condition to verify if query sanitization handles quotes cleanly.',
    descriptionAr: 'يرسل شرطاً منطقياً بديهياً لفحص ما إذا كان استعلام قاعدة البيانات يدمج النصوص دون عزل (Sanitization).',
    method: 'GET',
    targetPath: '/api/search?q=%27%20OR%201%3D1%20--',
    headers: {
      'User-Agent': 'SecuriPulse-Canary-Auditor/2.5',
      'Accept': 'application/json, text/html',
    },
    payloadCode: "' OR 1=1 --",
    canaryExpectedOutcome: 'Server must treat input as literal text, never alter query logic or return unescaped database errors.',
    canaryExpectedOutcomeAr: 'يجب على الخادم معاملة النص ككلمة بحث عادية، وعدم تغيير هيكل الاستعلام أو إظهار خطأ SQL.',
    intensityLevel: 'standard',
    enabled: true,
  },
  {
    id: 'sqli-02',
    category: 'sqli',
    name: 'SQL Error-Based Disclosure Check',
    nameAr: 'كشف أخطاء قواعد البيانات المكشوفة (Error Disclosure)',
    description: 'Sends malformed punctuation to test if internal SQL dialect/database stack traces are leaked in HTTP 500.',
    descriptionAr: 'يرسل علامات ترقيم غير مكتملة لفحص هل يسرّب الخادم رسائل خطأ تكشف نوع قاعدة البيانات وإصدارها للمخترق.',
    method: 'POST',
    targetPath: '/api/v1/auth/login',
    headers: {
      'Content-Type': 'application/json',
      'User-Agent': 'SecuriPulse-Canary-Auditor/2.5',
    },
    payloadCode: JSON.stringify({ email: "admin'\"", password: "test" }, null, 2),
    canaryExpectedOutcome: 'Server must return generic 400/401 response without disclosing PostgreSQL, MySQL, or SQLite syntax traces.',
    canaryExpectedOutcomeAr: 'يجب أن يعيد الخادم رسالة عامة "بيانات غير صالحة" دون ذكر أي تفاصيل برمجية داخلية.',
    intensityLevel: 'rigorous',
    enabled: true,
  },

  // --- CROSS-SITE SCRIPTING (XSS) PROBES ---
  {
    id: 'xss-01',
    category: 'xss',
    name: 'Reflected Script Canary Probe',
    nameAr: 'فحص انعكاس وسوم الجافاسكريبت (Reflected Script Tag)',
    description: 'Tests if user inputs in URL parameters are reflected back raw into HTML without HTML entity escaping.',
    descriptionAr: 'فحص ما إذا كانت متغيرات الرابط تظهر كما هي في الصفحة بدون تشفير الكيانات (HTML Escaping).',
    method: 'GET',
    targetPath: '/?ref=%3Cscript%3Econsole.log(%22securipulse_canary%22)%3C%2Fscript%3E',
    headers: {
      'User-Agent': 'SecuriPulse-Canary-Auditor/2.5',
    },
    payloadCode: '<script>console.log("securipulse_canary")</script>',
    canaryExpectedOutcome: 'Output must be safely entity-encoded (&lt;script&gt;) or blocked by Content-Security-Policy.',
    canaryExpectedOutcomeAr: 'يجب تحويل الأقواس لرموز نصية آمنة لمنع المتصفح من تشغيل الكود.',
    intensityLevel: 'standard',
    enabled: true,
  },
  {
    id: 'xss-02',
    category: 'xss',
    name: 'HTML Attribute Event-Handler Injection',
    nameAr: 'فحص حقن أحداث المتصفح في الوسوم (Attribute Event Injection)',
    description: 'Sends an image tag with an onerror handler to verify attribute context sanitization.',
    descriptionAr: 'محاكاة إرسال وسم صورة مع معالج خطأ لاختبار هل يتم تفريغ الأحداث التنفيذية في الحقول.',
    method: 'POST',
    targetPath: '/api/feedback',
    headers: {
      'Content-Type': 'application/json',
      'User-Agent': 'SecuriPulse-Canary-Auditor/2.5',
    },
    payloadCode: JSON.stringify({ comment: '<img src=x onerror=void(0)>' }, null, 2),
    canaryExpectedOutcome: 'Attributes like onerror, onclick must be stripped by sanitization library (e.g. DOMPurify).',
    canaryExpectedOutcomeAr: 'يجب حذف الأحداث التنفيذية بواسطة مكتبة تنظيف موثوقة.',
    intensityLevel: 'rigorous',
    enabled: true,
  },

  // --- BROKEN AUTHENTICATION & ACCESS CONTROL ---
  {
    id: 'auth-01',
    category: 'auth',
    name: 'Protected API Route Authorization Omission',
    nameAr: 'فحص حماية المسارات الإدارية بدون رمز تصريح (Missing Auth Header)',
    description: 'Probes common internal endpoints without providing an Authorization bearer token.',
    descriptionAr: 'محاولة الدخول على مسارات إدارية حساسة بدون إرسال تصريح لفحص هل الخادم محمي بالكامل.',
    method: 'GET',
    targetPath: '/api/admin/users',
    headers: {
      'User-Agent': 'SecuriPulse-Canary-Auditor/2.5',
      'Accept': 'application/json',
    },
    payloadCode: '// Empty Authorization Header Test\nGET /api/admin/users HTTP/1.1\nHost: target\n',
    canaryExpectedOutcome: 'Server must immediately reject with HTTP 401 Unauthorized or 403 Forbidden.',
    canaryExpectedOutcomeAr: 'يجب أن يرفض الخادم الطلب فوراً برمز 401 أو 403 دون إظهار أي بيانات مستخدمين.',
    intensityLevel: 'gentle',
    enabled: true,
  },
  {
    id: 'auth-02',
    category: 'auth',
    name: 'JWT Algorithm "None" Signature Bypass Probe',
    nameAr: 'اختبار تجاوز توقيع رموز JWT (Algorithm None Probe)',
    description: 'Sends an unsigned JWT token with alg: none to check if the backend enforces cryptographic signature validation.',
    descriptionAr: 'إرسال رمز JWT مفكك التوقيع لفحص هل يتحقق الباك إند من صحة التوقيع المشفر أم يقبل الرموز المزيفة.',
    method: 'GET',
    targetPath: '/api/user/profile',
    headers: {
      'Authorization': 'Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IlNlY3VyaVB1bHNlIn0.',
      'User-Agent': 'SecuriPulse-Canary-Auditor/2.5',
    },
    payloadCode: 'Header: {"alg":"none","typ":"JWT"}\nPayload: {"sub":"canary-user","role":"admin"}',
    canaryExpectedOutcome: 'Token must be rejected as invalid signature (HTTP 401).',
    canaryExpectedOutcomeAr: 'يجب رفض الرمز فوراً لعدم وجود توقيع رقمي صالح.',
    intensityLevel: 'standard',
    enabled: true,
  },

  // --- OPEN PORTS & EXPOSED ASSETS ---
  {
    id: 'ports-01',
    category: 'ports',
    name: 'Exposed Environment Secrets & Git Metadata Probe',
    nameAr: 'فحص تسريب ملفات الإعدادات والبيئة (.env & .git)',
    description: 'Checks if sensitive environment configuration or source control metadata directories are publicly accessible.',
    descriptionAr: 'فحص هل ملفات المتغيرات الحساسة (.env) أو مجلدات Git مكشوفة للزوار عبر المتصفح.',
    method: 'GET',
    targetPath: '/.env',
    headers: {
      'User-Agent': 'SecuriPulse-Canary-Auditor/2.5',
    },
    payloadCode: 'GET /.env HTTP/1.1\nHost: target\nConnection: close',
    canaryExpectedOutcome: 'Server must return HTTP 404 Not Found or 403 Forbidden, never returning text/plain secrets.',
    canaryExpectedOutcomeAr: 'يجب أن يعيد السيرفر 404 أو 403 ولا يسمح أبداً بتحميل الملف.',
    intensityLevel: 'gentle',
    enabled: true,
  },
  {
    id: 'ports-02',
    category: 'ports',
    name: 'Exposed Database & Microservice Port Audit',
    nameAr: 'فحص منافذ الخدمات وقواعد البيانات المباشرة (Ports 5432, 6379, 8080)',
    description: 'Simulates safe banner checking on commonly misconfigured ports like Redis, PostgreSQL, and Node debuggers.',
    descriptionAr: 'فحص هل قواعد البيانات مثل بوستجرس أو ريديس مكشوفة برقم IP العام دون جدار ناري.',
    method: 'HEAD',
    targetPath: ':5432',
    headers: {
      'User-Agent': 'SecuriPulse-Canary-Auditor/2.5',
    },
    payloadCode: 'TCP SYN Canary Probe to Port 5432 (Postgres) / 6379 (Redis)',
    canaryExpectedOutcome: 'Database ports should never be exposed to the public internet; only accessible via private VPC.',
    canaryExpectedOutcomeAr: 'يجب أن تكون منافذ قواعد البيانات مغلقة عن الإنترنت العام ومحصورة بالشبكة الداخلية.',
    intensityLevel: 'standard',
    enabled: true,
  },

  // --- SUBDOMAIN TAKEOVER & DNS HYGIENE ---
  {
    id: 'subdomain-01',
    category: 'subdomain',
    name: 'Dangling CNAME & Cloud Service Record Audit',
    nameAr: 'فحص سجلات CNAME المعلقة ومضيفات السحابة المهجورة',
    description: 'Audits DNS canonical name mappings for orphaned targets on AWS S3, Vercel, GitHub Pages, or Heroku.',
    descriptionAr: 'التأكد من أن النطاقات الفرعية لا تشير إلى خدمات سحابية تم حذفها مما يتيح للغير حجزها باسمك.',
    method: 'GET',
    targetPath: '/dns-hygiene-audit',
    headers: {
      'User-Agent': 'SecuriPulse-Canary-Auditor/2.5',
    },
    payloadCode: 'DNS Query: CNAME record verification & NXDOMAIN error check',
    canaryExpectedOutcome: 'No CNAME records pointing to unclaimed resources with NXDOMAIN status.',
    canaryExpectedOutcomeAr: 'عدم وجود سجلات توجه لمشاريع محذوفة تتيح للغرباء السيطرة على دومينك الفرعي.',
    intensityLevel: 'gentle',
    enabled: true,
  },

  // --- DEFENSIVE SECURITY HEADERS & CORS ---
  {
    id: 'headers-01',
    category: 'headers',
    name: 'HSTS & Clickjacking Protection Audit',
    nameAr: 'فحص ترويسات HSTS و X-Frame-Options (منع التضمين الخبيث)',
    description: 'Verifies presence of Strict-Transport-Security, X-Frame-Options, and X-Content-Type-Options headers.',
    descriptionAr: 'التحقق من إلزام المتصفح بتشفير HTTPS ومنع وضع موقعك داخل إطار وهمي (iFrame) لسرقة نقرات المستخدمين.',
    method: 'HEAD',
    targetPath: '/',
    headers: {
      'User-Agent': 'SecuriPulse-Canary-Auditor/2.5',
    },
    payloadCode: 'HEAD / HTTP/1.1\nHost: target\n',
    canaryExpectedOutcome: 'Response must include: Strict-Transport-Security, X-Frame-Options: DENY, and X-Content-Type-Options: nosniff.',
    canaryExpectedOutcomeAr: 'يجب أن تحتوي ترويسات الاستجابة على HSTS و X-Frame-Options.',
    intensityLevel: 'gentle',
    enabled: true,
  },
  {
    id: 'headers-02',
    category: 'headers',
    name: 'Permissive CORS Preflight Wildcard Audit',
    nameAr: 'فحص سياسة تبادل الموارد (CORS Wildcard with Credentials)',
    description: 'Sends an OPTIONS preflight request with an untrusted Origin to detect insecure wildcard CORS settings.',
    descriptionAr: 'إرسال طلب تجريبي من موقع خارجي لفحص هل يسمح خادمك لأي موقع بسرقة بيانات المستخدمين عبر CORS.',
    method: 'OPTIONS',
    targetPath: '/api/user/data',
    headers: {
      'Origin': 'https://untrusted-external-canary.com',
      'Access-Control-Request-Method': 'POST',
      'User-Agent': 'SecuriPulse-Canary-Auditor/2.5',
    },
    payloadCode: 'OPTIONS /api/user/data HTTP/1.1\nOrigin: https://untrusted-external-canary.com',
    canaryExpectedOutcome: 'Server must NOT return Access-Control-Allow-Origin: * along with Access-Control-Allow-Credentials: true.',
    canaryExpectedOutcomeAr: 'يجب ألا يسمح الخادم للجميع بالوصول للبيانات الشخصية مع السماح بملفات الارتباط.',
    intensityLevel: 'standard',
    enabled: true,
  },
];

// ============================================================================
// BEGINNER-FRIENDLY CODE FIX RECIPES (COPIED IN 1-CLICK)
// ============================================================================
export const REMEDIATION_RECIPES = {
  headers: {
    titleAr: 'حل ترويسات الأمان في Next.js',
    titleEn: 'Next.js Security Headers Middleware Solution',
    fileName: 'middleware.ts',
    code: `import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

export function middleware(request: NextRequest) {
  const response = NextResponse.next();

  // ترويسات الأمان القياسية الموصى بها عالمياً
  response.headers.set('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload');
  response.headers.set('X-Frame-Options', 'DENY');
  response.headers.set('X-Content-Type-Options', 'nosniff');
  response.headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');
  response.headers.set('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');

  return response;
}

export const config = {
  matcher: '/((?!api|_next/static|_next/image|favicon.ico).*)',
};`,
  },
  sqli: {
    titleAr: 'الحماية من حقن قواعد البيانات (استعلامات معيارية)',
    titleEn: 'Parameterized Queries Defense (Prisma / SQL)',
    fileName: 'src/lib/db.ts',
    code: `// ❌ خطأ فادح: الدمج المباشر للنصوص في الاستعلام
// const users = await db.query(\`SELECT * FROM users WHERE email = '\${userInput}'\`);

// ✅ الحل الصحيح: استخدام الاستعلام المعياري (Parameterized Query)
// في PostgreSQL / Node-PG:
const result = await db.query(
  'SELECT id, email, created_at FROM users WHERE email = $1',
  [userInput] // يتم عزل وتشفير القيمة تلقائياً دون تنفيذها كأمر
);

// أو باستخدام Prisma ORM (محمي تلقائياً):
const user = await prisma.user.findUnique({
  where: { email: userInput },
});`,
  },
  cors: {
    titleAr: 'ضبط سياسة CORS الآمنة للمواقع',
    titleEn: 'Secure CORS Configuration (Express / Next.js API)',
    fileName: 'src/app/api/cors.ts',
    code: `// قائمة النطاقات المسموح لها فقط بالوصول إلى واجهة موقعك
const ALLOWED_ORIGINS = [
  'https://yourdomain.com',
  'https://admin.yourdomain.com',
];

export function setCorsHeaders(origin: string | null) {
  const isAllowed = origin && ALLOWED_ORIGINS.includes(origin);
  
  return {
    'Access-Control-Allow-Origin': isAllowed ? origin : 'null',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Allow-Credentials': 'true',
  };
}`,
  },
  xss: {
    titleAr: 'تطهير مدخلات المستخدمين لمنع XSS',
    titleEn: 'Input Sanitization with DOMPurify / React Escaping',
    fileName: 'src/lib/sanitize.ts',
    code: `import DOMPurify from 'isomorphic-dompurify';

// تطهير أي نص HTML يدخله المستخدم قبل عرضه في الصفحة
export function cleanUserInput(dirtyInput: string): string {
  return DOMPurify.sanitize(dirtyInput, {
    ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'a'],
    ALLOWED_ATTR: ['href'],
  });
}

// في React: استخدم الأقواس العادية دائماً لأنها تشفر الرموز تلقائياً:
// <div>{userInput}</div> // ✅ آمن 100%
// ❌ تجنب استخدام: dangerouslySetInnerHTML دون تطهير`,
  },
};
