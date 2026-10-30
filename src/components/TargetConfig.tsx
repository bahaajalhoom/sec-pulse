'use client';

// ============================================================================
// 1. IMPORTS
// ============================================================================
import React, { useState } from 'react';
import {
  GlobalOutlined,
  PlayCircleOutlined,
  StopOutlined,
  CheckOutlined,
  SettingOutlined,
  ApiOutlined,
  DownOutlined,
  UpOutlined,
  ThunderboltOutlined,
  SlidersOutlined,
  CheckSquareOutlined,
  CloseSquareOutlined,
  DatabaseOutlined,
  CodeOutlined,
  KeyOutlined,
  CloudServerOutlined,
  SafetyCertificateOutlined,
  LockOutlined,
  FileTextOutlined,
  DesktopOutlined,
  ShareAltOutlined,
  SafetyOutlined,
  ClusterOutlined,
  FolderOpenOutlined,
  ControlOutlined,
  FieldTimeOutlined,
} from '@ant-design/icons';
import {
  AttackIntensity,
  DiscoveredEndpoint,
  VulnerabilityCategory,
} from '@/types/security';
import { INTENSITY_PROFILES } from '@/lib/constants';
import EndpointDiscoveryPanel from './EndpointDiscoveryPanel';

// ============================================================================
// 2. CONFIGURATION & STYLES (ZONE 2)
// ============================================================================
const STYLES = {
  card: 'rounded-xl border border-white/[0.1] bg-[#0c0c0e] p-5 space-y-4 shadow-sm',
  input:
    'w-full rounded-lg border border-white/[0.12] bg-black px-4 py-3 text-sm text-white placeholder-zinc-500 focus:border-white/50 focus:outline-none font-mono transition-colors',
  primaryLaunchBtn:
    'w-full py-3.5 px-6 rounded-lg font-bold text-sm text-black bg-white hover:bg-zinc-200 transition-all flex items-center justify-center gap-2.5 cursor-pointer disabled:opacity-40 select-none shadow-lg active:scale-[0.99]',
  abortBtn:
    'w-full py-3.5 px-6 rounded-lg font-bold text-sm text-red-200 bg-red-950/80 hover:bg-red-900 border border-red-700/60 transition-all flex items-center justify-center gap-2.5 cursor-pointer select-none shadow-lg active:scale-[0.99]',
};

// Perfectly balanced 4x4 Attack Vectors Grid (4 groups × 4 items = 16 vectors)
const VECTOR_GROUPS: {
  id: string;
  nameAr: string;
  nameEn: string;
  tag: string;
  items: {
    cat: VulnerabilityCategory;
    nameAr: string;
    code: string;
    icon: React.ReactNode;
  }[];
}[] = [
  {
    id: 'injection',
    nameAr: 'حقن الأكواد وقواعد البيانات',
    nameEn: 'Injection & Execution',
    tag: 'INJECTION',
    items: [
      { cat: 'sqli', nameAr: 'حقن قواعد البيانات', code: 'SQLi', icon: <DatabaseOutlined /> },
      { cat: 'xss', nameAr: 'حقن النصوص البرمجية', code: 'XSS', icon: <CodeOutlined /> },
      { cat: 'cmd_injection', nameAr: 'أوامر نظام التشغيل', code: 'RCE', icon: <DesktopOutlined /> },
      { cat: 'directory_traversal', nameAr: 'التنقل في مسارات الملفات', code: 'LFI', icon: <FolderOpenOutlined /> },
    ],
  },
  {
    id: 'auth_access',
    nameAr: 'المصادقة والتحكم بالوصول',
    nameEn: 'Authentication & Access',
    tag: 'AUTH',
    items: [
      { cat: 'auth', nameAr: 'كسر المصادقة والجلسات', code: 'Auth', icon: <KeyOutlined /> },
      { cat: 'idor', nameAr: 'كسر عزل كائنات البيانات', code: 'IDOR', icon: <LockOutlined /> },
      { cat: 'mass_assignment', nameAr: 'التعيين الجماعي للصلاحيات', code: 'MassAssign', icon: <ControlOutlined /> },
      { cat: 'csrf', nameAr: 'حماية تزوير الطلبات', code: 'CSRF', icon: <SafetyOutlined /> },
    ],
  },
  {
    id: 'network_perimeter',
    nameAr: 'الشبكة والجدران النارية',
    nameEn: 'Network & Perimeter',
    tag: 'NETWORK',
    items: [
      { cat: 'ssrf', nameAr: 'تزوير طلبات جانب الخادم', code: 'SSRF', icon: <ApiOutlined /> },
      { cat: 'headers', nameAr: 'ترويسات الحماية والأمان', code: 'Headers', icon: <SafetyCertificateOutlined /> },
      { cat: 'ports', nameAr: 'المنافذ الحساسة المكشوفة', code: 'Ports', icon: <CloudServerOutlined /> },
      { cat: 'cors_leak', nameAr: 'تسريب سياسات النطاق', code: 'CORS', icon: <ShareAltOutlined /> },
    ],
  },
  {
    id: 'recon_leaks',
    nameAr: 'تسريب البيانات والأسرار',
    nameEn: 'Leaks & Infrastructure',
    tag: 'RECON',
    items: [
      { cat: 'sensitive_files', nameAr: 'ملفات التكوين والبيئة (.env)', code: '.env/.git', icon: <FileTextOutlined /> },
      { cat: 'graphql', nameAr: 'كشف استعلامات GraphQL', code: 'GraphQL', icon: <ClusterOutlined /> },
      { cat: 'rate_limiting', nameAr: 'تقييد معدل الطلبات والصمود', code: 'RateLimit', icon: <FieldTimeOutlined /> },
      { cat: 'subdomain', nameAr: 'الاستحواذ على النطاقات الفرعية', code: 'Subdomain', icon: <GlobalOutlined /> },
    ],
  },
];

// ============================================================================
// 3. TYPES & INTERFACES (ZONE 3)
// ============================================================================
interface TargetConfigProps {
  targetUrl: string;
  onTargetUrlChange: (url: string) => void;
  apiBaseUrl: string;
  onApiBaseUrlChange: (url: string) => void;
  endpoints: DiscoveredEndpoint[];
  onEndpointsChange: (updated: DiscoveredEndpoint[]) => void;
  intensity: AttackIntensity;
  onIntensityChange: (level: AttackIntensity) => void;
  concurrency: number;
  onConcurrencyChange: (threads: number) => void;
  delayMs: number;
  onDelayMsChange: (delay: number) => void;
  enabledCategories: Record<VulnerabilityCategory, boolean>;
  onToggleCategory: (cat: VulnerabilityCategory) => void;
  onOpenInspector: () => void;
  onStartAudit: () => void;
  onAbortAudit: () => void;
  isRunning: boolean;
  lang: 'ar' | 'en';
}

// ============================================================================
// 6. MAIN COMPONENT (ZONE 6)
// ============================================================================
export default function TargetConfig({
  targetUrl,
  onTargetUrlChange,
  apiBaseUrl,
  onApiBaseUrlChange,
  endpoints,
  onEndpointsChange,
  intensity,
  onIntensityChange,
  concurrency,
  onConcurrencyChange,
  delayMs,
  onDelayMsChange,
  enabledCategories,
  onToggleCategory,
  onOpenInspector,
  onStartAudit,
  onAbortAudit,
  isRunning,
  lang,
}: TargetConfigProps) {
  const isArabic = lang === 'ar';
  const [showApiDiscovery, setShowApiDiscovery] = useState(false);

  const totalEnabled = Object.values(enabledCategories).filter(Boolean).length;
  const isAllEnabled = totalEnabled === 16;

  function handleToggleAll(enable: boolean) {
    const allCategories: VulnerabilityCategory[] = [
      'sqli', 'xss', 'auth', 'ports', 'subdomain', 'headers', 'ssrf', 'idor',
      'sensitive_files', 'rate_limiting', 'cmd_injection', 'cors_leak',
      'csrf', 'graphql', 'directory_traversal', 'mass_assignment',
    ];
    allCategories.forEach((cat) => {
      if (enabledCategories[cat] !== enable) {
        onToggleCategory(cat);
      }
    });
  }

  return (
    <div className="space-y-5">
      {/* ===================================================================== */}
      {/* SECTION 1: TARGET WEB URL OMNIBAR                                     */}
      {/* ===================================================================== */}
      <div className={STYLES.card}>
        <div className="flex items-center justify-between flex-wrap gap-2">
          <label className="text-xs font-bold text-white flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-emerald-400" />
            <span>
              {isArabic
                ? 'رابط الموقع أو الواجهة المستهدفة (Target URL):'
                : 'Target Web Application or API URL:'}
            </span>
          </label>

          <span className="text-[11px] font-mono text-zinc-400 flex items-center gap-1.5">
            <span className="w-1.5 h-1.5 rounded-full bg-blue-400" />
            <span>{isArabic ? 'جاهز للفحص المباشر' : 'Live Audit Ready'}</span>
          </span>
        </div>

        {/* URL Input Bar */}
        <div className="relative">
          <div className="absolute inset-y-0 start-0 flex items-center ps-3.5 pointer-events-none text-zinc-400">
            <GlobalOutlined className="text-sm" />
          </div>
          <input
            type="text"
            value={targetUrl}
            onChange={(e) => onTargetUrlChange(e.target.value)}
            placeholder={isArabic ? 'https://example.com أو https://api.example.com' : 'https://yourdomain.com or https://api.yourdomain.com'}
            disabled={isRunning}
            className={`${STYLES.input} ps-10`}
            dir="ltr"
          />
        </div>

        <div className="flex items-center justify-between text-[11px] text-zinc-500 font-mono">
          <span>
            {isArabic
              ? 'أدخل النطاق الحي أو عنوان الخادم لبدء محاكاة الهجمات واختبار الثغرات.'
              : 'Enter production domain or API host to execute defensive security probing.'}
          </span>
          <span className="text-zinc-600">HTTPS / HTTP</span>
        </div>
      </div>

      {/* ===================================================================== */}
      {/* SECTION 1.5: AUTOMATED API & ENDPOINT DISCOVERY PANEL                 */}
      {/* ===================================================================== */}
      <div className="rounded-xl border border-white/[0.1] bg-[#0c0c0e] overflow-hidden">
        <button
          type="button"
          onClick={() => setShowApiDiscovery(!showApiDiscovery)}
          className="w-full p-4 flex items-center justify-between text-start cursor-pointer hover:bg-white/[0.03] transition-colors"
        >
          <div className="flex items-center gap-2.5">
            <ApiOutlined className="text-sm text-blue-400" />
            <span className="text-xs font-bold text-white">
              {isArabic
                ? 'مستكشف مسارات الـ API والنهايات الحقيقية'
                : 'Real API & Route Discovery Engine'}
            </span>
            <span className="font-mono text-[11px] px-2 py-0.5 rounded bg-white/[0.06] border border-white/[0.1] text-zinc-300">
              {endpoints.length} {isArabic ? 'مسارات مكتشفة' : 'routes'}
            </span>
          </div>
          <div className="text-xs text-zinc-400">
            {showApiDiscovery ? <UpOutlined /> : <DownOutlined />}
          </div>
        </button>

        {showApiDiscovery && (
          <div className="p-4 pt-0 border-t border-white/[0.08]">
            <EndpointDiscoveryPanel
              targetUrl={targetUrl}
              apiBaseUrl={apiBaseUrl}
              onApiBaseUrlChange={onApiBaseUrlChange}
              endpoints={endpoints}
              onEndpointsChange={onEndpointsChange}
              lang={lang}
              isRunning={isRunning}
            />
          </div>
        )}
      </div>

      {/* ===================================================================== */}
      {/* SECTION 2: ATTACK INTENSITY PROFILES (3 CARDS SIDE-BY-SIDE)           */}
      {/* ===================================================================== */}
      <div className={STYLES.card}>
        <div className="flex items-center justify-between">
          <label className="text-xs font-bold text-white flex items-center gap-2">
            <ThunderboltOutlined className="text-xs text-blue-400" />
            <span>
              {isArabic ? 'مستوى صعوبة وشدة الهجوم:' : 'Attack Intensity Profile:'}
            </span>
          </label>
          <span className="text-[11px] font-mono text-zinc-400">
            {INTENSITY_PROFILES[intensity].probesCount} {isArabic ? 'فحص نشط' : 'Active Probes'}
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          {(['gentle', 'standard', 'rigorous'] as AttackIntensity[]).map((level) => {
            const profile = INTENSITY_PROFILES[level];
            const isSelected = intensity === level;

            return (
              <button
                key={level}
                type="button"
                onClick={() => onIntensityChange(level)}
                disabled={isRunning}
                className={`p-4 rounded-xl border text-start transition-all flex flex-col justify-between gap-3 cursor-pointer select-none active:scale-[0.99] ${
                  isSelected
                    ? 'bg-white/[0.08] border-white text-white shadow-md'
                    : 'bg-black border-white/[0.08] text-zinc-400 hover:border-white/[0.2] hover:text-zinc-200'
                }`}
              >
                <div className="flex items-center justify-between w-full">
                  <span className="text-xs font-bold text-white">
                    {isArabic ? profile.labelAr : profile.labelEn}
                  </span>
                  <span
                    className={`text-[10px] px-2 py-0.5 rounded font-mono font-bold ${
                      isSelected
                        ? 'bg-white text-black'
                        : 'bg-white/[0.06] text-zinc-400 border border-white/[0.08]'
                    }`}
                  >
                    {profile.probesCount} {isArabic ? 'فحص' : 'probes'}
                  </span>
                </div>
                <p className="text-[11px] text-zinc-400 leading-relaxed">
                  {isArabic ? profile.descriptionAr : profile.descriptionEn}
                </p>
                <div className="text-[10px] font-mono text-zinc-500 pt-1 border-t border-white/[0.05]">
                  {isArabic ? profile.recommendedFor : 'Recommended environment'}
                </div>
              </button>
            );
          })}
        </div>

        {/* Concurrency & Pacing Segmented Dials */}
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 pt-2 border-t border-white/[0.08]">
          {/* Concurrency Threads */}
          <div className="p-3.5 rounded-lg bg-black border border-white/[0.08] space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-xs font-medium text-zinc-300">
                {isArabic ? 'الهجمات المتزامنة (Concurrency):' : 'Concurrent Workers:'}
              </span>
              <span className="font-mono text-xs font-bold text-white bg-white/[0.1] px-2 py-0.5 rounded">
                {concurrency}x
              </span>
            </div>
            <div className="grid grid-cols-4 gap-1.5 bg-[#0c0c0e] p-1 rounded-md border border-white/[0.08]">
              {[1, 2, 4, 8].map((t) => (
                <button
                  key={t}
                  type="button"
                  onClick={() => onConcurrencyChange(t)}
                  disabled={isRunning}
                  className={`py-1.5 rounded font-mono text-xs font-semibold transition-all cursor-pointer ${
                    concurrency === t
                      ? 'bg-white text-black shadow-sm'
                      : 'text-zinc-400 hover:text-white'
                  }`}
                >
                  {t}x
                </button>
              ))}
            </div>
            <p className="text-[10.5px] text-zinc-500">
              {isArabic
                ? 'توزيع حزم الهجوم عبر عدة خيوط متوازية لتسريع الفحص واختبار الصمود.'
                : 'Parallelize probe requests across multiple asynchronous threads.'}
            </p>
          </div>

          {/* Pacing Delay */}
          <div className="p-3.5 rounded-lg bg-black border border-white/[0.08] space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-xs font-medium text-zinc-300">
                {isArabic ? 'فترة التهدئة (Pacing Delay):' : 'Request Delay:'}
              </span>
              <span className="font-mono text-xs font-bold text-white bg-white/[0.1] px-2 py-0.5 rounded">
                {delayMs} ms
              </span>
            </div>
            <div className="grid grid-cols-4 gap-1.5 bg-[#0c0c0e] p-1 rounded-md border border-white/[0.08]">
              {[0, 50, 150, 350].map((d) => (
                <button
                  key={d}
                  type="button"
                  onClick={() => onDelayMsChange(d)}
                  disabled={isRunning}
                  className={`py-1.5 rounded font-mono text-xs font-semibold transition-all cursor-pointer ${
                    delayMs === d
                      ? 'bg-white text-black shadow-sm'
                      : 'text-zinc-400 hover:text-white'
                  }`}
                >
                  {d}ms
                </button>
              ))}
            </div>
            <p className="text-[10.5px] text-zinc-500">
              {isArabic
                ? 'تحديد فترة زمنية بين الطلبات لتجنب حظر الـ Rate Limiting بجدار الحماية.'
                : 'Interval spacing between packets to prevent triggering strict rate limiters.'}
            </p>
          </div>
        </div>
      </div>

      {/* ===================================================================== */}
      {/* SECTION 3: 4x4 SECURITY ATTACK VECTORS MATRIX                         */}
      {/* ===================================================================== */}
      <div className={STYLES.card}>
        <div className="flex items-center justify-between flex-wrap gap-2 pb-3 border-b border-white/[0.08]">
          <div className="flex items-center gap-2.5">
            <SlidersOutlined className="text-sm text-blue-400" />
            <span className="text-xs font-bold text-white">
              {isArabic ? 'نطاقات الفحص الأمني المشمولة بالهجوم' : 'Included Security Attack Vectors'}
            </span>
            <span className="font-mono text-xs font-bold px-2 py-0.5 rounded bg-white/[0.08] text-zinc-300 border border-white/[0.1]">
              {totalEnabled} / 16 {isArabic ? 'مفعلة' : 'Active'}
            </span>
          </div>

          {/* REAL, PROMINENT BUTTONS FOR SELECT ALL / CLEAR ALL */}
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={() => handleToggleAll(true)}
              disabled={isRunning}
              className={`flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-bold transition-all cursor-pointer shadow-sm active:scale-95 ${
                isAllEnabled
                  ? 'bg-white text-black border border-white'
                  : 'bg-white/[0.1] hover:bg-white/[0.18] text-white border border-white/[0.25]'
              }`}
            >
              <CheckSquareOutlined className="text-xs" />
              <span>{isArabic ? 'تحديد الكل' : 'Select All'}</span>
            </button>

            <button
              type="button"
              onClick={() => handleToggleAll(false)}
              disabled={isRunning || totalEnabled === 0}
              className="flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-semibold text-zinc-300 hover:text-white bg-white/[0.06] hover:bg-white/[0.12] border border-white/[0.18] transition-all cursor-pointer disabled:opacity-30 active:scale-95 shadow-sm"
            >
              <CloseSquareOutlined className="text-xs text-zinc-400" />
              <span>{isArabic ? 'إلغاء التحديد' : 'Clear All'}</span>
            </button>
          </div>
        </div>

        {/* The 4-Column Symmetrical Matrix */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          {VECTOR_GROUPS.map((sec) => (
            <div
              key={sec.id}
              className="p-3 rounded-xl bg-black border border-white/[0.08] space-y-2 flex flex-col justify-between"
            >
              <div className="flex items-center justify-between pb-1.5 border-b border-white/[0.06]">
                <span className="text-[11px] font-bold text-zinc-200 truncate">
                  {isArabic ? sec.nameAr : sec.nameEn}
                </span>
                <span className="font-mono text-[9px] uppercase tracking-wider text-zinc-500">
                  {sec.tag}
                </span>
              </div>

              <div className="space-y-1.5 flex-1">
                {sec.items.map((item) => {
                  const isEnabled = enabledCategories[item.cat];
                  return (
                    <button
                      key={item.cat}
                      type="button"
                      onClick={() => onToggleCategory(item.cat)}
                      disabled={isRunning}
                      className={`w-full p-2.5 rounded-lg border text-start flex items-center justify-between transition-all cursor-pointer select-none active:scale-[0.98] ${
                        isEnabled
                          ? 'bg-white/[0.08] border-white/[0.2] text-white hover:bg-white/[0.12]'
                          : 'bg-[#08080a] border-white/[0.04] text-zinc-500 hover:text-zinc-300 hover:border-white/[0.1]'
                      }`}
                    >
                      <div className="flex items-center gap-2 min-w-0">
                        <div
                          className={`w-4 h-4 rounded border flex items-center justify-center shrink-0 transition-colors ${
                            isEnabled
                              ? 'bg-white border-white text-black'
                              : 'border-zinc-700 bg-transparent'
                          }`}
                        >
                          {isEnabled && <CheckOutlined className="text-[9px] font-bold" />}
                        </div>
                        <span className="text-xs font-medium truncate">
                          {isArabic ? item.nameAr : item.code}
                        </span>
                      </div>

                      <span className="font-mono text-[10px] text-zinc-400 bg-black/60 px-1.5 py-0.5 rounded border border-white/[0.06] shrink-0 ms-1.5">
                        {item.code}
                      </span>
                    </button>
                  );
                })}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* ===================================================================== */}
      {/* SECTION 4: PRIMARY LAUNCH ACTION BAR                                  */}
      {/* ===================================================================== */}
      <div className="space-y-3">
        {isRunning ? (
          <button
            type="button"
            onClick={onAbortAudit}
            className={STYLES.abortBtn}
          >
            <StopOutlined className="text-base" />
            <span>{isArabic ? 'إيقاف الفحص المباشر فوراً (Abort Stream)' : 'Abort Live Audit'}</span>
          </button>
        ) : (
          <button
            type="button"
            onClick={onStartAudit}
            disabled={!targetUrl.trim() || totalEnabled === 0}
            className={STYLES.primaryLaunchBtn}
          >
            <PlayCircleOutlined className="text-base" />
            <span>
              {isArabic ? 'بدء فحص الأمان الشامل والمحاكاة الحية' : 'Launch Full Security Audit'}
            </span>
            <span className="font-mono text-xs px-2.5 py-0.5 rounded bg-black text-white font-bold">
              {INTENSITY_PROFILES[intensity].probesCount} Probes Active
            </span>
          </button>
        )}

        {/* Custom Payloads Inspector Trigger */}
        <div className="flex items-center justify-between px-4 py-2.5 rounded-lg bg-black border border-white/[0.08] text-xs text-zinc-400">
          <div className="flex items-center gap-2">
            <SettingOutlined className="text-xs text-zinc-400" />
            <span>
              {isArabic
                ? 'محرر الحمولات والـ Payloads (42 فحص قياسي)'
                : 'Custom Payload Editor & 42 Canary Suite'}
            </span>
          </div>
          <button
            type="button"
            onClick={onOpenInspector}
            className="text-xs font-semibold px-3 py-1 rounded-md bg-white/[0.08] hover:bg-white/[0.15] text-white border border-white/[0.12] transition-colors cursor-pointer active:scale-95"
          >
            {isArabic ? 'تعديل الأكواد' : 'Edit Probes'}
          </button>
        </div>
      </div>
    </div>
  );
}
