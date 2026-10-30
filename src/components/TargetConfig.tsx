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
const PRESET_URLS = [
  { label: 'Palestine Academy', url: 'https://palestine-international-academy.netlify.app' },
  { label: 'TaskFlow App', url: 'https://taskflow.apps.taqat.academy' },
  { label: 'SEO Opt Portal', url: 'https://seo-opt.apps.taqat.academy' },
];

const STYLES = {
  card: 'rounded-xl border border-white/[0.08] bg-[#0c0c0e] p-4 sm:p-5 space-y-4',
  input:
    'w-full rounded-lg border border-white/[0.08] bg-black px-3.5 py-2.5 text-xs text-white placeholder-zinc-600 focus:border-white/30 focus:outline-none font-mono transition-colors',
  launchBtn:
    'w-full py-2.5 px-4 rounded-lg font-semibold text-xs text-black bg-white hover:bg-zinc-200 transition-colors flex items-center justify-center gap-2 cursor-pointer disabled:opacity-40 select-none',
  abortBtn:
    'w-full py-2.5 px-4 rounded-lg font-semibold text-xs text-red-400 bg-red-500/10 hover:bg-red-500/20 border border-red-500/20 transition-colors flex items-center justify-center gap-2 cursor-pointer select-none',
};

const VECTOR_GROUPS: {
  id: string;
  nameAr: string;
  nameEn: string;
  items: {
    cat: VulnerabilityCategory;
    nameAr: string;
    code: string;
  }[];
}[] = [
  {
    id: 'injection',
    nameAr: 'حقن الأكواد وقواعد البيانات',
    nameEn: 'Code & SQL Injection',
    items: [
      { cat: 'sqli', nameAr: 'حقن قواعد البيانات', code: 'SQLi' },
      { cat: 'xss', nameAr: 'حقن النصوص البرمجية', code: 'XSS' },
      { cat: 'cmd_injection', nameAr: 'أوامر نظام التشغيل', code: 'Command' },
      { cat: 'directory_traversal', nameAr: 'مسارات الملفات', code: 'Traversal' },
    ],
  },
  {
    id: 'auth_access',
    nameAr: 'المصادقة والتحكم بالوصول',
    nameEn: 'Auth & Access Control',
    items: [
      { cat: 'auth', nameAr: 'كسر المصادقة والجلسات', code: 'Auth' },
      { cat: 'idor', nameAr: 'عزل كائنات البيانات', code: 'IDOR' },
      { cat: 'mass_assignment', nameAr: 'التعيين الجماعي للصلاحيات', code: 'MassAssign' },
    ],
  },
  {
    id: 'network_perimeter',
    nameAr: 'الشبكة والجدران النارية',
    nameEn: 'Network & Perimeter',
    items: [
      { cat: 'ssrf', nameAr: 'تزوير طلبات الخادم', code: 'SSRF' },
      { cat: 'headers', nameAr: 'ترويسات الحماية وسياسة الأمان', code: 'Headers' },
      { cat: 'ports', nameAr: 'المنافذ الحساسة المكشوفة', code: 'Ports' },
      { cat: 'cors_leak', nameAr: 'سياسات النطاق المشترك', code: 'CORS' },
      { cat: 'csrf', nameAr: 'تزوير الطلبات المتقاطعة', code: 'CSRF' },
    ],
  },
  {
    id: 'recon_leaks',
    nameAr: 'تسريب البيانات الحساسة',
    nameEn: 'Sensitive Leaks & Recon',
    items: [
      { cat: 'sensitive_files', nameAr: 'ملفات التكوين والبيئة', code: '.env/.git' },
      { cat: 'graphql', nameAr: 'مخططات GraphQL', code: 'GraphQL' },
      { cat: 'rate_limiting', nameAr: 'تقييد الطلبات والصمود', code: 'RateLimit' },
      { cat: 'subdomain', nameAr: 'النطاقات الفرعية', code: 'Subdomain' },
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
    <div className="space-y-3.5">
      {/* 1. Target URL & Scan Trigger */}
      <div className={STYLES.card}>
        <div className="flex items-center justify-between">
          <label className="text-xs font-medium text-zinc-300">
            {isArabic ? 'رابط الموقع أو الواجهة للفحص' : 'Target URL'}
          </label>
          <span className="text-[11px] font-mono text-zinc-500">
            {INTENSITY_PROFILES[intensity].probesCount} tests
          </span>
        </div>

        {/* URL Input */}
        <div className="relative">
          <div className="absolute inset-y-0 start-0 flex items-center ps-3 pointer-events-none text-zinc-500">
            <GlobalOutlined className="text-xs" />
          </div>
          <input
            type="text"
            value={targetUrl}
            onChange={(e) => onTargetUrlChange(e.target.value)}
            placeholder="https://example.com"
            disabled={isRunning}
            className={`${STYLES.input} ps-8`}
            dir="ltr"
          />
        </div>

        {/* Quick Presets */}
        <div className="flex items-center gap-2 flex-wrap text-xs">
          <span className="text-zinc-500">
            {isArabic ? 'أهداف سريعة:' : 'Quick targets:'}
          </span>
          {PRESET_URLS.map((p) => (
            <button
              key={p.url}
              type="button"
              onClick={() => onTargetUrlChange(p.url)}
              disabled={isRunning}
              className="text-zinc-400 hover:text-white transition-colors cursor-pointer underline-offset-2 hover:underline"
            >
              {p.label}
            </button>
          ))}
        </div>

        {/* Scan Action */}
        <div className="pt-1">
          {isRunning ? (
            <button
              type="button"
              onClick={onAbortAudit}
              className={STYLES.abortBtn}
            >
              <StopOutlined className="text-xs" />
              <span>{isArabic ? 'إيقاف الفحص المباشر' : 'Abort Audit'}</span>
            </button>
          ) : (
            <button
              type="button"
              onClick={onStartAudit}
              disabled={!targetUrl.trim()}
              className={STYLES.launchBtn}
            >
              <PlayCircleOutlined className="text-xs" />
              <span>{isArabic ? 'بدء فحص الأمان الشامل' : 'Start Security Audit'}</span>
            </button>
          )}
        </div>
      </div>

      {/* 2. Attack Profile & Speed Configuration */}
      <div className={STYLES.card}>
        <div className="space-y-1.5">
          <div className="flex items-center justify-between text-xs text-zinc-400">
            <span>{isArabic ? 'مستوى شدة الفحص' : 'Audit Intensity'}</span>
            <span className="font-mono text-zinc-500">
              {INTENSITY_PROFILES[intensity].probesCount} probes
            </span>
          </div>

          <div className="grid grid-cols-3 gap-1 bg-black p-1 rounded-lg border border-white/[0.08]">
            {(['gentle', 'standard', 'rigorous'] as AttackIntensity[]).map((lvl) => {
              const prof = INTENSITY_PROFILES[lvl];
              const isSelected = intensity === lvl;
              return (
                <button
                  key={lvl}
                  type="button"
                  onClick={() => onIntensityChange(lvl)}
                  disabled={isRunning}
                  className={`py-1.5 px-2 rounded-md text-xs transition-colors cursor-pointer flex items-center justify-center gap-1 ${
                    isSelected
                      ? 'bg-white/[0.1] text-white font-medium'
                      : 'text-zinc-500 hover:text-zinc-300'
                  }`}
                >
                  <span>{isArabic ? prof.labelAr.split(' ')[0] : prof.labelEn.split(' ')[0]}</span>
                  <span className="font-mono text-[10px] opacity-60">({prof.probesCount})</span>
                </button>
              );
            })}
          </div>
        </div>

        {/* Concurrency & Pacing */}
        <div className="grid grid-cols-2 gap-3 pt-1 border-t border-white/[0.06]">
          {/* Concurrency */}
          <div className="space-y-1">
            <div className="flex items-center justify-between text-[11px] text-zinc-500">
              <span>{isArabic ? 'التزامن:' : 'Workers:'}</span>
              <span className="font-mono text-zinc-300">{concurrency}x</span>
            </div>
            <div className="grid grid-cols-4 gap-1 bg-black p-0.5 rounded border border-white/[0.08]">
              {[1, 2, 4, 8].map((t) => (
                <button
                  key={t}
                  type="button"
                  onClick={() => onConcurrencyChange(t)}
                  disabled={isRunning}
                  className={`py-1 rounded font-mono text-[11px] transition-colors cursor-pointer ${
                    concurrency === t
                      ? 'bg-white/[0.1] text-white font-medium'
                      : 'text-zinc-500 hover:text-zinc-300'
                  }`}
                >
                  {t}x
                </button>
              ))}
            </div>
          </div>

          {/* Delay */}
          <div className="space-y-1">
            <div className="flex items-center justify-between text-[11px] text-zinc-500">
              <span>{isArabic ? 'المهلة:' : 'Delay:'}</span>
              <span className="font-mono text-zinc-300">{delayMs}ms</span>
            </div>
            <div className="grid grid-cols-4 gap-1 bg-black p-0.5 rounded border border-white/[0.08]">
              {[0, 50, 150, 350].map((d) => (
                <button
                  key={d}
                  type="button"
                  onClick={() => onDelayMsChange(d)}
                  disabled={isRunning}
                  className={`py-1 rounded font-mono text-[11px] transition-colors cursor-pointer ${
                    delayMs === d
                      ? 'bg-white/[0.1] text-white font-medium'
                      : 'text-zinc-500 hover:text-zinc-300'
                  }`}
                >
                  {d}m
                </button>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* 3. Security Vector Matrix */}
      <div className={STYLES.card}>
        <div className="flex items-center justify-between pb-1 border-b border-white/[0.06]">
          <div className="flex items-center gap-2">
            <span className="text-xs font-medium text-white">
              {isArabic ? 'نطاقات الفحص الأمني' : 'Security Probes'}
            </span>
            <span className="font-mono text-[11px] text-zinc-500">
              {totalEnabled}/16
            </span>
          </div>

          <div className="flex items-center gap-2 text-xs">
            <button
              type="button"
              onClick={() => handleToggleAll(true)}
              disabled={isRunning || isAllEnabled}
              className="text-zinc-400 hover:text-white transition-colors cursor-pointer disabled:opacity-30"
            >
              {isArabic ? 'تحديد الكل' : 'Select all'}
            </button>
            <span className="text-zinc-700">·</span>
            <button
              type="button"
              onClick={() => handleToggleAll(false)}
              disabled={isRunning || totalEnabled === 0}
              className="text-zinc-400 hover:text-white transition-colors cursor-pointer disabled:opacity-30"
            >
              {isArabic ? 'إلغاء' : 'Clear'}
            </button>
          </div>
        </div>

        {/* Vectors List */}
        <div className="space-y-3">
          {VECTOR_GROUPS.map((sec) => (
            <div key={sec.id} className="space-y-1">
              <span className="text-[10px] font-medium text-zinc-500 block">
                {isArabic ? sec.nameAr : sec.nameEn}
              </span>

              <div className="space-y-0.5">
                {sec.items.map((item) => {
                  const isEnabled = enabledCategories[item.cat];
                  return (
                    <button
                      key={item.cat}
                      type="button"
                      onClick={() => onToggleCategory(item.cat)}
                      disabled={isRunning}
                      className="w-full py-1.5 px-2 rounded hover:bg-white/[0.04] text-start flex items-center justify-between transition-colors cursor-pointer select-none"
                    >
                      <div className="flex items-center gap-2">
                        <div
                          className={`w-3.5 h-3.5 rounded-sm border flex items-center justify-center shrink-0 ${
                            isEnabled
                              ? 'bg-white border-white text-black'
                              : 'border-zinc-700 bg-transparent'
                          }`}
                        >
                          {isEnabled && <CheckOutlined className="text-[8px] font-bold" />}
                        </div>
                        <span className={`text-xs ${isEnabled ? 'text-zinc-200' : 'text-zinc-600'}`}>
                          {isArabic ? item.nameAr : item.code}
                        </span>
                      </div>

                      <span className="font-mono text-[10px] text-zinc-600">
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

      {/* 4. Automated API Discovery Drawer */}
      <div className="rounded-xl border border-white/[0.08] bg-[#0c0c0e] overflow-hidden">
        <button
          type="button"
          onClick={() => setShowApiDiscovery(!showApiDiscovery)}
          className="w-full p-4 flex items-center justify-between text-start cursor-pointer hover:bg-white/[0.02] transition-colors"
        >
          <div className="flex items-center gap-2">
            <ApiOutlined className="text-xs text-zinc-400" />
            <span className="text-xs font-medium text-white">
              {isArabic ? 'مستكشف نهايات الـ API الحقيقية' : 'Real API Discovery'}
            </span>
            <span className="font-mono text-[10px] text-zinc-500">
              {endpoints.length} routes
            </span>
          </div>
          <div className="text-xs text-zinc-500">
            {showApiDiscovery ? <UpOutlined /> : <DownOutlined />}
          </div>
        </button>

        {showApiDiscovery && (
          <div className="p-4 pt-0 border-t border-white/[0.06]">
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

      {/* 5. Custom Payloads Inspector */}
      <div className="rounded-xl border border-white/[0.08] bg-[#0c0c0e] p-3 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <SettingOutlined className="text-xs text-zinc-400" />
          <span className="text-xs text-zinc-400">
            {isArabic ? 'محرر الحمولات والـ Payloads' : 'Payloads Inspector'}
          </span>
        </div>
        <button
          type="button"
          onClick={onOpenInspector}
          className="text-xs px-2.5 py-1 rounded bg-white/[0.04] hover:bg-white/[0.08] text-zinc-300 hover:text-white border border-white/[0.08] transition-colors cursor-pointer"
        >
          {isArabic ? 'تعديل الأكواد' : 'Edit Probes'}
        </button>
      </div>
    </div>
  );
}
