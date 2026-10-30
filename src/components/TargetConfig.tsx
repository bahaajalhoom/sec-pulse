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
import * as DropdownMenu from '@radix-ui/react-dropdown-menu';
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
const PRESET_TARGETS = [
  {
    nameAr: 'أكاديمية فلسطين الدولية',
    nameEn: 'Palestine International Academy',
    url: 'https://palestine-international-academy.netlify.app',
    category: 'E-Learning Portal',
  },
  {
    nameAr: 'تطبيق تاسك فلو لإدارة المهام',
    nameEn: 'TaskFlow SaaS Platform',
    url: 'https://taskflow.apps.taqat.academy',
    category: 'SaaS Web Application',
  },
  {
    nameAr: 'بوابة تحسين محركات البحث الذكية',
    nameEn: 'SEO Opt Portal',
    url: 'https://seo-opt.apps.taqat.academy',
    category: 'Analytics Dashboard',
  },
];

const STYLES = {
  card: 'rounded-xl border border-white/[0.1] bg-[#0c0c0e] p-4 sm:p-5 space-y-4',
  input:
    'w-full rounded-lg border border-white/[0.1] bg-black px-3.5 py-2.5 text-xs text-white placeholder-zinc-500 focus:border-white/40 focus:outline-none font-mono transition-colors',
  primaryLaunchBtn:
    'w-full py-2.5 px-5 rounded-lg font-bold text-xs text-black bg-white hover:bg-zinc-200 transition-all flex items-center justify-center gap-2 cursor-pointer disabled:opacity-40 select-none shadow-md active:scale-[0.99]',
  abortBtn:
    'w-full py-2.5 px-5 rounded-lg font-bold text-xs text-red-300 bg-red-500/20 hover:bg-red-500/30 border border-red-500/40 transition-all flex items-center justify-center gap-2 cursor-pointer select-none shadow-md active:scale-[0.99]',
};

// Grouped vectors with icons
const VECTOR_GROUPS: {
  id: string;
  nameAr: string;
  nameEn: string;
  items: {
    cat: VulnerabilityCategory;
    nameAr: string;
    code: string;
    icon: React.ReactNode;
  }[];
}[] = [
  {
    id: 'injection',
    nameAr: 'حقن الأكواد وقواعد البيانات (Injection)',
    nameEn: 'Code & SQL Injection Canaries',
    items: [
      { cat: 'sqli', nameAr: 'حقن قواعد البيانات', code: 'SQLi', icon: <DatabaseOutlined /> },
      { cat: 'xss', nameAr: 'حقن النصوص البرمجية', code: 'XSS', icon: <CodeOutlined /> },
      { cat: 'cmd_injection', nameAr: 'أوامر نظام التشغيل', code: 'RCE', icon: <DesktopOutlined /> },
      { cat: 'directory_traversal', nameAr: 'التنقل في مسارات الملفات', code: 'LFI', icon: <FolderOpenOutlined /> },
    ],
  },
  {
    id: 'auth_access',
    nameAr: 'المصادقة والتحكم بالوصول (Auth)',
    nameEn: 'Authentication & Access Control',
    items: [
      { cat: 'auth', nameAr: 'كسر المصادقة وإدارة الجلسات', code: 'Auth', icon: <KeyOutlined /> },
      { cat: 'idor', nameAr: 'كسر عزل كائنات البيانات', code: 'IDOR', icon: <LockOutlined /> },
      { cat: 'mass_assignment', nameAr: 'التعيين الجماعي للصلاحيات', code: 'MassAssign', icon: <ControlOutlined /> },
    ],
  },
  {
    id: 'network_perimeter',
    nameAr: 'الشبكة والجدران النارية (Network & Headers)',
    nameEn: 'Network & Perimeter Security',
    items: [
      { cat: 'ssrf', nameAr: 'تزوير طلبات جانب الخادم', code: 'SSRF', icon: <ApiOutlined /> },
      { cat: 'headers', nameAr: 'ترويسات الحماية وسياسة الأمان', code: 'Headers', icon: <SafetyCertificateOutlined /> },
      { cat: 'ports', nameAr: 'المنافذ الحساسة المكشوفة', code: 'Ports', icon: <CloudServerOutlined /> },
      { cat: 'cors_leak', nameAr: 'تسريب سياسات النطاق المشترك', code: 'CORS', icon: <ShareAltOutlined /> },
      { cat: 'csrf', nameAr: 'حماية تزوير الطلبات المتقاطعة', code: 'CSRF', icon: <SafetyOutlined /> },
    ],
  },
  {
    id: 'recon_leaks',
    nameAr: 'تسريب البيانات الحساسة (Leaks & Recon)',
    nameEn: 'Sensitive Leaks & Infrastructure',
    items: [
      { cat: 'sensitive_files', nameAr: 'ملفات التكوين والبيئة (.env)', code: '.env/.git', icon: <FileTextOutlined /> },
      { cat: 'graphql', nameAr: 'كشف مخططات واستعلامات GraphQL', code: 'GraphQL', icon: <ClusterOutlined /> },
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
    <div className="space-y-4">
      {/* 1. Target URL Omnibar */}
      <div className={STYLES.card}>
        <div className="flex items-center justify-between">
          <label className="text-xs font-semibold text-white flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-emerald-400" />
            <span>{isArabic ? 'رابط الموقع أو الواجهة المستهدفة' : 'Target Application URL'}</span>
          </label>

          {/* Radix Dropdown Menu for Target Presets */}
          <DropdownMenu.Root>
            <DropdownMenu.Trigger asChild>
              <button
                type="button"
                className="flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-medium text-zinc-300 hover:text-white bg-white/[0.06] hover:bg-white/[0.12] border border-white/[0.12] transition-colors cursor-pointer select-none"
              >
                <span>{isArabic ? 'نماذج جاهزة للفحص' : 'Preset Targets'}</span>
                <DownOutlined className="text-[10px]" />
              </button>
            </DropdownMenu.Trigger>

            <DropdownMenu.Portal>
              <DropdownMenu.Content
                className="z-50 min-w-[280px] rounded-xl bg-[#141416] p-1.5 shadow-2xl border border-white/[0.15] text-xs text-zinc-300 font-sans animate-in fade-in-50 zoom-in-95"
                sideOffset={6}
                align="end"
              >
                <div className="px-2.5 py-1.5 text-[11px] font-semibold text-zinc-500 uppercase tracking-wider">
                  {isArabic ? 'اختر موقعاً للتجربة المباشرة' : 'Select a live testing target'}
                </div>

                {PRESET_TARGETS.map((t) => (
                  <DropdownMenu.Item
                    key={t.url}
                    onClick={() => onTargetUrlChange(t.url)}
                    className="flex flex-col gap-0.5 px-3 py-2 rounded-lg cursor-pointer hover:bg-white/[0.08] hover:text-white outline-none transition-colors"
                  >
                    <span className="font-semibold text-white">
                      {isArabic ? t.nameAr : t.nameEn}
                    </span>
                    <span className="text-[11px] text-zinc-500 font-mono truncate" dir="ltr">
                      {t.url}
                    </span>
                  </DropdownMenu.Item>
                ))}
              </DropdownMenu.Content>
            </DropdownMenu.Portal>
          </DropdownMenu.Root>
        </div>

        {/* URL Input */}
        <div className="relative">
          <div className="absolute inset-y-0 start-0 flex items-center ps-3 pointer-events-none text-zinc-400">
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

        {/* Quick Presets Buttons (Tactile and apparent) */}
        <div className="flex items-center gap-1.5 flex-wrap">
          {PRESET_TARGETS.map((p) => (
            <button
              key={p.url}
              type="button"
              onClick={() => onTargetUrlChange(p.url)}
              disabled={isRunning}
              className="flex items-center gap-1 px-2.5 py-1 rounded-md text-xs font-medium text-zinc-300 hover:text-white bg-white/[0.05] hover:bg-white/[0.1] border border-white/[0.1] transition-all cursor-pointer select-none active:scale-95"
            >
              <span>{isArabic ? p.nameAr.split(' ')[0] : p.nameEn.split(' ')[0]}</span>
            </button>
          ))}
        </div>

        {/* Launch / Abort Action */}
        <div className="pt-1">
          {isRunning ? (
            <button
              type="button"
              onClick={onAbortAudit}
              className={STYLES.abortBtn}
            >
              <StopOutlined className="text-xs" />
              <span>{isArabic ? 'إيقاف الفحص المباشر' : 'Abort Audit Stream'}</span>
            </button>
          ) : (
            <button
              type="button"
              onClick={onStartAudit}
              disabled={!targetUrl.trim()}
              className={STYLES.primaryLaunchBtn}
            >
              <PlayCircleOutlined className="text-sm" />
              <span>{isArabic ? 'بدء فحص الأمان الشامل' : 'Start Full Security Audit'}</span>
              <span className="font-mono text-[11px] px-2 py-0.5 rounded bg-black/10 text-black">
                {INTENSITY_PROFILES[intensity].probesCount} Probes
              </span>
            </button>
          )}
        </div>
      </div>

      {/* 2. Attack Profile & Pacing Bar */}
      <div className={STYLES.card}>
        <div className="space-y-2">
          <div className="flex items-center justify-between text-xs">
            <span className="font-semibold text-white flex items-center gap-1.5">
              <ThunderboltOutlined className="text-xs text-zinc-400" />
              <span>{isArabic ? 'مستوى شدة الهجوم:' : 'Audit Profile:'}</span>
            </span>
            <span className="font-mono text-zinc-400 text-[11px]">
              {INTENSITY_PROFILES[intensity].probesCount} Probes Active
            </span>
          </div>

          {/* Segmented Intensity Switcher */}
          <div className="grid grid-cols-3 gap-1.5 bg-black p-1 rounded-lg border border-white/[0.1]">
            {(['gentle', 'standard', 'rigorous'] as AttackIntensity[]).map((lvl) => {
              const prof = INTENSITY_PROFILES[lvl];
              const isSelected = intensity === lvl;
              return (
                <button
                  key={lvl}
                  type="button"
                  onClick={() => onIntensityChange(lvl)}
                  disabled={isRunning}
                  className={`py-2 px-2.5 rounded-md text-xs font-medium transition-all cursor-pointer flex flex-col items-center justify-center gap-0.5 ${
                    isSelected
                      ? 'bg-white text-black font-bold shadow-sm'
                      : 'text-zinc-400 hover:text-white hover:bg-white/[0.04]'
                  }`}
                >
                  <span className="text-xs">{isArabic ? prof.labelAr.split(' ')[0] : prof.labelEn.split(' ')[0]}</span>
                  <span className="font-mono text-[10px] opacity-75">({prof.probesCount} فحص)</span>
                </button>
              );
            })}
          </div>
        </div>

        {/* Concurrency & Pacing Segmented Controls */}
        <div className="grid grid-cols-2 gap-3 pt-1 border-t border-white/[0.08]">
          {/* Concurrency */}
          <div className="space-y-1.5">
            <div className="flex items-center justify-between text-[11px] text-zinc-400">
              <span>{isArabic ? 'التزامن (Workers):' : 'Concurrency:'}</span>
              <span className="font-mono text-white font-semibold">{concurrency}x</span>
            </div>
            <div className="grid grid-cols-4 gap-1 bg-black p-1 rounded-md border border-white/[0.08]">
              {[1, 2, 4, 8].map((t) => (
                <button
                  key={t}
                  type="button"
                  onClick={() => onConcurrencyChange(t)}
                  disabled={isRunning}
                  className={`py-1 rounded font-mono text-xs transition-all cursor-pointer ${
                    concurrency === t
                      ? 'bg-white text-black font-bold'
                      : 'text-zinc-400 hover:text-white'
                  }`}
                >
                  {t}x
                </button>
              ))}
            </div>
          </div>

          {/* Delay */}
          <div className="space-y-1.5">
            <div className="flex items-center justify-between text-[11px] text-zinc-400">
              <span>{isArabic ? 'المهلة بين الحزم:' : 'Packet Delay:'}</span>
              <span className="font-mono text-white font-semibold">{delayMs}ms</span>
            </div>
            <div className="grid grid-cols-4 gap-1 bg-black p-1 rounded-md border border-white/[0.08]">
              {[0, 50, 150, 350].map((d) => (
                <button
                  key={d}
                  type="button"
                  onClick={() => onDelayMsChange(d)}
                  disabled={isRunning}
                  className={`py-1 rounded font-mono text-xs transition-all cursor-pointer ${
                    delayMs === d
                      ? 'bg-white text-black font-bold'
                      : 'text-zinc-400 hover:text-white'
                  }`}
                >
                  {d}m
                </button>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* 3. Security Vector Matrix with CLEAR APPARENT BUTTONS */}
      <div className={STYLES.card}>
        <div className="flex items-center justify-between pb-2 border-b border-white/[0.08]">
          <div className="flex items-center gap-2">
            <SlidersOutlined className="text-xs text-zinc-400" />
            <span className="text-xs font-bold text-white">
              {isArabic ? 'نطاقات الفحص الأمني' : 'Security Attack Vectors'}
            </span>
            <span className="font-mono text-[11px] text-zinc-400">
              ({totalEnabled} / 16)
            </span>
          </div>

          {/* REAL, PROMINENT BUTTONS FOR SELECT ALL / CLEAR ALL */}
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={() => handleToggleAll(true)}
              disabled={isRunning}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition-all cursor-pointer shadow-sm active:scale-95 ${
                isAllEnabled
                  ? 'bg-white text-black border border-white'
                  : 'bg-white/[0.08] hover:bg-white/[0.16] text-white border border-white/[0.2]'
              }`}
            >
              <CheckSquareOutlined className={isAllEnabled ? 'text-black text-xs' : 'text-emerald-400 text-xs'} />
              <span>{isArabic ? 'تحديد الكل' : 'Select All'}</span>
            </button>

            <button
              type="button"
              onClick={() => handleToggleAll(false)}
              disabled={isRunning || totalEnabled === 0}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold text-zinc-300 hover:text-white bg-white/[0.06] hover:bg-white/[0.12] border border-white/[0.18] transition-all cursor-pointer disabled:opacity-30 active:scale-95 shadow-sm"
            >
              <CloseSquareOutlined className="text-xs text-zinc-400" />
              <span>{isArabic ? 'إلغاء التحديد' : 'Clear All'}</span>
            </button>
          </div>
        </div>

        {/* Vectors List */}
        <div className="space-y-3.5">
          {VECTOR_GROUPS.map((sec) => (
            <div key={sec.id} className="space-y-1.5">
              <span className="text-[11px] font-bold text-zinc-400 block pb-0.5">
                {isArabic ? sec.nameAr : sec.nameEn}
              </span>

              <div className="space-y-1">
                {sec.items.map((item) => {
                  const isEnabled = enabledCategories[item.cat];
                  return (
                    <button
                      key={item.cat}
                      type="button"
                      onClick={() => onToggleCategory(item.cat)}
                      disabled={isRunning}
                      className={`w-full py-2 px-3 rounded-lg border text-start flex items-center justify-between transition-all cursor-pointer select-none ${
                        isEnabled
                          ? 'bg-white/[0.06] border-white/[0.15] text-white hover:bg-white/[0.09]'
                          : 'bg-black border-white/[0.05] text-zinc-500 hover:text-zinc-300 hover:border-white/[0.1]'
                      }`}
                    >
                      <div className="flex items-center gap-2.5">
                        <div
                          className={`w-4 h-4 rounded border flex items-center justify-center shrink-0 transition-colors ${
                            isEnabled
                              ? 'bg-white border-white text-black'
                              : 'border-zinc-600 bg-transparent'
                          }`}
                        >
                          {isEnabled && <CheckOutlined className="text-[9px] font-bold" />}
                        </div>
                        <span className="text-xs font-medium">
                          {isArabic ? item.nameAr : item.code}
                        </span>
                      </div>

                      <span className="font-mono text-[10px] text-zinc-400 bg-black/40 px-1.5 py-0.5 rounded border border-white/[0.05]">
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
      <div className="rounded-xl border border-white/[0.1] bg-[#0c0c0e] overflow-hidden">
        <button
          type="button"
          onClick={() => setShowApiDiscovery(!showApiDiscovery)}
          className="w-full p-4 flex items-center justify-between text-start cursor-pointer hover:bg-white/[0.04] transition-colors"
        >
          <div className="flex items-center gap-2">
            <ApiOutlined className="text-xs text-zinc-300" />
            <span className="text-xs font-bold text-white">
              {isArabic ? 'مستكشف نهايات الـ API الحقيقية' : 'Real API Discovery Engine'}
            </span>
            <span className="font-mono text-[10px] px-2 py-0.5 rounded bg-white/[0.06] border border-white/[0.1] text-zinc-300">
              {endpoints.length} routes
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

      {/* 5. Custom Payloads Inspector */}
      <div className="rounded-xl border border-white/[0.1] bg-[#0c0c0e] p-3.5 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <SettingOutlined className="text-xs text-zinc-300" />
          <span className="text-xs font-semibold text-white">
            {isArabic ? 'محرر الحمولات والـ Payloads (42 فحص)' : '42 Security Probes Inspector'}
          </span>
        </div>
        <button
          type="button"
          onClick={onOpenInspector}
          className="text-xs font-medium px-3 py-1.5 rounded-lg bg-white/[0.08] hover:bg-white/[0.14] text-white border border-white/[0.15] transition-all cursor-pointer shadow-sm active:scale-95"
        >
          {isArabic ? 'تعديل الأكواد' : 'Edit Probes'}
        </button>
      </div>
    </div>
  );
}
