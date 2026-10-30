'use client';

// ============================================================================
// 1. IMPORTS
// ============================================================================
import React, { useState, useRef, useCallback } from 'react';
import Header from '@/components/Header';
import TargetConfig from '@/components/TargetConfig';
import PayloadInspectorModal from '@/components/PayloadInspectorModal';
import LiveTelemetryConsole from '@/components/LiveTelemetryConsole';
import FindingsSummary from '@/components/FindingsSummary';
import DefenseRecipesModal from '@/components/DefenseRecipesModal';
import {
  AttackIntensity,
  AuditReport,
  DiscoveredEndpoint,
  LiveTelemetryEvent,
  SecurityProbePayload,
  VulnerabilityCategory,
} from '@/types/security';
import { INITIAL_PROBES } from '@/lib/constants';
import { normalizeTargetUrl } from '@/lib/security-engine';
import {
  CodeOutlined,
  SafetyCertificateOutlined,
  SyncOutlined,
  AppstoreOutlined,
} from '@ant-design/icons';

// ============================================================================
// 2. CONFIGURATION & CONSTANTS (EASY EDIT ZONE)
// ============================================================================
const DEFAULT_CONFIG = {
  initialTargetUrl: 'https://palestine-international-academy.netlify.app',
  defaultIntensity: 'rigorous' as AttackIntensity,
  defaultConcurrency: 4,
  defaultDelayMs: 40,
};

const DEFAULT_CATEGORIES: Record<VulnerabilityCategory, boolean> = {
  sqli: true,
  xss: true,
  auth: true,
  ports: true,
  subdomain: true,
  headers: true,
  ssrf: true,
  idor: true,
  sensitive_files: true,
  rate_limiting: true,
  cmd_injection: true,
  cors_leak: true,
  csrf: true,
  graphql: true,
  directory_traversal: true,
  mass_assignment: true,
};

type ResultViewMode = 'telemetry' | 'report' | 'both';

// ============================================================================
// 6. MAIN COMPONENT (ZONE 6)
// ============================================================================
export default function HomePage() {
  // --- UI & Language State ---
  const [lang, setLang] = useState<'ar' | 'en'>('ar');
  const isArabic = lang === 'ar';
  const [resultView, setResultView] = useState<ResultViewMode>('both');

  // --- Configuration State ---
  const [targetUrl, setTargetUrl] = useState(DEFAULT_CONFIG.initialTargetUrl);
  const [apiBaseUrl, setApiBaseUrl] = useState('');
  const [endpoints, setEndpoints] = useState<DiscoveredEndpoint[]>([]);
  const [intensity, setIntensity] = useState<AttackIntensity>(DEFAULT_CONFIG.defaultIntensity);
  const [concurrency, setConcurrency] = useState(DEFAULT_CONFIG.defaultConcurrency);
  const [delayMs, setDelayMs] = useState(DEFAULT_CONFIG.defaultDelayMs);
  const [enabledCategories, setEnabledCategories] = useState(DEFAULT_CATEGORIES);

  // --- Probes Catalog ---
  const [probes, setProbes] = useState<SecurityProbePayload[]>(INITIAL_PROBES);

  // --- Modals State ---
  const [isInspectorOpen, setIsInspectorOpen] = useState(false);
  const [isRecipesOpen, setIsRecipesOpen] = useState(false);

  // --- Execution & Telemetry State ---
  const [isRunning, setIsRunning] = useState(false);
  const [telemetryEvents, setTelemetryEvents] = useState<LiveTelemetryEvent[]>([]);
  const [auditReport, setAuditReport] = useState<AuditReport | null>(null);

  // Abort controller ref & live results section ref
  const abortControllerRef = useRef<AbortController | null>(null);
  const resultsRef = useRef<HTMLDivElement>(null);

  // Ensure page always starts at top on initial mount / refresh
  React.useEffect(() => {
    if (typeof window !== 'undefined') {
      window.scrollTo(0, 0);
      if ('scrollRestoration' in window.history) {
        window.history.scrollRestoration = 'manual';
      }
    }
  }, []);

  // --- Handlers: Category & Probes Management ---
  function handleToggleCategory(cat: VulnerabilityCategory) {
    setEnabledCategories((prev) => ({ ...prev, [cat]: !prev[cat] }));
  }

  function handleSaveProbes(updated: SecurityProbePayload[]) {
    setProbes(updated);
  }

  function handleResetDefaultProbes() {
    setProbes(INITIAL_PROBES);
  }

  function handleToggleLang() {
    setLang((prev) => (prev === 'ar' ? 'en' : 'ar'));
  }

  // --- Handlers: Live Audit Execution ---
  const handleStartAudit = useCallback(async () => {
    const cleanUrl = normalizeTargetUrl(targetUrl);
    setTargetUrl(cleanUrl);

    const hasCategory = Object.values(enabledCategories).some(Boolean);
    if (!hasCategory) {
      alert(
        isArabic
          ? 'يرجى تفعيل نطاق أمني واحد على الأقل قبل بدء الفحص!'
          : 'Please enable at least one security module before launching!'
      );
      return;
    }

    setIsRunning(true);
    setTelemetryEvents([]);
    setAuditReport(null);

    // Smoothly scroll down to live results when the test starts
    setTimeout(() => {
      resultsRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }, 100);

    const abortController = new AbortController();
    abortControllerRef.current = abortController;

    try {
      const response = await fetch('/api/audit?stream=true', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          targetUrl: cleanUrl,
          apiBaseUrl: apiBaseUrl.trim() || undefined,
          intensity,
          concurrency,
          delayMs,
          enabledCategories,
          customPayloads: probes,
          endpointsToTest: endpoints.filter((e) => e.selected),
        }),
        signal: abortController.signal,
      });

      if (!response.ok || !response.body) {
        throw new Error(`Server returned ${response.status}`);
      }

      const reader = response.body.getReader();
      const decoder = new TextDecoder('utf-8');
      let buffer = '';

      while (true) {
        const { value, done } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split('\n\n');
        buffer = lines.pop() || '';

        for (const line of lines) {
          const trimmed = line.trim();
          if (trimmed.startsWith('data: ')) {
            try {
              const payload = JSON.parse(trimmed.slice(6));
              if (payload.type === 'event' && payload.event) {
                setTelemetryEvents((prev) => [...prev, payload.event]);
              } else if (payload.type === 'report' && payload.report) {
                setAuditReport(payload.report);
              }
            } catch {
              // Ignore malformed chunks
            }
          }
        }
      }
    } catch (err: unknown) {
      if (err instanceof Error && err.name !== 'AbortError') {
        alert(
          isArabic
            ? `حدث خطأ أثناء الاتصال بالخادم: ${err.message}`
            : `Audit error: ${err.message}`
        );
      }
    } finally {
      setIsRunning(false);
      abortControllerRef.current = null;
    }
  }, [
    targetUrl,
    apiBaseUrl,
    endpoints,
    probes,
    enabledCategories,
    concurrency,
    delayMs,
    intensity,
    isArabic,
  ]);

  function handleAbortAudit() {
    if (abortControllerRef.current) {
      abortControllerRef.current.abort();
    }
    setIsRunning(false);
  }

  function handleClearLogs() {
    setTelemetryEvents([]);
  }

  return (
    <div
      className={`min-h-screen bg-black text-zinc-200 flex flex-col font-sans selection:bg-white selection:text-black ${
        isArabic ? 'rtl' : 'ltr'
      }`}
      dir={isArabic ? 'rtl' : 'ltr'}
    >
      {/* 1. Top Executive Navigation Bar */}
      <Header
        lang={lang}
        onToggleLang={handleToggleLang}
        onOpenRecipes={() => setIsRecipesOpen(true)}
        isRunning={isRunning}
        score={auditReport ? auditReport.score : null}
      />

      {/* 2. Main Workstation Area (Full Width Spacious Architecture) */}
      <main className="flex-1 max-w-[1360px] w-full mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8">
        {/* Hero Section */}
        <div className="space-y-3">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-md bg-white/[0.06] border border-white/[0.1] text-xs font-mono text-zinc-300">
            <span className="w-2 h-2 rounded-full bg-blue-400" />
            <span>
              {isArabic
                ? 'محرك الفحص الشبكي الحي v3.5 • 42 اختبار أمان قياسي مع استكشاف الـ API'
                : 'Real Network Threat Auditor v3.5 • 42 Probes & Live API Discovery'}
            </span>
          </div>

          <h1 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">
            {isArabic
              ? 'فحص أمان موقعك ونهايات الـ API الحقيقية'
              : 'Audit Real Web & API Endpoints Under Live Threat Probing'}
          </h1>

          <p className="text-xs sm:text-sm text-zinc-400 max-w-3xl leading-relaxed">
            {isArabic
              ? 'المنصة لا تخمن مسارات وهمية! تكتشف نهايات الـ API تلقائياً من كود موقعك (أو تتيح لك كتابة مسار API منفصل)، ثم تنفذ اختبارات حقيقية على تلك النهايات للتأكد من حمايتها وترويساتها.'
              : 'No synthetic mocks! Discovers real endpoints from your JavaScript client bundles or custom API servers, then tests them with safe payloads for injection, auth bypasses, and leaks.'}
          </p>
        </div>

        {/* 3. Target & Threat Configuration Cockpit (Full Width) */}
        <TargetConfig
          targetUrl={targetUrl}
          onTargetUrlChange={setTargetUrl}
          apiBaseUrl={apiBaseUrl}
          onApiBaseUrlChange={setApiBaseUrl}
          endpoints={endpoints}
          onEndpointsChange={setEndpoints}
          intensity={intensity}
          onIntensityChange={setIntensity}
          concurrency={concurrency}
          onConcurrencyChange={setConcurrency}
          delayMs={delayMs}
          onDelayMsChange={setDelayMs}
          enabledCategories={enabledCategories}
          onToggleCategory={handleToggleCategory}
          onOpenInspector={() => setIsInspectorOpen(true)}
          onStartAudit={handleStartAudit}
          onAbortAudit={handleAbortAudit}
          isRunning={isRunning}
          lang={lang}
        />

        {/* 4. Results Section Header & View Mode Switcher */}
        <div ref={resultsRef} className="pt-4 space-y-4">
          <div className="flex items-center justify-between flex-wrap gap-3 pb-2 border-b border-white/[0.1]">
            <div className="flex items-center gap-2 bg-[#0c0c0e] p-1.5 rounded-xl border border-white/[0.1]">
              {/* Tab 1: Live Telemetry */}
              <button
                type="button"
                onClick={() => setResultView('telemetry')}
                className={`flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-semibold transition-all cursor-pointer ${
                  resultView === 'telemetry'
                    ? 'bg-white text-black shadow-sm'
                    : 'text-zinc-400 hover:text-white hover:bg-white/[0.04]'
                }`}
              >
                {isRunning ? (
                  <SyncOutlined spin className="text-xs text-amber-500" />
                ) : (
                  <CodeOutlined className="text-xs" />
                )}
                <span>{isArabic ? 'سجل الرصد الحي' : 'Live Telemetry'}</span>
                {telemetryEvents.length > 0 && (
                  <span className="font-mono text-[10px] opacity-75">
                    ({telemetryEvents.length})
                  </span>
                )}
              </button>

              {/* Tab 2: Findings Summary */}
              <button
                type="button"
                onClick={() => setResultView('report')}
                className={`flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-semibold transition-all cursor-pointer ${
                  resultView === 'report'
                    ? 'bg-white text-black shadow-sm'
                    : 'text-zinc-400 hover:text-white hover:bg-white/[0.04]'
                }`}
              >
                <SafetyCertificateOutlined className="text-xs" />
                <span>{isArabic ? 'تقرير الثغرات والحلول' : 'Findings & AI Fixes'}</span>
                {auditReport && (
                  <span
                    className={`font-mono font-bold text-[10px] px-1.5 py-0.2 rounded ${
                      auditReport.score >= 80
                        ? 'bg-emerald-500/20 text-emerald-400'
                        : auditReport.score >= 60
                        ? 'bg-amber-500/20 text-amber-400'
                        : 'bg-red-500/20 text-red-400'
                    }`}
                  >
                    {auditReport.score}/100
                  </span>
                )}
              </button>

              {/* Tab 3: Show Both Stacked */}
              <button
                type="button"
                onClick={() => setResultView('both')}
                className={`flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-semibold transition-all cursor-pointer ${
                  resultView === 'both'
                    ? 'bg-white text-black shadow-sm'
                    : 'text-zinc-400 hover:text-white hover:bg-white/[0.04]'
                }`}
              >
                <AppstoreOutlined className="text-xs" />
                <span>{isArabic ? 'عرض متكامل (كلاهما)' : 'Show Both'}</span>
              </button>
            </div>

            {/* Status Ticker */}
            <div className="flex items-center gap-3 text-xs font-mono">
              {isRunning ? (
                <div className="flex items-center gap-2 px-3 py-1 rounded-md bg-amber-500/10 border border-amber-500/30 text-amber-300">
                  <span className="w-2 h-2 rounded-full bg-amber-400 animate-ping" />
                  <span>{isArabic ? 'جاري الفحص المباشر عبر الشبكة...' : 'LIVE PROBING IN PROGRESS'}</span>
                </div>
              ) : auditReport ? (
                <div className="flex items-center gap-2 px-3 py-1 rounded-md bg-emerald-500/10 border border-emerald-500/30 text-emerald-300">
                  <span className="w-2 h-2 rounded-full bg-emerald-400" />
                  <span>{isArabic ? 'اكتمل الفحص بنجاح' : 'AUDIT COMPLETE'}</span>
                </div>
              ) : (
                <div className="flex items-center gap-2 px-3 py-1 rounded-md bg-white/[0.05] border border-white/[0.1] text-zinc-400">
                  <span className="w-2 h-2 rounded-full bg-zinc-600" />
                  <span>{isArabic ? 'محرك الرصد جاهز' : 'SYSTEM STANDBY'}</span>
                </div>
              )}
            </div>
          </div>

          {/* 5. Live Telemetry Console (Rendered when 'telemetry' or 'both') */}
          {(resultView === 'telemetry' || resultView === 'both') && (
            <div className="space-y-2">
              <div className="flex items-center justify-between text-xs font-mono text-zinc-400 px-1">
                <span>{isArabic ? '● سجل الرصد وحزم الطلبات الحية:' : '● Real-Time Packet Log:'}</span>
                <span>{telemetryEvents.length} events logged</span>
              </div>
              <LiveTelemetryConsole
                events={telemetryEvents}
                isRunning={isRunning}
                onClear={handleClearLogs}
                lang={lang}
              />
            </div>
          )}

          {/* 6. Executive Findings & Code Fixes Report (Rendered when 'report' or 'both') */}
          {(resultView === 'report' || resultView === 'both') && (
            <div className="space-y-2 pt-2">
              <div className="flex items-center justify-between text-xs font-mono text-zinc-400 px-1">
                <span>{isArabic ? '● التقرير الأمني وبرومبتات الإصلاح الفوري:' : '● Executive Audit Report & Remediation:'}</span>
                {auditReport && <span>Score: {auditReport.score}/100</span>}
              </div>
              <FindingsSummary report={auditReport} lang={lang} />
            </div>
          )}
        </div>
      </main>

      {/* 7. Footer */}
      <footer className="border-t border-white/[0.08] bg-[#0c0c0e] py-6 text-center text-xs text-zinc-500 font-mono mt-12">
        <div className="max-w-[1360px] mx-auto px-4 flex flex-col sm:flex-row items-center justify-between gap-3">
          <span>
            {isArabic
              ? 'SecuriPulse — محاكي التهديدات وفاحص أمان التطبيقات ونقاط الـ API'
              : 'SecuriPulse — Defensive Threat Simulator & API Security Auditor'}
          </span>
          <span className="text-zinc-600">
            Next.js 16.4.3 • 42 Probes Engine • Zero-Slop Architecture
          </span>
        </div>
      </footer>

      {/* Modals */}
      <PayloadInspectorModal
        isOpen={isInspectorOpen}
        onClose={() => setIsInspectorOpen(false)}
        probes={probes}
        onSaveProbes={handleSaveProbes}
        onResetDefaultProbes={handleResetDefaultProbes}
        lang={lang}
      />

      <DefenseRecipesModal
        isOpen={isRecipesOpen}
        onClose={() => setIsRecipesOpen(false)}
        lang={lang}
      />
    </div>
  );
}
