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

type RightPaneView = 'telemetry' | 'report';

// ============================================================================
// 6. MAIN COMPONENT (ZONE 6)
// ============================================================================
export default function HomePage() {
  // --- UI & Language State ---
  const [lang, setLang] = useState<'ar' | 'en'>('ar');
  const isArabic = lang === 'ar';
  const [rightView, setRightView] = useState<RightPaneView>('telemetry');

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

  // Abort controller ref
  const abortControllerRef = useRef<AbortController | null>(null);

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
    setRightView('telemetry');

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
                setRightView('report');
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
      {/* 1. Header Bar */}
      <Header
        lang={lang}
        onToggleLang={handleToggleLang}
        onOpenRecipes={() => setIsRecipesOpen(true)}
        isRunning={isRunning}
        score={auditReport ? auditReport.score : null}
      />

      {/* 2. Main Workstation Area (Split Screen) */}
      <main className="flex-1 max-w-[1600px] w-full mx-auto px-4 sm:px-6 py-5">
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 items-start">
          {/* ================================================================= */}
          {/* LEFT PANE (5 COLS): ATTACK SURFACE & TARGET CONFIGURATION        */}
          {/* ================================================================= */}
          <div className="lg:col-span-5 space-y-4">
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
          </div>

          {/* ================================================================= */}
          {/* RIGHT PANE (7 COLS): LIVE TELEMETRY TERMINAL & SECURITY REPORT    */}
          {/* ================================================================= */}
          <div className="lg:col-span-7 space-y-3.5">
            {/* View Switcher Header Bar */}
            <div className="flex items-center justify-between flex-wrap gap-2 bg-[#0c0c0e] p-2 rounded-xl border border-white/[0.1]">
              <div className="flex items-center gap-1.5 bg-black p-1 rounded-lg border border-white/[0.08]">
                {/* Switcher Tab 1: Live Terminal */}
                <button
                  type="button"
                  onClick={() => setRightView('telemetry')}
                  className={`flex items-center gap-2 px-3.5 py-1.5 rounded-md text-xs font-semibold transition-all cursor-pointer ${
                    rightView === 'telemetry'
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

                {/* Switcher Tab 2: Security Findings & AI Remediation */}
                <button
                  type="button"
                  onClick={() => setRightView('report')}
                  className={`flex items-center gap-2 px-3.5 py-1.5 rounded-md text-xs font-semibold transition-all cursor-pointer ${
                    rightView === 'report'
                      ? 'bg-white text-black shadow-sm'
                      : 'text-zinc-400 hover:text-white hover:bg-white/[0.04]'
                  }`}
                >
                  <SafetyCertificateOutlined className="text-xs" />
                  <span>{isArabic ? 'تقرير الثغرات والحلول' : 'Findings & AI'}</span>
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
              </div>

              {/* Status Indicator */}
              <div className="flex items-center gap-2 text-[11px] font-mono text-zinc-500">
                {isRunning ? (
                  <span className="text-amber-400 flex items-center gap-1.5">
                    <span className="w-1.5 h-1.5 rounded-full bg-amber-400 animate-ping" />
                    <span>AUDITING LIVE</span>
                  </span>
                ) : auditReport ? (
                  <span className="text-emerald-400 flex items-center gap-1.5">
                    <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
                    <span>AUDIT COMPLETE</span>
                  </span>
                ) : (
                  <span className="flex items-center gap-1.5">
                    <span className="w-1.5 h-1.5 rounded-full bg-zinc-600" />
                    <span>STANDBY</span>
                  </span>
                )}
              </div>
            </div>

            {/* Active Right Pane Display */}
            {rightView === 'telemetry' ? (
              <LiveTelemetryConsole
                events={telemetryEvents}
                isRunning={isRunning}
                onClear={handleClearLogs}
                lang={lang}
              />
            ) : (
              <FindingsSummary report={auditReport} lang={lang} />
            )}
          </div>
        </div>
      </main>

      {/* 3. Footer */}
      <footer className="border-t border-white/[0.08] bg-black py-3 text-center text-xs text-zinc-600 mt-auto">
        <div className="max-w-[1600px] mx-auto px-4 flex flex-col sm:flex-row items-center justify-between gap-2">
          <span>
            {isArabic
              ? 'SecuriPulse — محاكي التهديدات وفاحص أمان الواجهات ونقاط الـ API'
              : 'SecuriPulse — Defensive Threat Simulator & API Security Auditor'}
          </span>
          <span className="font-mono text-[11px] text-zinc-600">
            v2.6 PRODUCTION
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
