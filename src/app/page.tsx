'use client';

// ============================================================================
// 1. IMPORTS
// ============================================================================
import React, { useState, useRef, useCallback, useEffect } from 'react';
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
  DashboardOutlined,
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

type ActiveViewTab = 'cockpit' | 'telemetry' | 'report';

// ============================================================================
// 6. MAIN COMPONENT (ZONE 6)
// ============================================================================
export default function HomePage() {
  // --- UI & Language State ---
  const [lang, setLang] = useState<'ar' | 'en'>('ar');
  const isArabic = lang === 'ar';
  const [activeTab, setActiveTab] = useState<ActiveViewTab>('cockpit');

  // --- Configuration State ---
  const [targetUrl, setTargetUrl] = useState(DEFAULT_CONFIG.initialTargetUrl);
  const [apiBaseUrl, setApiBaseUrl] = useState('');
  const [endpoints, setEndpoints] = useState<DiscoveredEndpoint[]>([]);
  const [intensity, setIntensity] = useState<AttackIntensity>(DEFAULT_CONFIG.defaultIntensity);
  const [concurrency, setConcurrency] = useState(DEFAULT_CONFIG.defaultConcurrency);
  const [delayMs, setDelayMs] = useState(DEFAULT_CONFIG.defaultDelayMs);
  const [enabledCategories, setEnabledCategories] = useState(DEFAULT_CATEGORIES);

  // --- Probes Catalog (Editable in Inspector) ---
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

  // --- Handlers: REAL Live Network Audit Execution ---
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
    setActiveTab('telemetry'); // Switch to live telemetry automatically

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
                // When report completes, switch smoothly to report view
                setActiveTab('report');
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
      className={`min-h-screen bg-[#08090d] text-[#d9d9d9] flex flex-col font-sans selection:bg-[#1677ff] selection:text-white ${
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

      {/* 2. Main Work Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-5 space-y-5">
        {/* Navigation Tabs Bar (Cockpit / Live Telemetry / Report) */}
        <div className="flex items-center justify-between flex-wrap gap-2 pb-1 border-b border-[#262626]">
          <div className="flex items-center gap-1.5 bg-[#141414] p-1 rounded-xl border border-[#303030]">
            {/* Tab 1: Cockpit */}
            <button
              type="button"
              onClick={() => setActiveTab('cockpit')}
              className={`flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-semibold transition-all cursor-pointer ${
                activeTab === 'cockpit'
                  ? 'bg-[#1677ff] text-white shadow-sm'
                  : 'text-[#8c8c8c] hover:text-white'
              }`}
            >
              <DashboardOutlined className="text-xs" />
              <span>{isArabic ? 'لوحة التحكم والمسارات' : 'Attack Cockpit'}</span>
            </button>

            {/* Tab 2: Live Telemetry */}
            <button
              type="button"
              onClick={() => setActiveTab('telemetry')}
              className={`flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-semibold transition-all cursor-pointer ${
                activeTab === 'telemetry'
                  ? 'bg-[#1677ff] text-white shadow-sm'
                  : 'text-[#8c8c8c] hover:text-white'
              }`}
            >
              {isRunning ? (
                <SyncOutlined spin className="text-xs text-[#faad14]" />
              ) : (
                <CodeOutlined className="text-xs" />
              )}
              <span>{isArabic ? 'شاشة البث المباشر' : 'Live Stream'}</span>
              {telemetryEvents.length > 0 && (
                <span className="font-mono text-[10px] px-1.5 py-0.2 rounded bg-black/40 text-current">
                  {telemetryEvents.length}
                </span>
              )}
            </button>

            {/* Tab 3: Report & Remediation */}
            <button
              type="button"
              onClick={() => setActiveTab('report')}
              className={`flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-semibold transition-all cursor-pointer ${
                activeTab === 'report'
                  ? 'bg-[#1677ff] text-white shadow-sm'
                  : 'text-[#8c8c8c] hover:text-white'
              }`}
            >
              <SafetyCertificateOutlined className="text-xs" />
              <span>{isArabic ? 'تقرير الثغرات والحلول' : 'Audit Report'}</span>
              {auditReport && (
                <span
                  className={`font-mono font-bold text-[10px] px-1.5 py-0.2 rounded ${
                    auditReport.score >= 80
                      ? 'bg-[#162312] text-[#52c41a]'
                      : auditReport.score >= 60
                      ? 'bg-[#2b2111] text-[#faad14]'
                      : 'bg-[#2a1215] text-[#ff4d4f]'
                  }`}
                >
                  {auditReport.score}/100
                </span>
              )}
            </button>
          </div>

          {/* Quick Engine Meta */}
          <div className="hidden sm:flex items-center gap-2 text-xs text-[#8c8c8c] font-mono">
            <span>PROBES: 42</span>
            <span>•</span>
            <span>CONCURRENCY: {concurrency}X</span>
            <span>•</span>
            <span className="text-[#52c41a]">ZERO-SLOP</span>
          </div>
        </div>

        {/* Tab Content Display */}
        {activeTab === 'cockpit' && (
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
        )}

        {activeTab === 'telemetry' && (
          <div className="space-y-4">
            <LiveTelemetryConsole
              events={telemetryEvents}
              isRunning={isRunning}
              onClear={handleClearLogs}
              lang={lang}
            />
          </div>
        )}

        {activeTab === 'report' && (
          <div className="space-y-4">
            <FindingsSummary report={auditReport} lang={lang} />
          </div>
        )}
      </main>

      {/* 3. Footer */}
      <footer className="border-t border-[#262626] bg-[#0c0d12] py-4 text-center text-xs text-[#8c8c8c]">
        <div className="max-w-7xl mx-auto px-4 flex flex-col sm:flex-row items-center justify-between gap-2">
          <span>
            {isArabic
              ? 'SecuriPulse — منصة محاكاة الهجمات السيبرانية وفحص الثغرات الحقيقية'
              : 'SecuriPulse — Enterprise Defensive Threat Simulator & Real Vulnerability Auditor'}
          </span>
          <span className="font-mono text-[11px] text-[#595959]">
            DEVSEC OPS 2026 • ZERO AI SLOP
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
