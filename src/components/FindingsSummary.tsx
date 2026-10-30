'use client';

// ============================================================================
// 1. IMPORTS
// ============================================================================
import React, { useState } from 'react';
import {
  DownloadOutlined,
  ThunderboltOutlined,
  FileTextOutlined,
} from '@ant-design/icons';
import { AuditReport, VulnerabilityFinding } from '@/types/security';
import VulnerabilityCard from './VulnerabilityCard';
import AiRemediationModal from './AiRemediationModal';

// ============================================================================
// 2. CONFIGURATION & STYLES (ZONE 2)
// ============================================================================
const STYLES = {
  container: 'space-y-4',
  metricCard:
    'p-3.5 rounded-xl bg-[#0c0c0e] border border-white/[0.08] flex flex-col justify-between space-y-1',
};

// ============================================================================
// 3. TYPES & INTERFACES (ZONE 3)
// ============================================================================
interface FindingsSummaryProps {
  report: AuditReport | null;
  lang: 'ar' | 'en';
}

// ============================================================================
// 4. HELPER FUNCTIONS
// ============================================================================
function getGrade(score: number): {
  grade: string;
  textColor: string;
  labelAr: string;
  labelEn: string;
} {
  if (score >= 90)
    return {
      grade: 'A+',
      textColor: 'text-emerald-400',
      labelAr: 'ممتاز وحصين أمنياً',
      labelEn: 'Fortified',
    };
  if (score >= 80)
    return {
      grade: 'A',
      textColor: 'text-emerald-400',
      labelAr: 'قوي ومستقر',
      labelEn: 'Strong',
    };
  if (score >= 70)
    return {
      grade: 'B',
      textColor: 'text-white',
      labelAr: 'جيد مع بعض الملاحظات',
      labelEn: 'Good with warnings',
    };
  if (score >= 60)
    return {
      grade: 'C',
      textColor: 'text-amber-400',
      labelAr: 'يحتاج إجراءات تصحيحية',
      labelEn: 'Needs Action',
    };
  return {
    grade: 'F',
    textColor: 'text-red-400',
    labelAr: 'مكشوف وضعيف أمنياً',
    labelEn: 'High Exposure',
  };
}

// ============================================================================
// 6. MAIN COMPONENT (ZONE 6)
// ============================================================================
export default function FindingsSummary({ report, lang }: FindingsSummaryProps) {
  const isArabic = lang === 'ar';
  const [isAiPromptOpen, setIsAiPromptOpen] = useState(false);
  const [focusedFinding, setFocusedFinding] = useState<VulnerabilityFinding | null>(null);

  if (!report) {
    return (
      <div className="rounded-xl border border-white/[0.08] bg-[#0c0c0e] p-12 text-center text-zinc-500 font-mono text-xs">
        <p className="text-zinc-300 font-medium text-sm">
          {isArabic ? 'تقرير الفحص الأمني جاهز' : 'Audit Report Standby'}
        </p>
        <p className="mt-1 text-zinc-500">
          {isArabic
            ? 'ابدأ الفحص لمشاهدة التقييم النهائي، الثغرات المكتشفة، وبرومبت الإصلاح الفوري.'
            : 'Start the scan to generate security scores, detected issues, and AI fix prompts.'}
        </p>
      </div>
    );
  }

  const { grade, textColor, labelAr, labelEn } = getGrade(report.score);

  function handleDownloadJson() {
    if (!report) return;
    const dataStr =
      'data:text/json;charset=utf-8,' +
      encodeURIComponent(JSON.stringify(report, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute('href', dataStr);
    downloadAnchor.setAttribute(
      'download',
      `securipulse-report-${Date.now()}.json`
    );
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  }

  return (
    <div className={STYLES.container}>
      {/* Executive Summary Metric Row */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        {/* Score Card */}
        <div className={STYLES.metricCard}>
          <span className="text-[11px] text-zinc-500">
            {isArabic ? 'التقييم العام:' : 'Security Grade:'}
          </span>
          <div className="flex items-baseline gap-2 mt-0.5">
            <span className={`text-2xl font-bold font-mono ${textColor}`}>
              {grade}
            </span>
            <span className="text-xs font-mono text-zinc-500">
              ({report.score}/100)
            </span>
          </div>
          <span className="text-[11px] text-zinc-400">
            {isArabic ? labelAr : labelEn}
          </span>
        </div>

        {/* Defended */}
        <div className={STYLES.metricCard}>
          <span className="text-[11px] text-zinc-500">
            {isArabic ? 'هجمات تم صدها:' : 'Defended:'}
          </span>
          <div className="flex items-baseline gap-1 mt-0.5">
            <span className="text-2xl font-bold font-mono text-emerald-400">
              {report.defendedCount}
            </span>
            <span className="text-xs text-zinc-600 font-mono">
              /{report.totalProbesRun}
            </span>
          </div>
          <span className="text-[11px] text-zinc-500">
            {isArabic ? 'محصن بنجاح' : 'Safely mitigated'}
          </span>
        </div>

        {/* Warnings */}
        <div className={STYLES.metricCard}>
          <span className="text-[11px] text-zinc-500">
            {isArabic ? 'تنبيهات أمنية:' : 'Warnings:'}
          </span>
          <div className="flex items-baseline gap-1 mt-0.5">
            <span className="text-2xl font-bold font-mono text-amber-400">
              {report.warningCount}
            </span>
          </div>
          <span className="text-[11px] text-zinc-500">
            {isArabic ? 'إعدادات ناقصة' : 'Missing configurations'}
          </span>
        </div>

        {/* Confirmed Vulns */}
        <div className={STYLES.metricCard}>
          <span className="text-[11px] text-zinc-500">
            {isArabic ? 'ثغرات مؤكدة:' : 'Vulnerabilities:'}
          </span>
          <div className="flex items-baseline gap-1 mt-0.5">
            <span className="text-2xl font-bold font-mono text-red-400">
              {report.vulnerableCount}
            </span>
          </div>
          <span className="text-[11px] text-zinc-500">
            {isArabic ? 'تحتاج تصحيح فوري' : 'Action required'}
          </span>
        </div>
      </div>

      {/* AI Master Remediation Prompt Trigger Bar */}
      {report.findings.length > 0 && (
        <div className="p-4 rounded-xl bg-[#0c0c0e] border border-white/[0.08] flex items-center justify-between flex-wrap gap-3">
          <div>
            <h3 className="text-xs font-semibold text-white">
              {isArabic
                ? 'برومبت الإصلاح الشامل للذكاء الاصطناعي'
                : 'Full AI Remediation Prompt'}
            </h3>
            <p className="text-[11px] text-zinc-400 mt-0.5">
              {isArabic
                ? 'انسخ كود البرومبت المخصص وضعه مباشرة في Cursor أو Claude 3.7 أو ChatGPT لتطبيق التصحيحات فوراً.'
                : 'One-click deterministic prompt payload ready to paste into Cursor or Claude to reach 100/100.'}
            </p>
          </div>

          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={() => {
                setFocusedFinding(null);
                setIsAiPromptOpen(true);
              }}
              className="px-3.5 py-1.5 rounded-lg text-xs font-semibold bg-white text-black hover:bg-zinc-200 transition-colors flex items-center gap-1.5 cursor-pointer"
            >
              <ThunderboltOutlined className="text-xs" />
              <span>{isArabic ? 'معاينة البرومبت (Prompt to AI)' : 'Prompt to AI'}</span>
            </button>

            <button
              type="button"
              onClick={handleDownloadJson}
              className="p-1.5 rounded-lg text-xs text-zinc-400 hover:text-white bg-white/[0.04] hover:bg-white/[0.08] border border-white/[0.08] transition-colors cursor-pointer"
              title="Download JSON Report"
            >
              <DownloadOutlined />
            </button>
          </div>
        </div>
      )}

      {/* Vulnerabilities List */}
      <div className="space-y-3">
        <div className="flex items-center justify-between text-xs text-zinc-400 pt-1">
          <span>{isArabic ? 'قائمة الثغرات المكتشفة' : 'Detected Vulnerabilities'}</span>
          <span className="font-mono text-zinc-500">
            {report.findings.length} {isArabic ? 'عنصر' : 'findings'}
          </span>
        </div>

        {report.findings.map((f) => (
          <VulnerabilityCard
            key={f.id}
            finding={f}
            lang={lang}
            onOpenAiPrompt={(finding) => {
              setFocusedFinding(finding);
              setIsAiPromptOpen(true);
            }}
          />
        ))}
      </div>

      {/* Modal */}
      {isAiPromptOpen && (
        <AiRemediationModal
          isOpen={isAiPromptOpen}
          onClose={() => setIsAiPromptOpen(false)}
          report={report}
          focusedFinding={focusedFinding}
          lang={lang}
        />
      )}
    </div>
  );
}
