'use client';

// ============================================================================
// 1. IMPORTS
// ============================================================================
import React, { useState } from 'react';
import {
  SafetyCertificateOutlined,
  CheckCircleOutlined,
  WarningOutlined,
  CloseCircleOutlined,
  DownloadOutlined,
  ThunderboltOutlined,
  FileTextOutlined,
} from '@ant-design/icons';
import { AuditReport, VulnerabilityFinding } from '@/types/security';
import VulnerabilityCard from './VulnerabilityCard';
import AiRemediationModal from './AiRemediationModal';

// ============================================================================
// 2. CONFIGURATION & STYLES (ANT DESIGN DARK THEME)
// ============================================================================
const STYLES = {
  container: 'space-y-5',
  metricCard:
    'p-4 rounded-[8px] bg-[#141414] border border-[#303030] flex flex-col justify-between space-y-2',
  exportBtn:
    'px-3 py-1.5 rounded-[6px] text-xs font-medium bg-[#1f1f1f] hover:bg-[#262626] text-[#d9d9d9] hover:text-white border border-[#303030] transition-colors flex items-center gap-1.5 cursor-pointer',
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
      textColor: 'text-[#52c41a]',
      labelAr: 'ممتاز وحصين أمنياً',
      labelEn: 'Fortified',
    };
  if (score >= 80)
    return {
      grade: 'A',
      textColor: 'text-[#52c41a]',
      labelAr: 'قوي ومستقر',
      labelEn: 'Strong',
    };
  if (score >= 70)
    return {
      grade: 'B',
      textColor: 'text-[#1677ff]',
      labelAr: 'جيد مع بعض الملاحظات',
      labelEn: 'Good with warnings',
    };
  if (score >= 60)
    return {
      grade: 'C',
      textColor: 'text-[#faad14]',
      labelAr: 'يحتاج إجراءات تصحيحية',
      labelEn: 'Needs Action',
    };
  return {
    grade: 'F',
    textColor: 'text-[#ff4d4f]',
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
      <div className="rounded-[8px] border border-[#303030] bg-[#141414] p-8 text-center text-[#8c8c8c]">
        <SafetyCertificateOutlined className="text-3xl mx-auto mb-3 text-[#1677ff]" />
        <h3 className="text-sm font-semibold text-white">
          {isArabic ? 'تقرير الفحص الأمني جاهز للعرض' : 'Security Audit Report'}
        </h3>
        <p className="text-xs text-[#8c8c8c] mt-1 max-w-md mx-auto">
          {isArabic
            ? 'بمجرد تشغيل الفحص ومحاكاة الهجمات، ستظهر هنا درجات الحماية، الثغرات المكتشفة، وأكواد التصحيح الموصى بها.'
            : 'Launch the simulated attack to view the security score, vulnerability breakdown, and copy-paste code fixes.'}
        </p>
      </div>
    );
  }

  const { grade, textColor, labelAr, labelEn } = getGrade(report.score);

  function handleDownloadJson() {
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
      {/* Executive Summary Bento Grid - Calm Ant Design Statistic Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-3.5">
        {/* Overall Score Box */}
        <div className={STYLES.metricCard}>
          <span className="text-xs font-medium text-[#8c8c8c]">
            {isArabic ? 'تقييم الجدار الأمني:' : 'Overall Security Grade:'}
          </span>
          <div className="flex items-baseline gap-2 mt-1">
            <span className={`text-3xl font-bold font-mono tracking-tight ${textColor}`}>
              {grade}
            </span>
            <span className="text-xs font-mono text-[#8c8c8c]">
              ({report.score}/100)
            </span>
          </div>
          <p className="text-xs font-medium text-[#d9d9d9] mt-1">
            {isArabic ? labelAr : labelEn}
          </p>
        </div>

        {/* Metric 1: Defended */}
        <div className={STYLES.metricCard}>
          <span className="text-xs text-[#8c8c8c] font-medium">
            {isArabic ? 'الهجمات التي تم صدها بنجاح:' : 'Attacks Safely Defended:'}
          </span>
          <div className="flex items-baseline gap-1.5 mt-1">
            <span className="text-2xl font-bold font-mono text-[#52c41a]">
              {report.defendedCount}
            </span>
            <span className="text-xs text-[#8c8c8c] font-mono">
              / {report.totalProbesRun}
            </span>
          </div>
          <span className="text-[11px] text-[#8c8c8c] mt-1">
            {isArabic ? 'موقعك محصن ضد هذه الفحوصات' : 'Endpoints resilient'}
          </span>
        </div>

        {/* Metric 2: Warnings */}
        <div className={STYLES.metricCard}>
          <span className="text-xs text-[#8c8c8c] font-medium">
            {isArabic ? 'تنبيهات أمنية وتكوينات ناقصة:' : 'Security Warnings:'}
          </span>
          <div className="flex items-baseline gap-1.5 mt-1">
            <span className="text-2xl font-bold font-mono text-[#faad14]">
              {report.warningCount}
            </span>
            <span className="text-xs text-[#8c8c8c] font-mono">
              {isArabic ? 'تنبيه' : 'warnings'}
            </span>
          </div>
          <span className="text-[11px] text-[#8c8c8c] mt-1">
            {isArabic ? 'ترويسات أو إعدادات يفضل تفعيلها' : 'Missing headers or CORS'}
          </span>
        </div>

        {/* Metric 3: Critical Vulnerabilities */}
        <div className={STYLES.metricCard}>
          <span className="text-xs text-[#8c8c8c] font-medium">
            {isArabic ? 'ثغرات حرجة يجب إصلاحها:' : 'Confirmed Vulnerabilities:'}
          </span>
          <div className="flex items-baseline gap-1.5 mt-1">
            <span className="text-2xl font-bold font-mono text-[#ff4d4f]">
              {report.vulnerableCount}
            </span>
            <span className="text-xs text-[#8c8c8c] font-mono">
              {isArabic ? 'ثغرة' : 'issues'}
            </span>
          </div>
          <span className="text-[11px] text-[#8c8c8c] mt-1">
            {isArabic ? 'يوجد حل برمجي مقترح بالأسفل' : 'Fix recipes provided below'}
          </span>
        </div>
      </div>

      {/* AI Master Remediation Prompt Banner (Target: 100/100) */}
      {report.findings.length > 0 && (
        <div className="p-4 rounded-[8px] bg-[#141414] border border-[#303030] flex items-center justify-between flex-wrap gap-3">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-[6px] bg-[#111d2c] border border-[#153450] flex items-center justify-center text-[#1677ff] shrink-0">
              <ThunderboltOutlined className="text-sm" />
            </div>
            <div>
              <div className="flex items-center gap-2 flex-wrap">
                <h3 className="text-xs sm:text-sm font-semibold text-white">
                  {isArabic
                    ? 'برومبت الإصلاح الشامل للذكاء الاصطناعي'
                    : 'Comprehensive AI Remediation Prompt'}
                </h3>
                <span className="text-[11px] font-mono px-2 py-0.5 rounded-[4px] bg-[#162312] text-[#52c41a] border border-[#274916]">
                  Target: 100/100
                </span>
              </div>
              <p className="text-[11.5px] text-[#8c8c8c] mt-0.5 max-w-xl leading-relaxed">
                {isArabic
                  ? 'انسخ هذا البرومبت بالكامل وضعه مباشرة في ChatGPT أو Claude 3.7 أو محرر Cursor / Antigravity لتطبيق كافة الحلول البرمجية فوراً وسد جميع الثغرات.'
                  : 'Copy this complete prompt directly into ChatGPT, Claude 3.7, or Cursor / Antigravity to apply all code patches immediately.'}
              </p>
            </div>
          </div>

          <button
            type="button"
            onClick={() => {
              setFocusedFinding(null);
              setIsAiPromptOpen(true);
            }}
            className="px-3.5 py-1.5 rounded-[6px] text-xs font-medium bg-[#1677ff] hover:bg-[#4096ff] text-white transition-all flex items-center gap-1.5 cursor-pointer shrink-0"
          >
            <ThunderboltOutlined className="text-xs" />
            <span>
              {isArabic ? 'معاينة برومبت الإصلاح للـ AI' : 'Preview Prompt to AI'}
            </span>
          </button>
        </div>
      )}

      {/* Findings Section Header & Export */}
      <div className="flex items-center justify-between border-b border-[#303030] pb-3 pt-2 flex-wrap gap-2">
        <div>
          <h2 className="text-sm font-semibold text-white flex items-center gap-2">
            <FileTextOutlined className="text-sm text-[#1677ff]" />
            <span>
              {isArabic
                ? 'تفاصيل الثغرات والحلول البرمجية الفورية'
                : 'Detailed Findings & Instant Code Fixes'}
            </span>
          </h2>
          <p className="text-xs text-[#8c8c8c] mt-0.5">
            {isArabic
              ? 'شرح مبسط لكل خطر مع الكود المنسوخ بنقرة واحدة لأصحاب المواقع'
              : 'Plain-language explainers and copy-paste code patches for website owners'}
          </p>
        </div>

        <div className="flex items-center gap-2">
          {report.findings.length > 0 && (
            <button
              type="button"
              onClick={() => {
                setFocusedFinding(null);
                setIsAiPromptOpen(true);
              }}
              className="px-3 py-1.5 rounded-[6px] text-xs font-medium bg-[#111d2c] hover:bg-[#153450] text-[#1677ff] border border-[#153450] transition-all flex items-center gap-1.5 cursor-pointer"
            >
              <ThunderboltOutlined className="text-xs" />
              <span>{isArabic ? 'برومبت AI' : 'Prompt to AI'}</span>
            </button>
          )}

          <button
            type="button"
            onClick={handleDownloadJson}
            className={STYLES.exportBtn}
          >
            <DownloadOutlined className="text-xs" />
            <span>{isArabic ? 'تصدير التقرير JSON' : 'Export JSON'}</span>
          </button>
        </div>
      </div>

      {/* Vulnerabilities Cards List */}
      {report.findings.length === 0 ? (
        <div className="p-8 rounded-[8px] bg-[#141414] border border-[#303030] text-center">
          <CheckCircleOutlined className="text-3xl mx-auto text-[#52c41a] mb-2" />
          <h4 className="text-sm font-semibold text-white">
            {isArabic ? 'ما شاء الله! موقعك صمد أمام جميع الاختبارات' : 'Zero Vulnerabilities Detected!'}
          </h4>
          <p className="text-xs text-[#8c8c8c] mt-1 max-w-lg mx-auto">
            {isArabic
              ? 'الاستجابات سليمة، الترويسات موجودة، ومدخلات الاستعلامات تم التعامل معها بمعايير حماية مرتفعة.'
              : 'The target successfully withstood all benign canary attack vectors for the selected intensity.'}
          </p>
        </div>
      ) : (
        <div className="space-y-3">
          {report.findings.map((finding) => (
            <VulnerabilityCard
              key={finding.id}
              finding={finding}
              lang={lang}
              onOpenAiPrompt={(f) => {
                setFocusedFinding(f);
                setIsAiPromptOpen(true);
              }}
            />
          ))}
        </div>
      )}

      {/* AI Remediation Master Modal */}
      <AiRemediationModal
        isOpen={isAiPromptOpen}
        onClose={() => {
          setIsAiPromptOpen(false);
          setFocusedFinding(null);
        }}
        report={report}
        focusedFinding={focusedFinding}
        lang={lang}
      />
    </div>
  );
}
