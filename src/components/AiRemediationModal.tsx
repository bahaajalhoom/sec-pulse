'use client';

// ============================================================================
// 1. IMPORTS
// ============================================================================
import React, { useState, useMemo } from 'react';
import {
  CloseOutlined,
  CopyOutlined,
  CheckOutlined,
  DownloadOutlined,
  ThunderboltOutlined,
  CodeOutlined,
  CheckCircleOutlined,
} from '@ant-design/icons';
import { AuditReport, VulnerabilityFinding } from '@/types/security';

// ============================================================================
// 2. CONFIGURATION & STYLES (ANT DESIGN DARK THEME)
// ============================================================================
const STYLES = {
  backdrop:
    'fixed inset-0 z-50 bg-black/60 flex items-center justify-center p-3 sm:p-5 overflow-y-auto animate-in fade-in duration-150',
  modal:
    'bg-[#1f1f1f] border border-[#303030] rounded-[8px] w-full max-w-4xl max-h-[90vh] flex flex-col shadow-2xl overflow-hidden',
  pillBtn:
    'px-2.5 py-1 rounded-[4px] text-xs font-medium transition-all cursor-pointer border',
  actionBtn:
    'px-3.5 py-1.5 rounded-[6px] text-xs font-medium flex items-center gap-1.5 transition-all cursor-pointer',
  terminalBox:
    'font-mono text-xs leading-relaxed p-4 rounded-[6px] bg-[#141414] border border-[#303030] text-[#d9d9d9] overflow-y-auto max-h-[50vh] select-all whitespace-pre-wrap selection:bg-[#1677ff] selection:text-white',
};

type TargetModel = 'claude' | 'cursor' | 'chatgpt' | 'antigravity';

interface AiRemediationModalProps {
  isOpen: boolean;
  onClose: () => void;
  report: AuditReport | null;
  focusedFinding?: VulnerabilityFinding | null;
  lang: 'ar' | 'en';
}

// ============================================================================
// 5. PROMPT BUILDER ENGINE (DETERMINISTIC & ZERO-SLOP)
// ============================================================================
function generateRemediationPrompt(
  report: AuditReport,
  focusedFinding: VulnerabilityFinding | null | undefined,
  model: TargetModel,
  promptLang: 'ar' | 'en'
): string {
  const isAr = promptLang === 'ar';
  const target = report.targetUrl || 'Target Site';
  const apiHost = report.apiBaseUrl || target;
  const currentScore = report.score || 0;
  const findingsToFix = focusedFinding
    ? [focusedFinding]
    : report.findings || [];

  const modelInstructions: Record<TargetModel, string> = {
    claude: isAr
      ? 'أنت تعمل كـ Claude 3.7 Sonnet. اكتب الحلول البرمجية كاملة بدون شفرات ناقصة مع مراعاة بنية Next.js الحديثة.'
      : 'You are operating as Claude 3.7 Sonnet. Output complete, production-ready code files with zero omissions.',
    cursor: isAr
      ? 'أنت تعمل كمساعد تطوير Cursor IDE. قم بتعديل الملفات المحددة عبر بنية الشجرة البرمجية مباشرة.'
      : 'You are operating as Cursor IDE Agent. Apply edits directly to target files within the project tree.',
    chatgpt: isAr
      ? 'أنت تعمل كـ ChatGPT-4o. اكتب كوداً آمناً جاهزاً للنسخ واللصق فوراً مع شروح تنفيذ دقيقة.'
      : 'You are operating as ChatGPT-4o. Provide copy-paste safe code with exact file placement instructions.',
    antigravity: isAr
      ? 'أنت تعمل كـ Google Antigravity Agent. طبق أفضل الممارسات الموثقة مع الحفاظ على سلامة الـ Build.'
      : 'You are operating as Antigravity Agent. Follow modern Next.js clean code with zero TypeScript errors.',
  };

  if (isAr) {
    let p = `# [الدرجة الكاملة: 100/100] برومبت الإصلاح الشامل للموقع: ${target}\n`;
    p += `الهدف: تصحيح كافة مشاكل الأمان، والترويسات، وصلاحيات الـ API، وسد الثغرات المكتشفة لرفع تقييم الأمان من (${currentScore}/100) إلى (100/100) وفق أعلى المعايير الهندسية الرسمية.\n\n`;

    p += `## 📊 ملخص الفحص الأمني الحالي للموقع\n`;
    p += `- **النطاق المستهدف:** \`${target}\`\n`;
    p += `- **خادم الـ API أو قاعدة البيانات:** \`${apiHost}\`\n`;
    p += `- **الدرجة الإجمالية الحالية:** \`${currentScore}/100\`\n`;
    p += `- **عدد المشاكل والثغرات:** \`${findingsToFix.length}\`\n`;
    p += `- **حالة الجدار الأمني:** يحتاج تطبيق الإصلاحات البرمجية فوراً للوصول إلى الحصانة الكاملة (A+).\n\n`;

    p += `## 🦾 دور الذكاء الاصطناعي وقواعد التنفيذ\n`;
    p += `مهمتك تطبيق التعديلات البرمجية التالية: ${modelInstructions[model]}\n`;
    p += `1. **كتابة كود إنتاجي جاهز للنسخ:** لا تكتفِ بالنماذج النظرية. اكتب الأكواد كاملة لكل ملف محدد دون اختصارات.\n`;
    p += `2. **الالتزام بالملفات المستهدفة:** ضع كل كود في ملفه المخصص الموضح أدناه.\n`;
    p += `3. **الحفاظ على الوظائف القائمة:** لا تقم بحذف أي ميزات حالية في الموقع أثناء سد الثغرات.\n\n`;

    p += `## 🛠️ الملفات المطلوب تعديلها والأكواد البرمجية للإصلاح\n\n`;

    findingsToFix.forEach((finding, idx) => {
      p += `### الخلل ${idx + 1}: ${finding.titleAr} (${finding.severity.toUpperCase()})\n`;
      p += `* **الملف المستهدف:** \`${finding.fixFileName}\`\n`;
      p += `* **تصنيف المشكلة:** ${finding.category.toUpperCase()}\n`;
      p += `* **لماذا يجب إصلاح هذا الخلل فوراً؟** ${finding.whyItMattersAr}\n`;
      if (finding.evidenceResponse || finding.evidencePayload) {
        p += `* **الدليل المرصود أثناء الفحص:** \`${finding.evidenceResponse || finding.evidencePayload}\`\n`;
      }
      p += `* **التوصية الهندسية:** ${finding.recommendationAr}\n`;
      p += `* **الحل البرمجي الفوري الجاهز للنسخ في \`${finding.fixFileName}\`:**\n\n`;
      p += `\`\`\`typescript\n${finding.codeFixSnippet}\n\`\`\`\n\n`;
      p += `---\n\n`;
    });

    p += `## ✅ قائمة التحقق والاختبار بعد التطبيق (Acceptance Checklist)\n`;
    p += `1. **فحص الـ Build:** تشغيل \`npm run build\` والتأكد من عدم وجود أي خطأ في الـ Types.\n`;
    p += `2. **فحص الترويسات:** التحقق من وجود الترويسات عبر \`curl -I ${target}\`.\n`;
    p += `3. **فحص الصلاحيات:** التحقق من أن مسارات الـ API المحمية تطلب Authorization Token وتعيد 401 للزوار غير المصرحين.\n`;
    p += `4. **إعادة الفحص في SecuriPulse:** التأكد من وصول التقييم النهائي إلى **(100/100) A+**.\n`;

    return p;
  } else {
    // English Prompt
    let p = `# [Target Score: 100/100] Comprehensive Security Remediation Prompt: ${target}\n`;
    p += `Goal: Resolve all detected security exposures, missing headers, API authorization flaws, and injection vectors to elevate the security posture from (${currentScore}/100) to (100/100) Fortified.\n\n`;

    p += `## 📊 Executive Audit Summary\n`;
    p += `- **Target Host:** \`${target}\`\n`;
    p += `- **API / Database Host:** \`${apiHost}\`\n`;
    p += `- **Current Security Score:** \`${currentScore}/100\`\n`;
    p += `- **Total Issues to Remediate:** \`${findingsToFix.length}\`\n\n`;

    p += `## 🦾 AI Role & Implementation Directives\n`;
    p += `Your role: ${modelInstructions[model]}\n`;
    p += `1. **Complete Production Code:** Deliver full, copy-paste ready code for every targeted file with zero stubbing or omissions.\n`;
    p += `2. **Target File Placement:** Strictly apply the patches to the designated file paths below.\n`;
    p += `3. **Preserve Business Logic:** Harden security barriers without regressing existing site functionality.\n\n`;

    p += `## 🛠️ Step-by-Step Security Patches & File Edits\n\n`;

    findingsToFix.forEach((finding, idx) => {
      p += `### Issue ${idx + 1}: ${finding.title} (${finding.severity.toUpperCase()})\n`;
      p += `* **Target File:** \`${finding.fixFileName}\`\n`;
      p += `* **Vulnerability Category:** ${finding.category.toUpperCase()}\n`;
      p += `* **Security Impact:** ${finding.whyItMatters}\n`;
      p += `* **Observed Evidence:** \`${finding.evidenceResponse || finding.evidencePayload}\`\n`;
      p += `* **Remediation Recommendation:** ${finding.recommendation}\n`;
      p += `* **Production-Grade Patch for \`${finding.fixFileName}\`:**\n\n`;
      p += `\`\`\`typescript\n${finding.codeFixSnippet}\n\`\`\`\n\n`;
      p += `---\n\n`;
    });

    p += `## ✅ Post-Implementation Verification Checklist\n`;
    p += `1. Run \`npm run build\` to verify zero TypeScript errors.\n`;
    p += `2. Verify security headers via \`curl -I ${target}\`.\n`;
    p += `3. Re-run SecuriPulse audit to confirm a target score of **100/100 (A+)**.\n`;

    return p;
  }
}

// ============================================================================
// 6. MAIN COMPONENT (ZONE 6)
// ============================================================================
export default function AiRemediationModal({
  isOpen,
  onClose,
  report,
  focusedFinding,
  lang,
}: AiRemediationModalProps) {
  const isArabic = lang === 'ar';
  const [selectedModel, setSelectedModel] = useState<TargetModel>('claude');
  const [promptLang, setPromptLang] = useState<'ar' | 'en'>(lang);
  const [copied, setCopied] = useState(false);

  // Compute master prompt payload dynamically
  const generatedPrompt = useMemo(() => {
    if (!report) return '';
    return generateRemediationPrompt(
      report,
      focusedFinding,
      selectedModel,
      promptLang
    );
  }, [report, focusedFinding, selectedModel, promptLang]);

  if (!isOpen || !report) return null;

  async function handleCopy() {
    if (!generatedPrompt) return;
    try {
      await navigator.clipboard.writeText(generatedPrompt);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // Fallback
    }
  }

  function handleDownloadMarkdown() {
    if (!generatedPrompt) return;
    const blob = new Blob([generatedPrompt], { type: 'text/markdown;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `SECURITY_REMEDIATION_PROMPT_${Date.now()}.md`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  }

  return (
    <div className={STYLES.backdrop} role="dialog" aria-modal="true">
      <div className={STYLES.modal}>
        {/* Modal Top Header */}
        <div className="p-4 border-b border-[#303030] flex items-center justify-between bg-[#1f1f1f]">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-[6px] bg-[#111d2c] border border-[#153450] flex items-center justify-center text-[#1677ff]">
              <ThunderboltOutlined className="text-sm" />
            </div>
            <div>
              <div className="flex items-center gap-2 flex-wrap">
                <h2 className="text-sm font-semibold text-white">
                  {isArabic
                    ? 'برومبت الإصلاح الشامل للذكاء الاصطناعي'
                    : 'Comprehensive AI Remediation Prompt'}
                </h2>
                <span className="text-[11px] font-mono px-2 py-0.5 rounded-[4px] bg-[#162312] text-[#52c41a] border border-[#274916]">
                  Target: 100/100
                </span>
              </div>
              <p className="text-xs text-[#8c8c8c] mt-0.5">
                {isArabic
                  ? 'انسخ هذا البرومبت بالكامل وضعه مباشرة في ChatGPT أو Claude 3.7 أو محرر Cursor / Antigravity لتطبيق كافة الحلول البرمجية فوراً.'
                  : 'Copy this complete prompt directly into ChatGPT, Claude 3.7, or Cursor / Antigravity to apply all patches immediately.'}
              </p>
            </div>
          </div>

          <button
            type="button"
            onClick={onClose}
            className="p-1.5 rounded-[4px] text-[#8c8c8c] hover:text-white hover:bg-[#262626] transition-colors cursor-pointer"
            aria-label="Close"
          >
            <CloseOutlined className="text-sm" />
          </button>
        </div>

        {/* Controls Toolbar: Model Selection, Language, and Export Actions */}
        <div className="p-3 sm:px-4 border-b border-[#303030] bg-[#141414] flex items-center justify-between flex-wrap gap-2.5">
          {/* Target Model Selector */}
          <div className="flex items-center gap-1.5">
            <span className="text-xs text-[#8c8c8c] font-medium ml-1">
              {isArabic ? 'النموذج:' : 'Model:'}
            </span>
            {(
              [
                { id: 'claude', label: 'Claude 3.7' },
                { id: 'cursor', label: 'Cursor' },
                { id: 'chatgpt', label: 'ChatGPT-4o' },
                { id: 'antigravity', label: 'Antigravity' },
              ] as const
            ).map((m) => (
              <button
                key={m.id}
                type="button"
                onClick={() => setSelectedModel(m.id)}
                className={`${STYLES.pillBtn} ${
                  selectedModel === m.id
                    ? 'bg-[#111d2c] border-[#1677ff] text-[#1677ff] font-medium'
                    : 'bg-[#1f1f1f] border-[#303030] text-[#8c8c8c] hover:text-white'
                }`}
              >
                {m.label}
              </button>
            ))}
          </div>

          {/* Prompt Language & Actions */}
          <div className="flex items-center gap-2">
            {/* Language Toggle */}
            <div className="flex items-center bg-[#1f1f1f] p-0.5 rounded-[4px] border border-[#303030]">
              <button
                type="button"
                onClick={() => setPromptLang('ar')}
                className={`px-2 py-0.5 rounded-[2px] text-[11px] font-mono font-medium cursor-pointer ${
                  promptLang === 'ar'
                    ? 'bg-[#1677ff] text-white'
                    : 'text-[#8c8c8c] hover:text-white'
                }`}
              >
                AR
              </button>
              <button
                type="button"
                onClick={() => setPromptLang('en')}
                className={`px-2 py-0.5 rounded-[2px] text-[11px] font-mono font-medium cursor-pointer ${
                  promptLang === 'en'
                    ? 'bg-[#1677ff] text-white'
                    : 'text-[#8c8c8c] hover:text-white'
                }`}
              >
                EN
              </button>
            </div>

            {/* Download Markdown */}
            <button
              type="button"
              onClick={handleDownloadMarkdown}
              className={`${STYLES.actionBtn} bg-[#1f1f1f] hover:bg-[#262626] text-[#d9d9d9] hover:text-white border border-[#303030]`}
            >
              <DownloadOutlined className="text-xs text-[#1677ff]" />
              <span>{isArabic ? 'تحميل Markdown' : 'Download .md'}</span>
            </button>

            {/* Copy Full Prompt Button */}
            <button
              type="button"
              onClick={handleCopy}
              className={`${STYLES.actionBtn} bg-[#1677ff] hover:bg-[#4096ff] text-white border border-[#1677ff] font-medium`}
            >
              {copied ? (
                <>
                  <CheckOutlined className="text-xs" />
                  <span>{isArabic ? 'تم النسخ!' : 'Copied!'}</span>
                </>
              ) : (
                <>
                  <CopyOutlined className="text-xs" />
                  <span>{isArabic ? 'نسخ البرومبت بالكامل' : 'Copy Full Prompt'}</span>
                </>
              )}
            </button>
          </div>
        </div>

        {/* Master Prompt Terminal View */}
        <div className="p-4 space-y-3 bg-[#141414]">
          <div className="relative">
            <pre className={STYLES.terminalBox} dir="ltr">
              {generatedPrompt}
            </pre>
          </div>

          {/* Footer Metadata Status Bar */}
          <div className="flex items-center justify-between text-xs text-[#8c8c8c] px-1 font-mono pt-1">
            <span className="text-[#52c41a] flex items-center gap-1.5 font-medium">
              <CheckCircleOutlined className="text-xs" />
              <span>Score Target: 100/100 (A+)</span>
            </span>
            <span className="text-[#8c8c8c] flex items-center gap-1.5">
              <span>Deterministic Payload:</span>
              <span className="text-white font-medium">
                {generatedPrompt.length} chars
              </span>
            </span>
          </div>
        </div>
      </div>
    </div>
  );
}
