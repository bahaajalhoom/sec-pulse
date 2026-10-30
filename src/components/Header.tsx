'use client';

// ============================================================================
// 1. IMPORTS
// ============================================================================
import React from 'react';
import BrandLogo from './BrandLogo';
import {
  SafetyCertificateOutlined,
  BookOutlined,
  GlobalOutlined,
  CheckCircleOutlined,
  SyncOutlined,
} from '@ant-design/icons';

// ============================================================================
// 2. CONFIGURATION & CONSTANTS (ZONE 2)
// ============================================================================
const HEADER_CONFIG = {
  title: 'SecuriPulse',
  titleAr: 'سيكيوريبلس',
  tagline: 'Enterprise Threat Simulation & Vulnerability Auditor',
  taglineAr: 'منصة محاكاة الهجمات الأمنية وفحص الثغرات للمواقع',
  badgeText: 'DEVSEC 2026',
};

// ============================================================================
// 3. TYPES & INTERFACES (ZONE 3)
// ============================================================================
interface HeaderProps {
  lang: 'ar' | 'en';
  onToggleLang: () => void;
  onOpenRecipes: () => void;
  isRunning: boolean;
  score: number | null;
}

// ============================================================================
// 6. MAIN COMPONENT (ZONE 6)
// ============================================================================
export default function Header({
  lang,
  onToggleLang,
  onOpenRecipes,
  isRunning,
  score,
}: HeaderProps) {
  const isArabic = lang === 'ar';

  return (
    <header className="border-b border-[#303030] bg-[#141414] sticky top-0 z-40">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-14 flex items-center justify-between">
        {/* Brand Identity */}
        <BrandLogo lang={lang} size="md" />

        {/* Live Status & Quick Action Tools */}
        <div className="flex items-center gap-2.5">
          {/* Running Status Pill */}
          {isRunning && (
            <div className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-[#2b2111] border border-[#594214] text-[#faad14] text-xs font-medium">
              <SyncOutlined spin className="text-xs" />
              <span>{isArabic ? 'جاري الفحص المباشر...' : 'Audit in Progress...'}</span>
            </div>
          )}

          {/* Overall Score Badge if finished */}
          {score !== null && !isRunning && (
            <div className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-[#1f1f1f] border border-[#303030] text-xs">
              <span className="text-[#8c8c8c]">{isArabic ? 'تقييم الأمان:' : 'Score:'}</span>
              <span
                className={`font-mono font-bold ${
                  score >= 80 ? 'text-[#52c41a]' : score >= 60 ? 'text-[#faad14]' : 'text-[#ff4d4f]'
                }`}
              >
                {score}/100
              </span>
            </div>
          )}

          {/* Defense Quick Recipes Button */}
          <button
            type="button"
            onClick={onOpenRecipes}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-[#1f1f1f] hover:bg-[#262626] text-[#d9d9d9] border border-[#303030] transition-colors cursor-pointer"
          >
            <BookOutlined className="text-xs text-[#1677ff]" />
            <span className="hidden sm:inline">
              {isArabic ? 'أكواد الحماية الفورية' : 'Defense Recipes'}
            </span>
          </button>

          {/* Language Toggle */}
          <button
            type="button"
            onClick={onToggleLang}
            className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs font-mono font-semibold bg-[#1f1f1f] hover:bg-[#262626] text-[#d9d9d9] border border-[#303030] transition-colors cursor-pointer"
          >
            <GlobalOutlined className="text-xs text-[#8c8c8c]" />
            <span>{isArabic ? 'English' : 'العربية'}</span>
          </button>
        </div>
      </div>
    </header>
  );
}
