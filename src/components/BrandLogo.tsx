'use client';

import React from 'react';

export interface BrandLogoProps {
  variant?: 'full' | 'mark' | 'icon';
  size?: 'sm' | 'md' | 'lg';
  lang?: 'ar' | 'en';
  className?: string;
  showBadge?: boolean;
}

export default function BrandLogo({
  variant = 'full',
  size = 'md',
  lang = 'ar',
  className = '',
  showBadge = true,
}: BrandLogoProps) {
  // Dimension tokens based on standard sizes
  const dimensions = {
    sm: { icon: 24, text: 'text-xs', badge: 'text-[9px] px-1 py-0.2' },
    md: { icon: 32, text: 'text-sm', badge: 'text-[10px] px-1.5 py-0.2' },
    lg: { icon: 44, text: 'text-base', badge: 'text-[11px] px-2 py-0.5' },
  }[size];

  // Core Vector Shield + Telemetry Pulse Mark
  const MarkSvg = (
    <svg
      viewBox="0 0 256 256"
      width={dimensions.icon}
      height={dimensions.icon}
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      className="shrink-0 drop-shadow-sm select-none"
      aria-hidden="true"
    >
      <title>SecuriPulse Brandmark</title>
      {/* Outer Defensive Shield Perimeter */}
      <path
        d="M128 24 L48 54 V126 C48 180 82 226 128 238 C174 226 208 180 208 126 V54 Z"
        stroke="#1677ff"
        strokeWidth="18"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      {/* Inner Telemetry Pulse Wave */}
      <path
        d="M64 128 H96 L112 156 L128 72 L144 156 L160 128 H192"
        stroke="#13c2c2"
        strokeWidth="18"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      {/* Central Telemetry Apex Node */}
      <circle cx="128" cy="72" r="5" fill="#13c2c2" />
    </svg>
  );

  if (variant === 'mark' || variant === 'icon') {
    return (
      <div
        className={`inline-flex items-center justify-center rounded-lg bg-[#111d2c] border border-[#153450] p-1.5 ${className}`}
      >
        {MarkSvg}
      </div>
    );
  }

  const isArabic = lang === 'ar';

  return (
    <div className={`flex items-center gap-3 select-none ${className}`}>
      <div className="rounded-lg bg-[#111d2c] border border-[#153450] p-1.5 flex items-center justify-center">
        {MarkSvg}
      </div>
      <div>
        <div className="flex items-center gap-2">
          <span className={`font-bold tracking-tight text-white ${dimensions.text}`}>
            {isArabic ? (
              <span>
                سيكيوري<span className="text-[#1677ff]">بلس</span>
              </span>
            ) : (
              <span>
                Securi<span className="text-[#1677ff]">Pulse</span>
              </span>
            )}
          </span>
          {showBadge && (
            <span
              className={`font-mono font-medium rounded bg-[#1f1f1f] text-[#8c8c8c] border border-[#303030] ${dimensions.badge}`}
            >
              DEVSEC 2026
            </span>
          )}
        </div>
        <p className="text-[11px] text-[#8c8c8c] hidden sm:block">
          {isArabic
            ? 'منصة محاكاة الهجمات الأمنية وفحص الثغرات للمواقع'
            : 'Enterprise Threat Simulation & Vulnerability Auditor'}
        </p>
      </div>
    </div>
  );
}
