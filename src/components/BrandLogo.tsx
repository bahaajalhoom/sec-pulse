'use client';

import React from 'react';

export interface BrandLogoProps {
  variant?: 'full' | 'mark' | 'icon';
  size?: 'sm' | 'md' | 'lg';
  lang?: 'ar' | 'en';
  className?: string;
}

export default function BrandLogo({
  variant = 'full',
  size = 'md',
  lang = 'ar',
  className = '',
}: BrandLogoProps) {
  const dimensions = {
    sm: { icon: 20, text: 'text-xs' },
    md: { icon: 24, text: 'text-sm' },
    lg: { icon: 32, text: 'text-base' },
  }[size];

  const MarkSvg = (
    <svg
      viewBox="0 0 256 256"
      width={dimensions.icon}
      height={dimensions.icon}
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      className="shrink-0 select-none"
      aria-hidden="true"
    >
      <title>SecuriPulse</title>
      {/* Outer Defensive Shield */}
      <path
        d="M128 24 L48 54 V126 C48 180 82 226 128 238 C174 226 208 180 208 126 V54 Z"
        stroke="#ffffff"
        strokeWidth="18"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      {/* Inner Telemetry Pulse Wave */}
      <path
        d="M64 128 H96 L112 156 L128 72 L144 156 L160 128 H192"
        stroke="#a1a1aa"
        strokeWidth="18"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      <circle cx="128" cy="72" r="5" fill="#ffffff" />
    </svg>
  );

  if (variant === 'mark' || variant === 'icon') {
    return (
      <div
        className={`inline-flex items-center justify-center rounded-md bg-white/[0.04] border border-white/[0.08] p-1.5 ${className}`}
      >
        {MarkSvg}
      </div>
    );
  }

  const isArabic = lang === 'ar';

  return (
    <div className={`flex items-center gap-2.5 select-none ${className}`}>
      <div className="rounded-md bg-white/[0.04] border border-white/[0.08] p-1.5 flex items-center justify-center">
        {MarkSvg}
      </div>
      <div>
        <div className="flex items-center gap-2">
          <span className={`font-semibold tracking-tight text-white ${dimensions.text}`}>
            {isArabic ? 'سيكيوريبلس' : 'SecuriPulse'}
          </span>
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
        </div>
        <p className="text-[11px] text-zinc-500 hidden sm:block">
          {isArabic
            ? 'فحص ثغرات الواجهات ومحاكاة الهجمات السيبرانية'
            : 'Vulnerability Auditor & Threat Simulator'}
        </p>
      </div>
    </div>
  );
}
