import type { Metadata, Viewport } from 'next';
import { Cairo, JetBrains_Mono } from 'next/font/google';
import './globals.css';

const cairo = Cairo({
  subsets: ['arabic', 'latin'],
  variable: '--font-cairo',
  display: 'swap',
  weight: ['400', '500', '600', '700', '800'],
});

const jetbrainsMono = JetBrains_Mono({
  subsets: ['latin'],
  variable: '--font-mono',
  display: 'swap',
  weight: ['400', '500', '600', '700'],
});

export const viewport: Viewport = {
  themeColor: '#141414',
  colorScheme: 'dark',
};

export const metadata: Metadata = {
  title: 'SecuriPulse | سيكيوريبلس — Enterprise Threat Simulator & API Security Auditor',
  description:
    'Advanced automated web vulnerability auditor, defensive threat simulation engine with 42 active attack vectors, real API crawler, and AI-powered remediation.',
  metadataBase: new URL('https://securipulse.app'),
  applicationName: 'SecuriPulse',
  authors: [{ name: 'Bahaa Jalhoom', url: 'https://github.com/bahaajalhoom' }],
  keywords: [
    'cybersecurity',
    'security auditor',
    'threat simulation',
    'pentesting',
    'API security',
    'XSS detection',
    'SQL injection canary',
    'CORS audit',
    'SSRF prevention',
    'security headers',
    'SecuriPulse',
    'سيكيوريبلس',
  ],
  icons: {
    icon: [
      { url: '/favicon.ico', sizes: '48x48' },
      { url: '/favicon.svg', type: 'image/svg+xml' },
      { url: '/icon.svg', type: 'image/svg+xml' },
    ],
    apple: [{ url: '/apple-touch-icon.png', sizes: '180x180' }],
    other: [
      { rel: 'icon', url: '/favicon-32.png', sizes: '32x32', type: 'image/png' },
      { rel: 'icon', url: '/favicon-16.png', sizes: '16x16', type: 'image/png' },
    ],
  },
  manifest: '/site.webmanifest',
  openGraph: {
    type: 'website',
    locale: 'ar_SA',
    alternateLocale: ['en_US'],
    url: 'https://securipulse.app',
    title: 'SecuriPulse | سيكيوريبلس — Enterprise Defensive Threat Simulator',
    description:
      '42 Active attack probes, deep API endpoint discovery, real-time threat telemetry, and zero-slop enterprise remediation blueprints.',
    siteName: 'SecuriPulse',
    images: [
      {
        url: '/og-image.png',
        width: 1200,
        height: 630,
        alt: 'SecuriPulse Defensive Cyber Threat Simulator Cockpit',
      },
    ],
  },
  twitter: {
    card: 'summary_large_image',
    title: 'SecuriPulse | سيكيوريبلس — Enterprise Threat Simulator',
    description:
      '42 Active attack vectors, live network threat probing, and automated API discovery with instant AI remediation.',
    images: ['/og-image.png'],
    creator: '@bahaajalhoom',
  },
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html
      lang="ar"
      dir="rtl"
      className={`dark ${cairo.variable} ${jetbrainsMono.variable}`}
    >
      <head>
        <link rel="icon" href="/favicon.ico" sizes="48x48" />
        <link rel="icon" href="/favicon.svg" type="image/svg+xml" />
        <link rel="apple-touch-icon" href="/apple-touch-icon.png" />
      </head>
      <body className="bg-[#08090d] text-slate-100 antialiased font-sans selection:bg-blue-600 selection:text-white min-h-screen">
        {children}
      </body>
    </html>
  );
}
