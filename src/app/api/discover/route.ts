// ============================================================================
// API ROUTE: AUTOMATED ENDPOINT DISCOVERY (POST /api/discover)
// ============================================================================
import { NextRequest, NextResponse } from 'next/server';
import { crawlAndDiscoverEndpoints } from '@/lib/endpoint-crawler';

export const dynamic = 'force-dynamic';
export const maxDuration = 30;

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const targetUrl = body.targetUrl;

    if (!targetUrl || typeof targetUrl !== 'string') {
      return NextResponse.json(
        { success: false, error: 'Target URL is required' },
        { status: 400 }
      );
    }

    const discovery = await crawlAndDiscoverEndpoints(targetUrl);

    return NextResponse.json({
      success: true,
      discovery,
    });
  } catch (error) {
    return NextResponse.json(
      {
        success: false,
        error: error instanceof Error ? error.message : 'Discovery error',
      },
      { status: 500 }
    );
  }
}
