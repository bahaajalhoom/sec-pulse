// ============================================================================
// 1. IMPORTS
// ============================================================================
import { NextRequest, NextResponse } from 'next/server';
import { AuditConfig, AuditReport, VulnerabilityFinding } from '@/types/security';
import { INITIAL_PROBES } from '@/lib/constants';
import {
  executeRealProbe,
  generateDynamicProbes,
  normalizeTargetUrl,
} from '@/lib/security-engine';

// ============================================================================
// 2. CONFIGURATION & CONSTANTS
// ============================================================================
export const dynamic = 'force-dynamic';
export const maxDuration = 60; // 60s max execution

// ============================================================================
// 3. API ROUTE HANDLER (POST /api/audit)
// ============================================================================
export async function POST(request: NextRequest) {
  try {
    const isStreamRequested = request.nextUrl.searchParams.get('stream') === 'true';
    const body = (await request.json()) as Partial<AuditConfig>;

    const targetUrl = normalizeTargetUrl(body.targetUrl || 'https://example.com');
    const apiBaseUrl = body.apiBaseUrl ? body.apiBaseUrl.trim() : undefined;
    const intensity = body.intensity || 'standard';
    const concurrency = Math.min(Math.max(body.concurrency || 2, 1), 8);
    const delayMs = body.delayMs || 30;

    let probeCatalog =
      body.customPayloads && body.customPayloads.length > 0
        ? body.customPayloads
        : INITIAL_PROBES;

    // Dynamically bind ONLY valid probes (avoiding phantom /api/ 404 spam if no API exists)
    probeCatalog = generateDynamicProbes(
      body.endpointsToTest || [],
      probeCatalog,
      Boolean(apiBaseUrl)
    );

    const activeProbes = probeCatalog.filter((probe) => {
      if (!probe.enabled) return false;
      if (body.enabledCategories && !body.enabledCategories[probe.category]) {
        return false;
      }
      return true;
    });

    const startedAt = new Date().toISOString();
    const startTime = Date.now();

    // Streaming mode (SSE)
    if (isStreamRequested) {
      const encoder = new TextEncoder();

      const stream = new ReadableStream({
        async start(controller) {
          const telemetryEvents = [];
          const findings: VulnerabilityFinding[] = [];
          let defendedCount = 0;
          let warningCount = 0;
          let vulnerableCount = 0;

          try {
            for (let i = 0; i < activeProbes.length; i += concurrency) {
              const batch = activeProbes.slice(i, i + concurrency);
              const batchPromises = batch.map((probe, batchIndex) => {
                const threadId = (batchIndex % concurrency) + 1;
                return executeRealProbe(probe, targetUrl, apiBaseUrl, threadId, intensity);
              });

              const results = await Promise.all(batchPromises);

              for (const res of results) {
                telemetryEvents.push(res.event);
                if (res.event.status === 'passed') defendedCount++;
                if (res.event.status === 'warning') warningCount++;
                if (res.event.status === 'failed') vulnerableCount++;
                if (res.finding) findings.push(res.finding);

                const chunk = `data: ${JSON.stringify({ type: 'event', event: res.event })}\n\n`;
                controller.enqueue(encoder.encode(chunk));
              }

              if (delayMs > 0 && i + concurrency < activeProbes.length) {
                await new Promise((r) => setTimeout(r, delayMs));
              }
            }

            const completedAt = new Date().toISOString();
            const totalDurationMs = Date.now() - startTime;

            let deduction = 0;
            for (const f of findings) {
              if (f.severity === 'critical') deduction += 25;
              else if (f.severity === 'high') deduction += 15;
              else if (f.severity === 'medium') deduction += 8;
              else deduction += 3;
            }
            const score = Math.max(10, Math.min(100, 100 - deduction));

            const report: AuditReport = {
              targetUrl,
              apiBaseUrl,
              startedAt,
              completedAt,
              totalDurationMs,
              score,
              intensity,
              totalProbesRun: activeProbes.length,
              defendedCount,
              warningCount,
              vulnerableCount,
              findings,
            };

            const finalChunk = `data: ${JSON.stringify({ type: 'report', report })}\n\n`;
            controller.enqueue(encoder.encode(finalChunk));
            controller.close();
          } catch (streamErr) {
            const errChunk = `data: ${JSON.stringify({
              type: 'error',
              error: streamErr instanceof Error ? streamErr.message : 'Scan error',
            })}\n\n`;
            controller.enqueue(encoder.encode(errChunk));
            controller.close();
          }
        },
      });

      return new Response(stream, {
        headers: {
          'Content-Type': 'text/event-stream; charset=utf-8',
          'Cache-Control': 'no-cache, no-transform',
          'Connection': 'keep-alive',
        },
      });
    }

    // Standard JSON response
    const telemetryEvents = [];
    const findings: VulnerabilityFinding[] = [];
    let defendedCount = 0;
    let warningCount = 0;
    let vulnerableCount = 0;

    for (let i = 0; i < activeProbes.length; i += concurrency) {
      const batch = activeProbes.slice(i, i + concurrency);
      const batchPromises = batch.map((probe, batchIndex) => {
        const threadId = (batchIndex % concurrency) + 1;
        return executeRealProbe(probe, targetUrl, apiBaseUrl, threadId, intensity);
      });

      const results = await Promise.all(batchPromises);

      for (const res of results) {
        telemetryEvents.push(res.event);
        if (res.event.status === 'passed') defendedCount++;
        if (res.event.status === 'warning') warningCount++;
        if (res.event.status === 'failed') vulnerableCount++;
        if (res.finding) findings.push(res.finding);
      }

      if (delayMs > 0 && i + concurrency < activeProbes.length) {
        await new Promise((r) => setTimeout(r, delayMs));
      }
    }

    const completedAt = new Date().toISOString();
    const totalDurationMs = Date.now() - startTime;

    let deduction = 0;
    for (const f of findings) {
      if (f.severity === 'critical') deduction += 25;
      else if (f.severity === 'high') deduction += 15;
      else if (f.severity === 'medium') deduction += 8;
      else deduction += 3;
    }
    const score = Math.max(10, Math.min(100, 100 - deduction));

    const report: AuditReport = {
      targetUrl,
      apiBaseUrl,
      startedAt,
      completedAt,
      totalDurationMs,
      score,
      intensity,
      totalProbesRun: activeProbes.length,
      defendedCount,
      warningCount,
      vulnerableCount,
      findings,
    };

    return NextResponse.json({
      success: true,
      report,
      telemetry: telemetryEvents,
    });
  } catch (error) {
    return NextResponse.json(
      {
        success: false,
        error: error instanceof Error ? error.message : 'Internal audit error',
      },
      { status: 500 }
    );
  }
}
