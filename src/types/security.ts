// ============================================================================
// TYPES & INTERFACES: SECURITY AUDIT & SIMULATION ENGINE
// ============================================================================

export type AttackIntensity = 'gentle' | 'standard' | 'rigorous';

export type VulnerabilityCategory =
  | 'sqli'
  | 'xss'
  | 'auth'
  | 'ports'
  | 'subdomain'
  | 'headers';

export type SeverityLevel = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type ProbeStatus =
  | 'pending'
  | 'running'
  | 'passed'
  | 'warning'
  | 'failed'
  | 'blocked';

export interface SecurityProbePayload {
  id: string;
  category: VulnerabilityCategory;
  name: string;
  nameAr: string;
  description: string;
  descriptionAr: string;
  method: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'OPTIONS' | 'HEAD';
  targetPath: string;
  headers: Record<string, string>;
  payloadCode: string;
  canaryExpectedOutcome: string;
  canaryExpectedOutcomeAr: string;
  intensityLevel: AttackIntensity;
  enabled: boolean;
  endpointSource?: 'custom' | 'discovered' | 'system';
}

export interface DiscoveredEndpoint {
  id: string;
  path: string;
  method: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'OPTIONS' | 'HEAD';
  source: 'js_bundle' | 'sitemap' | 'robots' | 'spec_guess' | 'user_defined' | 'supabase_table';
  statusCode?: number;
  tested: boolean;
  selected: boolean;
  description?: string;
  detectedParameters?: string[];
}

export type ApiArchitecture =
  | 'co_located_serverless'
  | 'external_backend'
  | 'supabase_baas'
  | 'frontend_only';

export interface EndpointDiscoveryResult {
  targetUrl: string;
  detectedApiBaseUrl?: string;
  apiArchitecture: ApiArchitecture;
  endpoints: DiscoveredEndpoint[];
  crawledScriptsCount: number;
  status: 'success' | 'partial' | 'failed';
  error?: string;
}

export interface AuditConfig {
  targetUrl: string;
  apiBaseUrl?: string; // Optional custom or detected API base URL (e.g. https://api.site.com)
  intensity: AttackIntensity;
  concurrency: number; // 1 to 8 workers
  delayMs: number;     // 0ms to 1000ms delay between requests
  enabledCategories: Record<VulnerabilityCategory, boolean>;
  customPayloads: SecurityProbePayload[];
  endpointsToTest?: DiscoveredEndpoint[];
  simulatedTarget?: boolean;
}

export interface LiveTelemetryEvent {
  id: string;
  timestamp: string;
  threadId: number;
  category: VulnerabilityCategory;
  probeId: string;
  probeName: string;
  probeNameAr: string;
  method: string;
  url: string;
  sentPayloadSnippet: string;
  headersSent: Record<string, string>;
  statusCode: number;
  latencyMs: number;
  status: ProbeStatus;
  evidence: string;
  severity: SeverityLevel;
  explanation: string;
  explanationAr: string;
}

export interface VulnerabilityFinding {
  id: string;
  category: VulnerabilityCategory;
  title: string;
  titleAr: string;
  severity: SeverityLevel;
  description: string;
  descriptionAr: string;
  whyItMatters: string;
  whyItMattersAr: string;
  evidencePayload: string;
  evidenceResponse: string;
  recommendation: string;
  recommendationAr: string;
  codeFixSnippet: string;
  fixFileName: string;
}

export interface AuditReport {
  targetUrl: string;
  apiBaseUrl?: string;
  startedAt: string;
  completedAt: string;
  totalDurationMs: number;
  score: number; // 0 - 100
  intensity: AttackIntensity;
  totalProbesRun: number;
  defendedCount: number;
  warningCount: number;
  vulnerableCount: number;
  findings: VulnerabilityFinding[];
}
