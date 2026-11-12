// ===========================
// scan.types.ts
// ©AngelaMos | 2025
// ===========================

import type { ScanStatus, ScanTestType, Severity } from '@/config/constants'

export type { ScanTestType, ScanStatus, Severity }

export interface TestResult {
  id: number
  scan_id: number
  test_name: ScanTestType
  status: ScanStatus
  severity: Severity
  details: string
  evidence_json: Record<string, unknown>
  recommendations_json: string[]
  created_at: string
}

export interface Scan {
  id: number
  user_id: number
  target_url: string
  scan_date: string
  created_at: string
  test_results: TestResult[]
}

export interface CreateScanRequest {
  target_url: string
  auth_token: string | null
  tests_to_run: ScanTestType[]
  max_requests: number
}

export type CreateScanResponse = Scan

export type GetScansResponse = Scan[]

export type GetScanResponse = Scan

// ==========================================
// Purple-Team & Crawler Types
// ==========================================

export interface DiscoveredEndpoint {
  path: string
  method: string
  summary: string
  target_url: string
  parameters: Array<{ name: string; in: string; required: boolean; type: string }>
  requires_auth: boolean
  tags: string[]
}

export interface CrawlRequest {
  target_url: string
  crawl_mode: 'auto' | 'openapi' | 'spider'
}

export interface CrawlResponse {
  discovered: boolean
  endpoints_count: number
  endpoints: DiscoveredEndpoint[]
  source: string
  spec_url: string | null
  title: string
  message: string
}

export interface PurpleTeamTelemetry {
  endpoint: string
  method: string
  test_name: string
  payload_sample: string
  vulnerability_status: 'safe' | 'vulnerable' | 'error'
  severity: 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
  ai_threat_score: number
  ai_matched_rules: string[]
  defense_verdict: 'CAUGHT_BY_AI' | 'STEALTH_BYPASS' | 'BENIGN_TRAFFIC'
  remediation_patch: string
}

export interface PurpleTeamResponse {
  target_url: string
  scan_date: string
  total_endpoints_scanned: number
  total_attacks_simulated: number
  vulnerabilities_found: number
  ai_detected_count: number
  ai_bypassed_count: number
  defense_coverage_percent: number
  waf_info?: Record<string, any>
  telemetry: PurpleTeamTelemetry[]
}
