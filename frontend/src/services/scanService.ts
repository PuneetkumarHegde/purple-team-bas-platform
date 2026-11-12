// ===========================
// scanService.ts
// ©AngelaMos | 2025
// Extended with Crawler & Purple Team API calls
// ===========================

import { SCAN_ENDPOINTS } from '@/config/constants'
import { api } from '@/lib/api'
import type {
  CrawlRequest,
  CrawlResponse,
  CreateScanRequest,
  CreateScanResponse,
  GetScanResponse,
  GetScansResponse,
  PurpleTeamResponse,
  DiscoveredEndpoint,
  ScanTestType,
} from '@/types/scan.types'

export interface PurpleTeamRequestPayload {
  base_url: string
  endpoints: DiscoveredEndpoint[]
  tests_to_run: ScanTestType[]
  auth_token?: string | null
  token_attacker?: string | null
}

export const scanQueryKeys = {
  all: ['scans'] as const,
  lists: () => [...scanQueryKeys.all, 'list'] as const,
  list: () => [...scanQueryKeys.lists()] as const,
  details: () => [...scanQueryKeys.all, 'detail'] as const,
  detail: (id: number) => [...scanQueryKeys.details(), id] as const,
} as const

export const scanQueries = {
  getScans: async (): Promise<GetScansResponse> => {
    return api.get<GetScansResponse>(SCAN_ENDPOINTS.LIST)
  },

  getScan: async (id: number): Promise<GetScanResponse> => {
    return api.get<GetScanResponse>(SCAN_ENDPOINTS.GET(id))
  },
}

export const scanMutations = {
  createScan: async (data: CreateScanRequest): Promise<CreateScanResponse> => {
    return api.post<CreateScanResponse>(SCAN_ENDPOINTS.CREATE, data)
  },

  deleteScan: async (id: number): Promise<void> => {
    await api.delete<undefined>(SCAN_ENDPOINTS.DELETE(id))
  },

  crawlApi: async (data: CrawlRequest): Promise<CrawlResponse> => {
    return api.post<CrawlResponse>('/scans/crawl', data)
  },

  executePurpleTeam: async (data: PurpleTeamRequestPayload): Promise<PurpleTeamResponse> => {
    return api.post<PurpleTeamResponse>('/scans/purple-team', data)
  },
}
