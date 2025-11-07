import axios from 'axios'

const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000'

const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
})

export interface Attack {
  id: number
  timestamp: string
  source_ip: string
  dest_ip: string
  dest_port?: number
  url: string
  method: string
  attack_type: string
  attack_subtype?: string
  success_status: boolean
  severity: string
  confidence_score: number
  detection_method: string
  user_agent?: string
  referer?: string
  raw_request?: string
}

export interface AttackListResponse {
  total: number
  skip: number
  limit: number
  attacks: Attack[]
}

export interface StatsResponse {
  total_attacks: number
  recent_24h: number
  attack_types: Array<{ type: string; count: number }>
  severities: Array<{ severity: string; count: number }>
  top_attacking_ips: Array<{ ip: string; count: number }>
}

export interface TimelineDataPoint {
  timestamp: string
  count: number
  by_type: Record<string, number>
}

export interface TimelineResponse {
  period_hours: number
  timeline: TimelineDataPoint[]
}

export interface DetectionResult {
  is_attack: boolean
  attack_type?: string
  attack_subtype?: string
  confidence_score: number
  severity: string
  detection_method: string
  matched_patterns: string[]
  id?: number
}

// API functions
export const apiService = {
  // Analyze single URL
  analyzeURL: async (url: string, options?: {
    method?: string
    source_ip?: string
    dest_ip?: string
    user_agent?: string
  }): Promise<DetectionResult> => {
    const response = await api.post('/api/analyze/url', {
      url,
      ...options,
      store_result: true,
    })
    return response.data
  },

  // Upload PCAP file
  uploadPCAP: async (file: File) => {
    const formData = new FormData()
    formData.append('file', file)
    const response = await api.post('/api/upload/pcap', formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
    })
    return response.data
  },

  // Get attacks list
  getAttacks: async (params?: {
    skip?: number
    limit?: number
    attack_type?: string
    severity?: string
    source_ip?: string
    start_date?: string
    end_date?: string
    success_status?: boolean
  }): Promise<AttackListResponse> => {
    const response = await api.get('/api/attacks', { params })
    return response.data
  },

  // Get single attack detail
  getAttackDetail: async (id: number): Promise<Attack> => {
    const response = await api.get(`/api/attacks/${id}`)
    return response.data
  },

  // Get statistics
  getStats: async (): Promise<StatsResponse> => {
    const response = await api.get('/api/stats/summary')
    return response.data
  },

  // Get timeline data
  getTimeline: async (hours: number = 24): Promise<TimelineResponse> => {
    const response = await api.get('/api/stats/timeline', {
      params: { hours },
    })
    return response.data
  },

  // Export to CSV
  exportCSV: async (filters?: {
    attack_type?: string
    severity?: string
    start_date?: string
    end_date?: string
  }) => {
    const response = await api.get('/api/export/csv', {
      params: filters,
      responseType: 'blob',
    })
    return response.data
  },

  // Export to JSON
  exportJSON: async (filters?: {
    attack_type?: string
    severity?: string
    start_date?: string
    end_date?: string
  }) => {
    const response = await api.get('/api/export/json', { params: filters })
    return response.data
  },
}

export default api
