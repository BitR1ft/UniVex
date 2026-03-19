import axios from 'axios';

const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000/api';

const apiClient = axios.create({
  baseURL: API_URL,
  headers: {
    'Content-Type': 'application/json',
  },
  withCredentials: true,
});

apiClient.interceptors.request.use((config) => {
  if (typeof window !== 'undefined') {
    const token = localStorage.getItem('access_token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
  }
  return config;
});

// Token refresh on 401 – retry original request once with new token
let isRefreshing = false;
let refreshQueue: Array<(token: string) => void> = [];

apiClient.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;

    if (
      error.response?.status === 401 &&
      !originalRequest._retry &&
      typeof window !== 'undefined'
    ) {
      const refreshToken = localStorage.getItem('refresh_token');
      if (!refreshToken) return Promise.reject(error);

      originalRequest._retry = true;

      if (isRefreshing) {
        return new Promise<string>((resolve) => {
          refreshQueue.push(resolve);
        }).then((token) => {
          originalRequest.headers.Authorization = `Bearer ${token}`;
          return apiClient(originalRequest);
        });
      }

      isRefreshing = true;
      try {
        const res = await axios.post(`${API_URL}/auth/refresh`, { refresh_token: refreshToken });
        const newToken: string = res.data.access_token;
        localStorage.setItem('access_token', newToken);
        if (res.data.refresh_token) {
          localStorage.setItem('refresh_token', res.data.refresh_token);
        }
        refreshQueue.forEach((cb) => cb(newToken));
        refreshQueue = [];
        originalRequest.headers.Authorization = `Bearer ${newToken}`;
        return apiClient(originalRequest);
      } catch (refreshError) {
        if (process.env.NODE_ENV !== 'production') {
          console.warn('[API] Token refresh failed, redirecting to login', refreshError);
        }
        localStorage.removeItem('access_token');
        localStorage.removeItem('refresh_token');
        if (typeof window !== 'undefined') {
          window.location.href = '/auth/login';
        }
        return Promise.reject(error);
      } finally {
        isRefreshing = false;
      }
    }

    return Promise.reject(error);
  }
);

export const authApi = {
  login: (credentials: { username: string; password: string }) =>
    apiClient.post('/auth/login', credentials),
  
  register: (data: { username: string; email: string; password: string }) =>
    apiClient.post('/auth/register', data),
  
  logout: () => apiClient.post('/auth/logout'),
  
  getCurrentUser: () => apiClient.get('/auth/me'),
  
  refreshToken: () => apiClient.post('/auth/refresh'),
};

export interface Project {
  id: string;
  name: string;
  description?: string;
  target: string;
  status: string;
  enable_subdomain_enum: boolean;
  enable_port_scan: boolean;
  enable_web_crawl: boolean;
  enable_tech_detection: boolean;
  enable_vuln_scan: boolean;
  enable_nuclei: boolean;
  enable_auto_exploit: boolean;
  created_at: string;
  updated_at: string;
  user_id: string;
}

export interface CreateProjectDto {
  name: string;
  description?: string;
  target: string;
  enable_subdomain_enum?: boolean;
  enable_port_scan?: boolean;
  enable_web_crawl?: boolean;
  enable_tech_detection?: boolean;
  enable_vuln_scan?: boolean;
  enable_nuclei?: boolean;
  enable_auto_exploit?: boolean;
}

export const projectsApi = {
  getAll: () => apiClient.get<Project[]>('/projects'),
  
  getById: (id: string) => apiClient.get<Project>(`/projects/${id}`),
  
  create: (data: CreateProjectDto) => apiClient.post<Project>('/projects', data),
  
  update: (id: string, data: Partial<CreateProjectDto>) =>
    apiClient.put<Project>(`/projects/${id}`, data),
  
  delete: (id: string) => apiClient.delete(`/projects/${id}`),
  
  start: (id: string) => apiClient.post(`/projects/${id}/start`),
  
  stop: (id: string) => apiClient.post(`/projects/${id}/stop`),
};

// Graph types
export interface GraphNode {
  id: string;
  labels: string[];
  properties: Record<string, any>;
}

export interface GraphRelationship {
  id: string;
  type: string;
  startNode: string;
  endNode: string;
  properties: Record<string, any>;
}

export interface AttackSurfaceData {
  nodes: GraphNode[];
  relationships: GraphRelationship[];
}

export interface GraphStats {
  node_counts: Record<string, number>;
  total_nodes: number;
}

export const graphApi = {
  getAttackSurface: (projectId: string) =>
    apiClient.get<{ success: boolean; project_id: string; data: AttackSurfaceData }>(`/graph/attack-surface/${projectId}`),

  getVulnerabilities: (projectId: string, severity?: string) =>
    apiClient.get(`/graph/vulnerabilities/${projectId}`, { params: severity ? { severity } : {} }),

  getTechnologies: (projectId: string, withCves?: boolean) =>
    apiClient.get(`/graph/technologies/${projectId}`, { params: withCves ? { with_cves: true } : {} }),

  getStats: (projectId: string) =>
    apiClient.get<{ success: boolean; project_id: string } & GraphStats>(`/graph/stats/${projectId}`),

  getHealth: () =>
    apiClient.get('/graph/health'),
};

// ---------------------------------------------------------------------------
// Reports API
// ---------------------------------------------------------------------------

export type ReportTemplate = 'technical_report' | 'executive_summary' | 'compliance_report';
export type ReportFormat = 'html' | 'pdf';
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface FindingDto {
  title: string;
  description?: string;
  severity: Severity;
  cvss_score?: number;
  cve_id?: string;
  cwe_id?: string;
  owasp_category?: string;
  nist_controls?: string[];
  pci_dss_requirements?: string[];
  reproduction_steps?: string[];
  evidence?: string;
  remediation?: string;
  affected_component?: string;
  likelihood?: string;
  business_impact?: string;
}

export interface ScanResultDto {
  target: string;
  scan_type?: string;
  findings: FindingDto[];
  metadata?: Record<string, unknown>;
}

export interface GenerateReportDto {
  project_name: string;
  author: string;
  client_name?: string;
  title: string;
  template: ReportTemplate;
  format: ReportFormat;
  include_charts?: boolean;
  include_toc?: boolean;
  scan_results: ScanResultDto[];
  confidentiality?: string;
}

export interface ReportSummary {
  id: string;
  project_name: string;
  title: string;
  template: string;
  format: string;
  finding_count: number;
  risk_level: string;
  risk_score: number;
  created_at: string;
  author: string;
}

export const reportsApi = {
  generate: (data: GenerateReportDto) =>
    apiClient.post<ReportSummary>('/reports/generate', data),

  getAll: (params?: { limit?: number; offset?: number }) =>
    apiClient.get<ReportSummary[]>('/reports', { params }),

  getById: (id: string) =>
    apiClient.get<ReportSummary>(`/reports/${id}`),

  download: (id: string, format?: ReportFormat) =>
    apiClient.get(`/reports/${id}/download`, {
      params: format ? { format } : undefined,
      responseType: 'blob',
    }),

  delete: (id: string) =>
    apiClient.delete(`/reports/${id}`),
};

export default apiClient;
