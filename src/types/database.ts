// Database schema for prompt submissions and admin management

export interface PromptSubmission {
  id: string
  title: string
  description: string
  category: string
  tags: string[]
  prompt: string
  variables: string[]
  status: 'pending' | 'approved' | 'rejected'
  submitted_by: string
  submitted_at: string
  reviewed_by?: string
  reviewed_at?: string
  rejection_reason?: string
  usage_count?: number
  is_favorite?: boolean
}

export interface AdminUser {
  id: string
  username: string
  email: string
  role: 'admin' | 'super_admin'
  createdAt: string
  lastLogin?: string
}

export interface SubmissionStats {
  total: number
  pending: number
  approved: number
  rejected: number
  thisWeek: number
  thisMonth: number
}
