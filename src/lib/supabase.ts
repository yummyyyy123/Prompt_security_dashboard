import { createClient, SupabaseClient } from '@supabase/supabase-js'

// Lazy initialization of Supabase client
let supabaseClient: SupabaseClient | null = null

function getSupabaseClient(): SupabaseClient {
  if (!supabaseClient) {
    const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL
    const supabaseServiceKey = process.env.SUPABASE_SERVICE_KEY

    if (!supabaseUrl || !supabaseServiceKey) {
      console.warn('Supabase environment variables not set, using mock client for build compatibility')
      // Create a minimal mock client that satisfies the SupabaseClient interface
      supabaseClient = createClient('https://mock.supabase.co', 'mock-key')
    } else {
      supabaseClient = createClient(supabaseUrl, supabaseServiceKey)
    }
  }
  return supabaseClient
}

// Export the lazy-initialized client - guaranteed to never be null
export const supabase = getSupabaseClient()

// Database types
export interface DatabasePrompt {
  id: string
  title: string
  description: string
  category: string
  tags: string[]
  prompt: string
  variables: string[]
  created_at: string
  usage_count: number
  is_favorite: boolean
}

export interface DatabaseSubmission {
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

// Prompt operations
export async function getPromptsFromDB() {
  try {
    const { data, error } = await supabase
      .from('prompts')
      .select('*')
      .order('created_at', { ascending: false })

    if (error) throw error
    return { prompts: data || [] }
  } catch (error) {
    console.error('Error fetching prompts:', error)
    return { prompts: [] }
  }
}

export async function addPromptToDB(prompt: Omit<DatabasePrompt, 'id' | 'created_at' | 'usage_count' | 'is_favorite'>) {
  try {
    const { data, error } = await supabase
      .from('prompts')
      .insert({
        ...prompt,
        created_at: new Date().toISOString(),
        usage_count: 0,
        is_favorite: false
      })
      .select()
      .single()

    if (error) throw error
    return data
  } catch (error) {
    console.error('Error adding prompt:', error)
    throw error
  }
}

export async function updatePromptInDB(id: string, updates: Partial<DatabasePrompt>) {
  try {
    const { data, error } = await supabase
      .from('prompts')
      .update(updates)
      .eq('id', id)
      .select()
      .single()

    if (error) throw error
    return data
  } catch (error) {
    console.error('Error updating prompt:', error)
    throw error
  }
}

export async function deletePromptFromDB(id: string) {
  try {
    const { error } = await supabase
      .from('prompts')
      .delete()
      .eq('id', id)

    if (error) throw error
    return true
  } catch (error) {
    console.error('Error deleting prompt:', error)
    throw error
  }
}

// Submission operations
export async function getSubmissionsFromDB(status?: string) {
  try {
    let query = supabase
      .from('submissions')
      .select('*')
      .order('submitted_at', { ascending: false })

    if (status && status !== 'all') {
      query = query.eq('status', status)
    }

    const { data, error } = await query

    if (error) throw error
    return data || []
  } catch (error) {
    console.error('Error fetching submissions:', error)
    return []
  }
}

export async function addSubmissionToDB(submission: Omit<DatabaseSubmission, 'id' | 'submitted_at'>) {
  try {
    const { data, error } = await supabase
      .from('submissions')
      .insert({
        ...submission,
        submitted_at: new Date().toISOString()
      })
      .select()
      .single()

    if (error) throw error
    return data
  } catch (error) {
    console.error('Error adding submission:', error)
    throw error
  }
}

export async function updateSubmissionInDB(id: string, updates: Partial<DatabaseSubmission>) {
  try {
    const { data, error } = await supabase
      .from('submissions')
      .update(updates)
      .eq('id', id)
      .select()
      .single()

    if (error) throw error
    return data
  } catch (error) {
    console.error('Error updating submission:', error)
    throw error
  }
}

export async function approveSubmissionInDB(submissionId: string) {
  try {
    // First, get the submission
    const { data: submission, error: fetchError } = await supabase
      .from('submissions')
      .select('*')
      .eq('id', submissionId)
      .single()

    if (fetchError) throw fetchError

    // Update submission status
    const { error: updateError } = await supabase
      .from('submissions')
      .update({
        status: 'approved',
        reviewed_at: new Date().toISOString(),
        reviewed_by: 'admin'
      })
      .eq('id', submissionId)

    if (updateError) throw updateError

    // Add to prompts table
    const { error: insertError } = await supabase
      .from('prompts')
      .insert({
        id: submission.id,
        title: submission.title,
        description: submission.description,
        category: submission.category,
        tags: submission.tags,
        prompt: submission.prompt,
        variables: submission.variables,
        created_at: submission.submitted_at,
        usage_count: 0,
        is_favorite: false
      })

    if (insertError) throw insertError

    return true
  } catch (error) {
    console.error('Error approving submission:', error)
    throw error
  }
}

export async function rejectSubmissionInDB(submissionId: string, reason: string) {
  try {
    const { error } = await supabase
      .from('submissions')
      .update({
        status: 'rejected',
        reviewed_at: new Date().toISOString(),
        reviewed_by: 'admin',
        rejection_reason: reason
      })
      .eq('id', submissionId)

    if (error) throw error
    return true
  } catch (error) {
    console.error('Error rejecting submission:', error)
    throw error
  }
}

// Statistics
export async function getSubmissionStats() {
  try {
    const { data, error } = await supabase
      .from('submissions')
      .select('status, submitted_at')

    if (error) throw error

    const stats = {
      total: data?.length || 0,
      pending: data?.filter(s => s.status === 'pending').length || 0,
      approved: data?.filter(s => s.status === 'approved').length || 0,
      rejected: data?.filter(s => s.status === 'rejected').length || 0,
      thisWeek: data?.filter(s => {
        const submissionDate = new Date(s.submitted_at)
        const weekAgo = new Date()
        weekAgo.setDate(weekAgo.getDate() - 7)
        return submissionDate >= weekAgo
      }).length || 0,
      thisMonth: data?.filter(s => {
        const submissionDate = new Date(s.submitted_at)
        const monthAgo = new Date()
        monthAgo.setMonth(monthAgo.getMonth() - 1)
        return submissionDate >= monthAgo
      }).length || 0
    }

    return stats
  } catch (error) {
    console.error('Error fetching stats:', error)
    return {
      total: 0,
      pending: 0,
      approved: 0,
      rejected: 0,
      thisWeek: 0,
      thisMonth: 0
    }
  }
}
