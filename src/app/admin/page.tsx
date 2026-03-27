'use client'

import { useState, useEffect } from 'react'
import { motion } from 'framer-motion'
import { Search, Check, X, Eye, TrendingUp, Clock, Users, FileText, Filter, ChevronDown, LogOut, Shield, AlertCircle, Trash2, Plus, Type, Tag as TagIcon } from 'lucide-react'
import { PromptSubmission, SubmissionStats } from '@/types/database'
import { useRouter } from 'next/navigation'
import AdminAuthCheck from '@/components/AdminAuthCheck'

export default function AdminPanel() {
  const [submissions, setSubmissions] = useState<PromptSubmission[]>([])
  const [stats, setStats] = useState<SubmissionStats | null>(null)
  const [loading, setLoading] = useState(true)
  const [fetchError, setFetchError] = useState<string | null>(null)
  const [selectedSubmission, setSelectedSubmission] = useState<PromptSubmission | null>(null)
  const [filterStatus, setFilterStatus] = useState<'all' | 'pending' | 'approved' | 'rejected'>('all')
  const [searchQuery, setSearchQuery] = useState('')
  const [showRejectModal, setShowRejectModal] = useState(false)
  const [rejectionReason, setRejectionReason] = useState('')
  const [rejectionId, setRejectionId] = useState('')
  const [approvedPrompts, setApprovedPrompts] = useState<any[]>([])
  const [loadingApproved, setLoadingApproved] = useState(true)
  const [showDeleteAllConfirmation, setShowDeleteAllConfirmation] = useState(false)
  const [showAddPromptModal, setShowAddPromptModal] = useState(false)
  const [newPrompt, setNewPrompt] = useState({
    title: '',
    description: '',
    category: 'Marketing',
    tags: '',
    prompt: '',
    variables: ''
  })
  const [isAddingPrompt, setIsAddingPrompt] = useState(false)
  const router = useRouter()

  useEffect(() => {
    fetchData()
    fetchApprovedPrompts()

    // Prevent back button access after logout
    if (typeof window !== 'undefined') {
      const preventBack = () => {
        window.history.pushState(null, '', window.location.href)
      }
      window.addEventListener('popstate', preventBack)
      preventBack()

      return () => {
        window.removeEventListener('popstate', preventBack)
      }
    }
  }, [])

  const fetchApprovedPrompts = async () => {
    try {
      setLoadingApproved(true)
      const response = await fetch('/api/admin/prompts')
      const data = await response.json()
      setApprovedPrompts(data.prompts)
    } catch (error) {
      console.error('Error fetching approved prompts:', error)
    } finally {
      setLoadingApproved(false)
    }
  }

  const fetchData = async () => {
    try {
      setLoading(true)
      const response = await fetch('/api/admin/submissions')
      const data = await response.json()
      setSubmissions(data.submissions)
      setStats(data.stats)
    } catch (error: any) {
      console.error('Error fetching admin data:', error)
      setFetchError('Failed to load submissions. Please try again.')
    } finally {
      setLoading(false)
    }
  }

  const handleApprove = async (submissionId: string) => {
    try {
      const response = await fetch('/api/admin/submissions', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          action: 'approve',
          submissionId
        })
      })

      if (response.ok) {
        fetchData()
        setSelectedSubmission(null)
      }
    } catch (error) {
      console.error('Error approving submission:', error)
    }
  }

  const handleReject = async () => {
    try {
      const response = await fetch('/api/admin/submissions', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          action: 'reject',
          submissionId: rejectionId,
          reason: rejectionReason
        })
      })

      if (response.ok) {
        fetchData()
        setSelectedSubmission(null)
        setShowRejectModal(false)
        setRejectionReason('')
        setRejectionId('')
      }
    } catch (error) {
      console.error('Error rejecting submission:', error)
    }
  }

  const handleDeletePrompt = async (promptId: string) => {
    try {
      const response = await fetch('/api/admin/prompts', {
        method: 'DELETE',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          promptId
        })
      })

      if (response.ok) {
        fetchData()
        setSelectedSubmission(null)
      }
    } catch (error) {
      console.error('Error deleting prompt:', error)
    }
  }

  const handleDeleteAllApproved = async () => {
    try {
      const response = await fetch('/api/admin/prompts/delete-all', {
        method: 'DELETE',
        headers: {
          'Content-Type': 'application/json'
        }
      })

      if (response.ok) {
        fetchApprovedPrompts()
        setSelectedSubmission(null)
      }
    } catch (error) {
      console.error('Error deleting all approved prompts:', error)
    }
  }

  const handleDeleteSubmission = async (submissionId: string) => {
    if (!confirm('Are you sure you want to delete this submission?')) return

    try {
      const response = await fetch(`/api/admin/submissions?id=${submissionId}`, {
        method: 'DELETE'
      })

      if (response.ok) {
        fetchData()
      }
    } catch (error) {
      console.error('Error deleting submission:', error)
    }
  }

  const handleAddPrompt = async (e: React.FormEvent) => {
    e.preventDefault()
    setIsAddingPrompt(true)

    try {
      const response = await fetch('/api/admin/prompts', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          ...newPrompt,
          tags: newPrompt.tags.split(',').map(tag => tag.trim()).filter(tag => tag),
          variables: newPrompt.variables.split(',').map(variable => variable.trim()).filter(variable => variable)
        })
      })

      if (response.ok) {
        setShowAddPromptModal(false)
        setNewPrompt({
          title: '',
          description: '',
          category: 'Marketing',
          tags: '',
          prompt: '',
          variables: ''
        })
        fetchApprovedPrompts()
        fetchData()
      }
    } catch (error) {
      console.error('Error adding prompt:', error)
    } finally {
      setIsAddingPrompt(false)
    }
  }

  const handleLogout = async () => {
    try {
      // Clear local storage and session storage
      if (typeof window !== 'undefined') {
        localStorage.removeItem('adminToken')
        localStorage.removeItem('adminUser')
        sessionStorage.clear()
      }

      // Call logout API
      await fetch('/api/admin/auth', { method: 'DELETE' })

      // Redirect to login
      router.push('/admin/login')

      // Prevent back button after logout
      if (typeof window !== 'undefined') {
        window.history.pushState(null, '', '/admin/login')
        window.addEventListener('popstate', function (event) {
          window.history.pushState(null, '', '/admin/login')
        })
      }
    } catch (error) {
      console.error('Logout error:', error)
      // Still redirect even if API fails
      router.push('/admin/login')
      if (typeof window !== 'undefined') {
        window.history.pushState(null, '', '/admin/login')
      }
    }
  }

  const filteredSubmissions = submissions.filter(submission => {
    if (filterStatus === 'all') return true
    return submission.status === filterStatus
  }).filter(submission =>
    submission.title.toLowerCase().includes(searchQuery.toLowerCase())
  )

  return (
    <>
      <AdminAuthCheck />
      <div className="min-h-screen bg-gradient-to-br from-emerald-50 to-teal-100 dark:from-gray-900 dark:to-gray-800">
        {/* Header */}
        <header className="bg-white dark:bg-gray-900 border-b border-gray-200 dark:border-gray-700">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div className="flex items-center justify-between h-16">
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-lg bg-emerald-500">
                  <Shield className="w-5 h-5 text-white" />
                </div>
                <div>
                  <h1 className="text-xl font-bold text-gray-900 dark:text-white">Admin Panel</h1>
                  <p className="text-sm text-gray-600 dark:text-gray-400">Manage prompt submissions</p>
                </div>
              </div>
              <div className="flex items-center gap-3">
                <button
                  onClick={() => setShowAddPromptModal(true)}
                  className="flex items-center gap-2 px-4 py-2 bg-emerald-600 hover:bg-emerald-700 text-white text-sm font-medium rounded-lg transition-colors shadow-sm"
                >
                  <Plus className="w-4 h-4" />
                  New Prompt
                </button>
                <button onClick={handleLogout} className="flex items-center gap-2 px-4 py-2 text-sm font-medium text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-lg transition-colors">
                  <LogOut className="w-4 h-4" />
                  Logout
                </button>
              </div>
            </div>
          </div>
        </header>

        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
          {/* Stats Cards */}
          {stats && (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
              <motion.div
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6"
              >
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm text-gray-600 dark:text-gray-400">Total Submissions</p>
                    <p className="text-2xl font-bold text-gray-900 dark:text-white">{stats.total}</p>
                  </div>
                  <FileText className="w-8 h-8 text-emerald-500" />
                </div>
              </motion.div>

              <motion.div
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.1 }}
                className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6"
              >
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm text-gray-600 dark:text-gray-400">Pending Review</p>
                    <p className="text-2xl font-bold text-yellow-600 dark:text-yellow-400">{stats.pending}</p>
                  </div>
                  <Clock className="w-8 h-8 text-yellow-500" />
                </div>
              </motion.div>

              <motion.div
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.2 }}
                className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6"
              >
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm text-gray-600 dark:text-gray-400">Approved</p>
                    <p className="text-2xl font-bold text-green-600 dark:text-green-400">{stats.approved}</p>
                  </div>
                  <Check className="w-8 h-8 text-green-500" />
                </div>
              </motion.div>

              <motion.div
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.3 }}
                className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6"
              >
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm text-gray-600 dark:text-gray-400">Rejected</p>
                    <p className="text-2xl font-bold text-red-600 dark:text-red-400">{stats.rejected}</p>
                  </div>
                  <X className="w-8 h-8 text-red-500" />
                </div>
              </motion.div>
            </div>
          )}

          {/* Loading State */}
          {loading && (
            <div className="flex items-center justify-center py-12">
              <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-r-2 border-t-2 border-l-2 border-emerald-500"></div>
            </div>
          )}

          {/* Error Message */}
          {fetchError && (
            <div className="text-center py-12">
              <AlertCircle className="w-16 h-16 text-red-500 mx-auto mb-4" />
              <p className="text-red-600 text-lg">{fetchError}</p>
            </div>
          )}

          {/* Submissions List */}
          {!loading && !fetchError && filteredSubmissions.length === 0 && (
            <div className="text-center py-12">
              <AlertCircle className="w-16 h-16 text-gray-400 mx-auto mb-4" />
              <p className="text-gray-600 dark:text-gray-400 text-lg">No submissions found</p>
            </div>
          )}

          {!loading && filteredSubmissions.length > 0 && (
            <div className="space-y-4">
              <div className="flex items-center justify-between mb-6">
                <h2 className="text-2xl font-bold text-gray-900 dark:text-white">Submissions</h2>
                <div className="flex items-center gap-4">
                  <div className="relative">
                    <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-400" />
                    <input
                      type="text"
                      placeholder="Search submissions..."
                      value={searchQuery}
                      onChange={(e) => setSearchQuery(e.target.value)}
                      className="pl-10 pr-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg focus:ring-2 focus:ring-emerald-500 focus:border-transparent dark:bg-gray-700 dark:text-white"
                    />
                  </div>
                  <select
                    value={filterStatus}
                    onChange={(e) => setFilterStatus(e.target.value as 'all' | 'pending' | 'approved' | 'rejected')}
                    className="px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg focus:ring-2 focus:ring-emerald-500 focus:border-transparent dark:bg-gray-700 dark:text-white"
                  >
                    <option value="all">All Status</option>
                    <option value="pending">Pending</option>
                    <option value="approved">Approved</option>
                    <option value="rejected">Rejected</option>
                  </select>
                </div>
              </div>

              <div className="bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700 overflow-hidden shadow-sm">
                <div className="overflow-x-auto">
                  <table className="w-full text-left border-collapse">
                    <thead>
                      <tr className="bg-gray-50 dark:bg-gray-900/50 border-b border-gray-200 dark:border-gray-700">
                        <th className="px-6 py-4 text-xs font-bold text-gray-500 dark:text-gray-400 uppercase tracking-wider">Submission</th>
                        <th className="px-6 py-4 text-xs font-bold text-gray-500 dark:text-gray-400 uppercase tracking-wider">Category</th>
                        <th className="px-6 py-4 text-xs font-bold text-gray-500 dark:text-gray-400 uppercase tracking-wider">Status</th>
                        <th className="px-6 py-4 text-xs font-bold text-gray-500 dark:text-gray-400 uppercase tracking-wider">Date</th>
                        <th className="px-6 py-4 text-xs font-bold text-gray-500 dark:text-gray-400 uppercase tracking-wider text-right">Actions</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
                      {filteredSubmissions.map((submission, index) => (
                        <motion.tr
                          key={submission.id}
                          initial={{ opacity: 0 }}
                          animate={{ opacity: 1 }}
                          transition={{ delay: index * 0.05 }}
                          className="hover:bg-gray-50 dark:hover:bg-gray-800/50 transition-colors"
                        >
                          <td className="px-6 py-4">
                            <div className="flex flex-col">
                              <span className="text-sm font-bold text-gray-900 dark:text-white line-clamp-1">{submission.title}</span>
                              <span className="text-xs text-gray-500 dark:text-gray-400 line-clamp-1">{submission.description}</span>
                            </div>
                          </td>
                          <td className="px-6 py-4">
                            <span className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold bg-blue-100 dark:bg-blue-900 text-blue-800 dark:text-blue-200 uppercase tracking-tighter">
                              {submission.category}
                            </span>
                          </td>
                          <td className="px-6 py-4">
                            <span className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-tighter ${submission.status === 'pending' ? 'bg-yellow-100 dark:bg-yellow-900 text-yellow-800 dark:text-yellow-200' :
                              submission.status === 'approved' ? 'bg-green-100 dark:bg-green-900 text-green-800 dark:text-green-200' :
                                'bg-red-100 dark:bg-red-900 text-red-800 dark:text-red-200'
                              }`}>
                              {submission.status}
                            </span>
                          </td>
                          <td className="px-6 py-4 text-xs text-gray-500 dark:text-gray-400 font-mono">
                            {new Date(submission.submitted_at).toLocaleDateString()}
                          </td>
                          <td className="px-6 py-4 text-right">
                            <div className="flex items-center justify-end gap-1">
                              <button
                                onClick={() => setSelectedSubmission(submission)}
                                className="p-1.5 text-blue-600 dark:text-blue-400 hover:bg-blue-50 dark:hover:bg-blue-900 rounded transition-colors"
                                title="View Details"
                              >
                                <Eye className="w-4 h-4" />
                              </button>
                              {submission.status === 'pending' && (
                                <>
                                  <button
                                    onClick={() => handleApprove(submission.id)}
                                    className="p-1.5 text-green-600 dark:text-green-400 hover:bg-green-50 dark:hover:bg-green-900 rounded transition-colors"
                                    title="Approve"
                                  >
                                    <Check className="w-4 h-4" />
                                  </button>
                                  <button
                                    onClick={() => {
                                      setSelectedSubmission(submission)
                                      setRejectionId(submission.id)
                                      setShowRejectModal(true)
                                    }}
                                    className="p-1.5 text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-900 rounded transition-colors"
                                    title="Reject"
                                  >
                                    <X className="w-4 h-4" />
                                  </button>
                                </>
                              )}
                              <button
                                onClick={() => handleDeleteSubmission(submission.id)}
                                className="p-1.5 text-gray-400 hover:text-red-600 dark:hover:text-red-400 hover:bg-red-50 dark:hover:bg-red-900/40 rounded transition-colors"
                                title="Delete Submission"
                              >
                                <Trash2 className="w-4 h-4" />
                              </button>
                            </div>
                          </td>
                        </motion.tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}

          {/* Approved Prompts Section */}
          <div className="mt-8">
            <div className="flex items-center justify-between mb-6">
              <h2 className="text-2xl font-bold text-gray-900 dark:text-white">Approved Prompts</h2>
              <div className="flex items-center gap-4">
                <div className="text-sm text-gray-600 dark:text-gray-400">
                  Manage published prompts
                </div>
                <button
                  onClick={() => setShowDeleteAllConfirmation(true)}
                  className="px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                  disabled={approvedPrompts.length === 0}
                  title="Delete all approved prompts"
                >
                  Delete All Approved
                </button>
              </div>
            </div>

            {showDeleteAllConfirmation && (
              <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50">
                <motion.div
                  initial={{ opacity: 0, scale: 0.95 }}
                  animate={{ opacity: 1, scale: 1 }}
                  className="bg-white dark:bg-gray-900 rounded-xl border border-gray-200 dark:border-gray-700 p-6 max-w-2xl w-full"
                >
                  <h3 className="text-xl font-semibold text-gray-900 dark:text-white mb-4">Confirm Delete All</h3>
                  <p className="text-gray-700 dark:text-gray-300 mb-4">Are you sure you want to delete all approved prompts? This action cannot be undone.</p>
                  <div className="flex justify-end gap-3">
                    <button
                      onClick={() => setShowDeleteAllConfirmation(false)}
                      className="px-4 py-2 text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-lg transition-colors"
                    >
                      Cancel
                    </button>
                    <button
                      onClick={handleDeleteAllApproved}
                      className="px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded-lg transition-colors"
                    >
                      Confirm Delete All
                    </button>
                  </div>
                </motion.div>
              </div>
            )}

            <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
              {!loadingApproved && approvedPrompts.length === 0 && (
                <div className="text-center py-8">
                  <p className="text-gray-600 dark:text-gray-400">No approved prompts yet</p>
                </div>
              )}

              {loadingApproved && approvedPrompts.length === 0 && (
                <div className="text-center py-8">
                  <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-r-2 border-t-2 border-l-2 border-emerald-500"></div>
                </div>
              )}

              {!loadingApproved && approvedPrompts.length > 0 && (
                <div className="overflow-x-auto shadow-sm rounded-lg border border-gray-200 dark:border-gray-700">
                  <table className="w-full text-left border-collapse">
                    <thead>
                      <tr className="bg-gray-50 dark:bg-gray-900/50 border-b border-gray-200 dark:border-gray-700">
                        <th className="px-6 py-4 text-xs font-bold text-gray-500 dark:text-gray-400 uppercase tracking-wider">Prompt</th>
                        <th className="px-6 py-4 text-xs font-bold text-gray-500 dark:text-gray-400 uppercase tracking-wider">Category</th>
                        <th className="px-6 py-4 text-xs font-bold text-gray-500 dark:text-gray-400 uppercase tracking-wider">Date</th>
                        <th className="px-6 py-4 text-xs font-bold text-gray-500 dark:text-gray-400 uppercase tracking-wider text-right">Actions</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
                      {approvedPrompts.map((prompt, index) => (
                        <motion.tr
                          key={prompt.id}
                          initial={{ opacity: 0 }}
                          animate={{ opacity: 1 }}
                          transition={{ delay: index * 0.05 }}
                          className="hover:bg-gray-50 dark:hover:bg-gray-800/50 transition-colors"
                        >
                          <td className="px-6 py-4">
                            <div className="flex flex-col">
                              <span className="text-sm font-bold text-gray-900 dark:text-white line-clamp-1">{prompt.title}</span>
                              <span className="text-xs text-gray-500 dark:text-gray-400 line-clamp-1">{prompt.description}</span>
                            </div>
                          </td>
                          <td className="px-6 py-4">
                            <span className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold bg-blue-100 dark:bg-blue-900 text-blue-800 dark:text-blue-200 uppercase tracking-tighter">
                              {prompt.category}
                            </span>
                          </td>
                          <td className="px-6 py-4 text-xs text-gray-500 dark:text-gray-400 font-mono">
                            {new Date(prompt.created_at).toLocaleDateString()}
                          </td>
                          <td className="px-6 py-4 text-right">
                            <button
                              onClick={() => handleDeletePrompt(prompt.id)}
                              className="p-1.5 text-gray-400 hover:text-red-600 dark:hover:text-red-400 hover:bg-red-50 dark:hover:bg-red-900/40 rounded transition-colors"
                              title="Delete prompt"
                            >
                              <Trash2 className="w-4 h-4" />
                            </button>
                          </td>
                        </motion.tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Reject Modal */}
      {showRejectModal && selectedSubmission && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50 backdrop-blur-sm">
          <motion.div
            initial={{ opacity: 0, scale: 0.95 }}
            animate={{ opacity: 1, scale: 1 }}
            className="bg-white dark:bg-gray-900 rounded-xl border border-gray-200 dark:border-gray-700 p-6 max-w-2xl w-full max-h-[90vh] overflow-y-auto shadow-2xl"
          >
            <div className="flex justify-between items-center mb-6 border-b border-gray-100 dark:border-gray-800 pb-4">
              <h3 className="text-xl font-bold text-gray-900 dark:text-white">Reject Submission</h3>
              <button onClick={() => setShowRejectModal(false)} className="text-gray-400 hover:text-gray-600 dark:hover:text-gray-200">
                <X className="w-5 h-5" />
              </button>
            </div>
            <div className="space-y-6">
              <div className="grid grid-cols-2 gap-4">
                <div className="p-3 bg-gray-50 dark:bg-gray-800/50 rounded-lg">
                  <p className="text-xs font-bold text-gray-500 dark:text-gray-400 uppercase mb-1">Title</p>
                  <p className="text-sm font-semibold text-gray-900 dark:text-white">{selectedSubmission.title}</p>
                </div>
                <div className="p-3 bg-gray-50 dark:bg-gray-800/50 rounded-lg">
                  <p className="text-xs font-bold text-gray-500 dark:text-gray-400 uppercase mb-1">Category</p>
                  <p className="text-sm font-semibold text-gray-900 dark:text-white">{selectedSubmission.category}</p>
                </div>
              </div>
              <div className="p-4 bg-gray-50 dark:bg-gray-800 rounded-lg border border-gray-100 dark:border-gray-800">
                <p className="text-xs font-bold text-gray-500 dark:text-gray-400 uppercase mb-2">Prompt Content</p>
                <p className="text-sm text-gray-700 dark:text-gray-300 font-mono leading-relaxed">{selectedSubmission.prompt}</p>
              </div>
              <div>
                <label className="block text-xs font-bold text-gray-500 dark:text-gray-400 uppercase mb-2">Rejection Reason</label>
                <textarea
                  value={rejectionReason}
                  onChange={(e) => setRejectionReason(e.target.value)}
                  placeholder="Explain why this submission is being rejected..."
                  className="w-full px-4 py-3 border border-gray-200 dark:border-gray-700 rounded-lg focus:ring-2 focus:ring-red-500 focus:border-transparent dark:bg-gray-800 dark:text-white text-sm"
                  rows={4}
                />
              </div>
            </div>
            <div className="flex justify-end gap-3 mt-8 pt-6 border-t border-gray-100 dark:border-gray-800">
              <button
                onClick={() => setShowRejectModal(false)}
                className="px-5 py-2 text-sm font-bold text-gray-600 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-800 rounded-lg transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={handleReject}
                disabled={!rejectionReason.trim()}
                className="px-6 py-2 bg-red-600 hover:bg-red-700 text-white text-sm font-bold rounded-lg transition-colors shadow-lg shadow-red-500/20 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                Confirm Rejection
              </button>
            </div>
          </motion.div>
        </div>
      )}

      {/* Detail Modal */}
      {selectedSubmission && !showRejectModal && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50 backdrop-blur-sm">
          <motion.div
            initial={{ opacity: 0, scale: 0.95 }}
            animate={{ opacity: 1, scale: 1 }}
            className="bg-white dark:bg-gray-900 rounded-xl border border-gray-200 dark:border-gray-700 p-8 max-w-2xl w-full max-h-[90vh] overflow-y-auto shadow-2xl"
          >
            <div className="flex justify-between items-center mb-8 border-b border-gray-100 dark:border-gray-800 pb-6">
              <div>
                <h3 className="text-2xl font-bold text-gray-900 dark:text-white">Submission Detail</h3>
                <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">Status: <span className="uppercase font-bold tracking-widest text-[10px] px-2 py-0.5 rounded bg-gray-100 dark:bg-gray-800">{selectedSubmission.status}</span></p>
              </div>
              <button onClick={() => setSelectedSubmission(null)} className="p-2 bg-gray-50 dark:bg-gray-800 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-full transition-colors">
                <X className="w-5 h-5 text-gray-400" />
              </button>
            </div>

            <div className="space-y-8">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div>
                  <label className="text-[10px] font-bold text-gray-400 uppercase tracking-[0.2em] mb-2 block">Title</label>
                  <p className="text-lg font-bold text-gray-900 dark:text-white">{selectedSubmission.title}</p>
                </div>
                <div>
                  <label className="text-[10px] font-bold text-gray-400 uppercase tracking-[0.2em] mb-2 block">Category</label>
                  <span className="inline-flex items-center px-3 py-1 bg-emerald-100 dark:bg-emerald-900/30 text-emerald-700 dark:text-emerald-400 text-xs font-bold rounded-lg uppercase tracking-wider">
                    {selectedSubmission.category}
                  </span>
                </div>
              </div>

              <div>
                <label className="text-[10px] font-bold text-gray-400 uppercase tracking-[0.2em] mb-2 block">Description</label>
                <p className="text-sm text-gray-600 dark:text-gray-400 leading-relaxed">{selectedSubmission.description}</p>
              </div>

              <div>
                <label className="text-[10px] font-bold text-gray-400 uppercase tracking-[0.2em] mb-2 block">Prompt Content</label>
                <pre className="p-6 bg-gray-50 dark:bg-gray-950 rounded-xl border border-gray-100 dark:border-gray-800 text-sm text-gray-700 dark:text-gray-300 font-mono whitespace-pre-wrap leading-loose shadow-inner">
                  {selectedSubmission.prompt}
                </pre>
              </div>

              <div className="grid grid-cols-2 gap-6 p-4 bg-gray-50 dark:bg-gray-800/30 rounded-xl border border-dashed border-gray-200 dark:border-gray-800">
                <div>
                  <label className="text-[10px] font-bold text-gray-400 uppercase tracking-[0.2em] mb-1 block">Submitted By</label>
                  <p className="text-sm font-bold text-gray-900 dark:text-white uppercase tracking-tighter">{selectedSubmission.submitted_by}</p>
                </div>
                <div className="text-right">
                  <label className="text-[10px] font-bold text-gray-400 uppercase tracking-[0.2em] mb-1 block">Submission Date</label>
                  <p className="text-sm font-mono text-gray-500 dark:text-gray-400">{new Date(selectedSubmission.submitted_at).toLocaleString()}</p>
                </div>
              </div>
            </div>

            <div className="flex justify-end gap-3 mt-10 pt-8 border-t border-gray-100 dark:border-gray-800">
              <button
                onClick={() => setSelectedSubmission(null)}
                className="px-6 py-2.5 text-sm font-bold text-gray-500 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white transition-colors"
              >
                Close View
              </button>
              {selectedSubmission.status === 'pending' && (
                <div className="flex gap-3">
                  <button
                    onClick={() => {
                      setRejectionId(selectedSubmission.id)
                      setShowRejectModal(true)
                    }}
                    className="px-6 py-2.5 border-2 border-red-500/20 text-red-600 dark:text-red-400 text-sm font-bold rounded-xl hover:bg-red-500 hover:text-white transition-all shadow-lg shadow-red-500/10"
                  >
                    Reject
                  </button>
                  <button
                    onClick={() => handleApprove(selectedSubmission.id)}
                    className="px-8 py-2.5 bg-emerald-600 hover:bg-emerald-700 text-white text-sm font-bold rounded-xl transition-all shadow-lg shadow-emerald-500/20"
                  >
                    Approve
                  </button>
                </div>
              )}
            </div>
          </motion.div>
        </div>
      )}

      {/* New Prompt Modal */}
      {showAddPromptModal && (
        <div className="fixed inset-0 bg-black/50 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <motion.div
            initial={{ opacity: 0, scale: 0.95, y: 20 }}
            animate={{ opacity: 1, scale: 1, y: 0 }}
            className="bg-white dark:bg-gray-900 rounded-2xl border border-gray-200 dark:border-gray-700 shadow-2xl max-w-2xl w-full max-h-[90vh] overflow-hidden flex flex-col"
          >
            <div className="p-6 border-b border-gray-100 dark:border-gray-800 flex items-center justify-between bg-gray-50 dark:bg-gray-900/50">
              <div className="flex items-center gap-3">
                <div className="p-2 bg-emerald-500 rounded-lg">
                  <Plus className="w-5 h-5 text-white" />
                </div>
                <div>
                  <h3 className="text-xl font-bold text-gray-900 dark:text-white">Create New Prompt</h3>
                  <p className="text-xs text-gray-500 dark:text-gray-400 font-medium">Add a prompt directly to the library</p>
                </div>
              </div>
              <button onClick={() => setShowAddPromptModal(false)} className="p-2 hover:bg-gray-200 dark:hover:bg-gray-800 rounded-full transition-colors">
                <X className="w-5 h-5 text-gray-400" />
              </button>
            </div>

            <div className="p-6 overflow-y-auto flex-1 space-y-6">
              <div className="grid gap-6 md:grid-cols-2">
                <div className="space-y-2">
                  <label className="text-[10px] font-bold text-gray-500 dark:text-gray-400 uppercase tracking-widest pl-1">Title</label>
                  <input
                    type="text"
                    value={newPrompt.title}
                    onChange={(e) => setNewPrompt({ ...newPrompt, title: e.target.value })}
                    placeholder="E.g. SEO Meta Description Generator"
                    className="w-full px-4 py-3 bg-gray-50 dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-xl focus:ring-2 focus:ring-emerald-500 focus:border-transparent text-sm dark:text-white transition-all"
                  />
                </div>
                <div className="space-y-2">
                  <label className="text-[10px] font-bold text-gray-500 dark:text-gray-400 uppercase tracking-widest pl-1">Category</label>
                  <select
                    value={newPrompt.category}
                    onChange={(e) => setNewPrompt({ ...newPrompt, category: e.target.value })}
                    className="w-full px-4 py-3 bg-gray-50 dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-xl focus:ring-2 focus:ring-emerald-500 focus:border-transparent text-sm dark:text-white transition-all"
                  >
                    <option value="Marketing">Marketing</option>
                    <option value="Business Operations">Business Operations</option>
                    <option value="Social Media">Social Media</option>
                    <option value="Copywriting">Copywriting</option>
                  </select>
                </div>
              </div>

              <div className="space-y-2">
                <label className="text-[10px] font-bold text-gray-500 dark:text-gray-400 uppercase tracking-widest pl-1">Description</label>
                <textarea
                  value={newPrompt.description}
                  onChange={(e) => setNewPrompt({ ...newPrompt, description: e.target.value })}
                  placeholder="Short explanation of what this prompt achieves..."
                  className="w-full px-4 py-3 bg-gray-50 dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-xl focus:ring-2 focus:ring-emerald-500 focus:border-transparent text-sm dark:text-white transition-all"
                  rows={2}
                />
              </div>

              <div className="space-y-2">
                <label className="text-[10px] font-bold text-gray-500 dark:text-gray-400 uppercase tracking-widest pl-1">Prompt Text</label>
                <textarea
                  value={newPrompt.prompt}
                  onChange={(e) => setNewPrompt({ ...newPrompt, prompt: e.target.value })}
                  placeholder="The actual prompt instructions..."
                  className="w-full px-4 py-3 bg-gray-50 dark:bg-gray-950 border border-gray-200 dark:border-gray-700 rounded-xl focus:ring-2 focus:ring-emerald-500 focus:border-transparent text-sm font-mono dark:text-white transition-all"
                  rows={5}
                />
              </div>

              <div className="grid gap-6 md:grid-cols-2">
                <div className="space-y-2">
                  <label className="text-[10px] font-bold text-gray-500 dark:text-gray-400 uppercase tracking-widest pl-1">Tags (Comma separated)</label>
                  <input
                    type="text"
                    value={newPrompt.tags}
                    onChange={(e) => setNewPrompt({ ...newPrompt, tags: e.target.value })}
                    placeholder="seo, writing, tools"
                    className="w-full px-4 py-3 bg-gray-50 dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-xl focus:ring-2 focus:ring-emerald-500 focus:border-transparent text-sm dark:text-white transition-all"
                  />
                </div>
                <div className="space-y-2">
                  <label className="text-[10px] font-bold text-gray-500 dark:text-gray-400 uppercase tracking-widest pl-1">Variables (Comma separated)</label>
                  <input
                    type="text"
                    value={newPrompt.variables}
                    onChange={(e) => setNewPrompt({ ...newPrompt, variables: e.target.value })}
                    placeholder="audience, tone, keyword"
                    className="w-full px-4 py-3 bg-gray-50 dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-xl focus:ring-2 focus:ring-emerald-500 focus:border-transparent text-sm dark:text-white transition-all"
                  />
                </div>
              </div>
            </div>

            <div className="p-6 bg-gray-50 dark:bg-gray-900/50 border-t border-gray-100 dark:border-gray-800 flex justify-end gap-3">
              <button
                onClick={() => setShowAddPromptModal(false)}
                className="px-6 py-2.5 text-sm font-bold text-gray-500 hover:text-gray-800 dark:text-gray-400 dark:hover:text-white transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={handleAddPrompt}
                disabled={isAddingPrompt || !newPrompt.title || !newPrompt.prompt}
                className="px-8 py-2.5 bg-emerald-600 hover:bg-emerald-700 text-white text-sm font-bold rounded-xl transition-all shadow-lg shadow-emerald-500/20 disabled:opacity-50 disabled:grayscale"
              >
                {isAddingPrompt ? 'Adding...' : 'Add Prompt'}
              </button>
            </div>
          </motion.div>
        </div>
      )}

      {/* Delete All Confirmation Modal */}
      {showDeleteAllConfirmation && (
        <div className="fixed inset-0 bg-black/50 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <motion.div
            initial={{ opacity: 0, scale: 0.95 }}
            animate={{ opacity: 1, scale: 1 }}
            className="bg-white dark:bg-gray-900 rounded-2xl border border-gray-200 dark:border-gray-700 shadow-2xl max-w-md w-full p-8"
          >
            <div className="w-16 h-16 bg-red-100 dark:bg-red-900/20 rounded-full flex items-center justify-center mx-auto mb-6">
              <Trash2 className="w-8 h-8 text-red-600 dark:text-red-400" />
            </div>
            <h3 className="text-2xl font-bold text-gray-900 dark:text-white text-center mb-2">Are you absolutely sure?</h3>
            <p className="text-gray-600 dark:text-gray-400 text-center mb-8">
              This will permanently delete <span className="font-bold text-red-600 dark:text-red-400">ALL</span> approved prompts from the database. This action cannot be undone.
            </p>
            <div className="flex gap-4">
              <button
                onClick={() => setShowDeleteAllConfirmation(false)}
                className="flex-1 px-6 py-3 bg-gray-100 dark:bg-gray-800 text-gray-700 dark:text-gray-300 font-bold rounded-xl hover:bg-gray-200 dark:hover:bg-gray-700 transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={() => {
                  handleDeleteAllApproved()
                  setShowDeleteAllConfirmation(false)
                }}
                className="flex-1 px-6 py-3 bg-red-600 text-white font-bold rounded-xl hover:bg-red-700 transition-colors shadow-lg shadow-red-500/20"
              >
                Delete All
              </button>
            </div>
          </motion.div>
        </div>
      )}
    </>
  )
}
