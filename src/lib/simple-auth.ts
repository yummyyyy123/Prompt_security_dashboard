// Simple authentication utilities
export const checkAuthStatus = async () => {
  // Simple check - no complex logic that could cause loops
  try {
    const response = await fetch('/api/admin/auth/check', {
      method: 'GET',
      credentials: 'include'
    })
    
    if (!response.ok) {
      return false
    }
    
    const data = await response.json()
    return data.authenticated === true
  } catch (error) {
    return false
  }
}

export const logout = async () => {
  try {
    const response = await fetch('/api/admin/auth', { method: 'DELETE' })
    // Redirect after logout
    window.location.href = '/admin/login'
  } catch (error) {
    console.error('Logout error:', error)
    window.location.href = '/admin/login'
  }
}
