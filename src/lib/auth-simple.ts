// Simple, reliable authentication check
export const checkAuthStatus = async () => {
  try {
    const response = await fetch('/api/admin/auth/check', {
      method: 'GET',
      credentials: 'include'
    })
    
    if (!response.ok) {
      console.log('❌ Auth check failed:', response.status)
      return false
    }
    
    const data = await response.json()
    console.log('✅ Auth check success:', data.authenticated)
    return data.authenticated === true
  } catch (error) {
    console.error('💥 Auth check error:', error)
    return false
  }
}

export const logout = async () => {
  try {
    // Clear all storage first
    if (typeof window !== 'undefined') {
      localStorage.removeItem('adminToken')
      localStorage.removeItem('adminUser')
      sessionStorage.clear()
      // Clear all cookies
      document.cookie.split(";").forEach(function(c) { 
        document.cookie = c.replace(/^ +/, "").replace(/=.*/, "=;expires=" + new Date().toUTCString() + ";path=/"); 
      });
    }
    
    const response = await fetch('/api/admin/auth', { method: 'DELETE' })
    console.log('🔄 Logout response:', response.ok)
    
    // Force redirect after logout
    if (typeof window !== 'undefined') {
      window.location.href = '/admin/login'
    }
  } catch (error) {
    console.error('💥 Logout error:', error)
    if (typeof window !== 'undefined') {
      window.location.href = '/admin/login'
    }
  }
}
