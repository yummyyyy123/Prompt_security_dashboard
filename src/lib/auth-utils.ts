// Better authentication check for admin panel
export const isAuthenticated = async () => {
  if (typeof window === 'undefined') {
    console.log('🔍 Window not available')
    return false
  }
  
  try {
    console.log('🔍 Starting authentication check...')
    // Check if we have a valid admin token
    const response = await fetch('/api/admin/auth/check', {
      method: 'GET',
      credentials: 'include'
    })

    if (response.ok) {
      const data = await response.json()
      console.log('✅ Auth check response:', data)
      return data.authenticated === true
    } else {
      console.log('❌ Auth check failed:', response.status, response.statusText)
      return false
    }
  } catch (error) {
    console.error('💥 Auth check error:', error)
    return false
  }
}

// Redirect to login if not authenticated
export const requireAuth = () => {
  console.log('🔍 requireAuth called, checking if already authenticated...')
  
  // Check if already authenticated to prevent infinite loops
  if (typeof window !== 'undefined') {
    checkIfAuthenticated()
  }
}

// Helper function to check authentication status
const checkIfAuthenticated = async () => {
  try {
    const response = await fetch('/api/admin/auth/check', {
      method: 'GET',
      credentials: 'include'
    })

    if (response.ok) {
      const data = await response.json()
      console.log('✅ User already authenticated, skipping auth check')
      return true
    } else {
      console.log('🔄 Redirecting to login page...')
      window.location.href = '/admin/login'
      return false
    }
  } catch (error) {
    console.error('💥 Pre-auth check error:', error)
    return false
  }
}
