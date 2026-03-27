// Simple, reliable admin authentication
'use client'

import { useEffect } from 'react'
import { useRouter } from 'next/navigation'
import { checkAuthStatus } from '@/lib/auth-simple'

export default function AdminAuthCheck() {
  const router = useRouter()
  
  useEffect(() => {
    const checkAuth = async () => {
      console.log('🔍 Starting admin auth check...')
      
      const isAuthenticated = await checkAuthStatus()
      
      if (!isAuthenticated) {
        console.log('🔄 Not authenticated, redirecting to login...')
        router.push('/admin/login')
        return
      }
      
      console.log('✅ Authenticated, staying on admin page')
    }
    
    checkAuth()
  }, [router])
  
  return null
}
