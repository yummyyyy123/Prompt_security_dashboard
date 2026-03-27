import { NextRequest, NextResponse } from 'next/server'
import jwt from 'jsonwebtoken'
import bcrypt from 'bcryptjs'
import { createClient } from '@supabase/supabase-js'

const supabase = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL!,
  process.env.SUPABASE_SERVICE_ROLE_KEY!
)

// Enhanced security configurations
const SECURITY_CONFIG = {
  PASSWORD_MIN_LENGTH: 12,
  MAX_FAILED_ATTEMPTS: 3,
  LOCKOUT_DURATION_MINUTES: 30,
  TOKEN_EXPIRY_MINUTES: 15,
  REFRESH_TOKEN_EXPIRY_DAYS: 7,
}

// Failed login tracking
interface FailedAttempt {
  ip: string
  username: string
  timestamp: number
  attempts: number
  lockedUntil?: number
}

const failedAttempts = new Map<string, FailedAttempt>()

// Password strength validation
export function validatePasswordStrength(password: string): { valid: boolean; errors: string[] } {
  const errors: string[] = []
  
  if (password.length < SECURITY_CONFIG.PASSWORD_MIN_LENGTH) {
    errors.push(`Password must be at least ${SECURITY_CONFIG.PASSWORD_MIN_LENGTH} characters`)
  }
  
  if (!/[A-Z]/.test(password)) {
    errors.push('Password must contain uppercase letters')
  }
  
  if (!/[a-z]/.test(password)) {
    errors.push('Password must contain lowercase letters')
  }
  
  if (!/\d/.test(password)) {
    errors.push('Password must contain numbers')
  }
  
  if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) {
    errors.push('Password must contain symbols')
  }
  
  return { valid: errors.length === 0, errors }
}

// Check for brute force attempts
export function isAccountLocked(ip: string, username: string): boolean {
  const key = `${ip}:${username}`
  const attempt = failedAttempts.get(key)
  
  if (!attempt) return false
  
  if (attempt.lockedUntil && Date.now() < attempt.lockedUntil) {
    return true
  }
  
  if (attempt.lockedUntil && Date.now() >= attempt.lockedUntil) {
    failedAttempts.delete(key)
    return false
  }
  
  return false
}

// Track failed login attempts
export function trackFailedAttempt(ip: string, username: string): { locked: boolean; remainingAttempts: number } {
  const key = `${ip}:${username}`
  const attempt = failedAttempts.get(key) || { ip, username, timestamp: Date.now(), attempts: 0 }
  
  attempt.attempts += 1
  attempt.timestamp = Date.now()
  
  if (attempt.attempts >= SECURITY_CONFIG.MAX_FAILED_ATTEMPTS) {
    attempt.lockedUntil = Date.now() + (SECURITY_CONFIG.LOCKOUT_DURATION_MINUTES * 60 * 1000)
    failedAttempts.set(key, attempt)
    return { locked: true, remainingAttempts: 0 }
  }
  
  failedAttempts.set(key, attempt)
  return { locked: false, remainingAttempts: SECURITY_CONFIG.MAX_FAILED_ATTEMPTS - attempt.attempts }
}

// Device fingerprinting
export function generateDeviceFingerprint(request: NextRequest): string {
  const ip = request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() || 'unknown'
  const userAgent = request.headers.get('user-agent') || 'unknown'
  const acceptLanguage = request.headers.get('accept-language') || 'unknown'
  const acceptEncoding = request.headers.get('accept-encoding') || 'unknown'
  
  const fingerprint = `${ip}:${userAgent}:${acceptLanguage}:${acceptEncoding}`
  return Buffer.from(fingerprint).toString('base64').substring(0, 32)
}

// Enhanced token generation with device fingerprinting
export function generateSecureTokens(userId: string, deviceFingerprint: string, ip: string): { accessToken: string; refreshToken: string } {
  const payload = {
    userId,
    deviceFingerprint,
    ip,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + (SECURITY_CONFIG.TOKEN_EXPIRY_MINUTES * 60),
    type: 'access'
  }
  
  const refreshPayload = {
    userId,
    deviceFingerprint,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + (SECURITY_CONFIG.REFRESH_TOKEN_EXPIRY_DAYS * 24 * 60 * 60),
    type: 'refresh'
  }
  
  if (!process.env.JWT_SECRET || !process.env.REFRESH_TOKEN_SECRET) {
    throw new Error('JWT secrets not configured')
  }
  
  return {
    accessToken: jwt.sign(payload, process.env.JWT_SECRET),
    refreshToken: jwt.sign(refreshPayload, process.env.REFRESH_TOKEN_SECRET!)
  }
}

// Enhanced token validation
export async function validateSecureToken(request: NextRequest): Promise<{ valid: boolean; userId?: string; reason?: string }> {
  try {
    const authHeader = request.headers.get('authorization')
    const cookieToken = request.cookies.get('access-token')?.value
    
    let token = ''
    
    if (authHeader && authHeader.startsWith('Bearer ')) {
      token = authHeader.substring(7)
    } else if (cookieToken) {
      token = cookieToken
    }
    
    if (!token) {
      return { valid: false, reason: 'No token provided' }
    }
    
    if (!process.env.JWT_SECRET) {
      return { valid: false, reason: 'JWT secrets not configured' }
    }
    
    const decoded = jwt.verify(token, process.env.JWT_SECRET) as any
    
    // Validate device fingerprint and IP
    const currentFingerprint = generateDeviceFingerprint(request)
    const currentIp = request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() || 'unknown'
    
    if (decoded.deviceFingerprint !== currentFingerprint) {
      return { valid: false, reason: 'Device fingerprint mismatch' }
    }
    
    if (decoded.ip !== currentIp) {
      return { valid: false, reason: 'IP address mismatch' }
    }
    
    return { valid: true, userId: decoded.userId }
    
  } catch (error: any) {
    if (error.name === 'TokenExpiredError') {
      return { valid: false, reason: 'Token expired' }
    }
    if (error.name === 'JsonWebTokenError') {
      return { valid: false, reason: 'Invalid token' }
    }
    return { valid: false, reason: 'Token validation failed' }
  }
}

// Enhanced admin authentication wrapper
export function withEnhancedAuth(handler: (req: NextRequest) => Promise<NextResponse>) {
  return async (request: NextRequest): Promise<NextResponse> => {
    try {
      const validation = await validateSecureToken(request)
      
      if (!validation.valid) {
        const ip = request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() || 'unknown'
        const userAgent = request.headers.get('user-agent') || 'unknown'
        const path = new URL(request.url).pathname
        
        // Log failed authentication attempt
        await supabase.from('security_logs').insert({
          ip_address: ip,
          event_type: 'authentication_failure',
          severity: 'warning',
          details: {
            reason: validation.reason,
            user_agent: userAgent,
            endpoint: path,
            authentication_method: 'enhanced_jwt'
          },
          created_at: new Date().toISOString()
        })
        
        return NextResponse.json(
          {
            error: 'Unauthorized',
            message: validation.reason,
            timestamp: new Date().toISOString()
          },
          { status: 401 }
        )
      }
      
      // Add user context to request
      ;(request as any).userId = validation.userId
      
      return await handler(request)
      
    } catch (error: any) {
      console.error('💥 Enhanced Auth Error:', error)
      return NextResponse.json(
        {
          error: 'Unauthorized',
          message: 'Authentication system error',
          timestamp: new Date().toISOString()
        },
        { status: 401 }
      )
    }
  }
}
