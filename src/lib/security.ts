// OWASP Top 10 Security Implementation
// 1. Broken Access Control
// 2. Cryptographic Failures
// 3. Injection
// 4. Insecure Design
// 5. Security Misconfiguration
// 6. Vulnerable and Outdated Components
// 7. Identification and Authentication Failures
// 8. Software and Data Integrity Failures
// 9. Security Logging and Monitoring Failures
// 10. Server-Side Request Forgery (SSRF)

import { NextRequest, NextResponse } from 'next/server'
import crypto from 'crypto'
import { getRequiredEnvVar, getOptionalEnvVar } from './admin-auth'

// 1. BROKEN ACCESS CONTROL - Enhanced JWT with role-based access
export function createSecureJWT(payload: any, expiresIn: string = '1h') {
  const header = {
    alg: 'HS256',
    typ: 'JWT',
    kid: process.env.JWT_KEY_ID || '1'
  }
  
  const now = Math.floor(Date.now() / 1000)
  const jwtPayload = {
    ...payload,
    iat: now,
    exp: now + (expiresIn === '1h' ? 3600 : expiresIn === '15m' ? 900 : 86400),
    jti: crypto.randomUUID(),
    scope: payload.role === 'admin' ? 'admin:read admin:write admin:delete' : 'user:read'
  }
  
  const signature = crypto
    .createHmac('sha256', process.env.JWT_SECRET!)
    .update(`${btoa(JSON.stringify(header))}.${btoa(JSON.stringify(jwtPayload))}`)
    .digest('base64url')
  
  return `${btoa(JSON.stringify(header))}.${btoa(JSON.stringify(jwtPayload))}.${signature}`
}

export function verifySecureJWT(token: string): any {
  try {
    const [headerB64, payloadB64, signature] = token.split('.')
    const header = JSON.parse(atob(headerB64))
    const payload = JSON.parse(atob(payloadB64))
    
    // Verify signature
    const expectedSignature = crypto
      .createHmac('sha256', process.env.JWT_SECRET!)
      .update(`${headerB64}.${payloadB64}`)
      .digest('base64url')
    
    if (signature !== expectedSignature) {
      throw new Error('Invalid signature')
    }
    
    // Check expiration
    if (payload.exp < Math.floor(Date.now() / 1000)) {
      throw new Error('Token expired')
    }
    
    // Check scope
    if (!payload.scope || !payload.scope.includes('admin:write')) {
      throw new Error('Insufficient permissions')
    }
    
    return payload
  } catch (error) {
    throw new Error('Invalid token')
  }
}

// 2. CRYPTOGRAPHIC FAILURES - Secure password hashing
export function hashPassword(password: string): string {
  const salt = crypto.randomBytes(16).toString('hex')
  const hash = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex')
  return `${salt}:${hash}`
}

export function verifyPassword(password: string, hashedPassword: string): boolean {
  const [salt, hash] = hashedPassword.split(':')
  const hashVerify = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex')
  return hash === hashVerify
}

// 3. INJECTION - Input validation and sanitization
export function validateInput(input: string, type: 'email' | 'text' | 'prompt' | 'category'): string {
  if (!input || typeof input !== 'string') {
    throw new Error('Invalid input')
  }
  
  // Length validation
  const maxLengths = {
    email: 254,
    text: 1000,
    prompt: 10000,
    category: 50
  }
  
  if (input.length > maxLengths[type]) {
    throw new Error(`Input too long (max ${maxLengths[type]} characters)`)
  }
  
  // Content validation
  switch (type) {
    case 'email':
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(input)) {
        throw new Error('Invalid email format')
      }
      break
    case 'text':
    case 'prompt':
      // Basic XSS prevention
      const sanitized = input.replace(/[<>]/g, '')
      if (sanitized !== input) {
        throw new Error('Invalid characters detected')
      }
      break
    case 'category':
      if (!/^[a-zA-Z\s-]+$/.test(input)) {
        throw new Error('Invalid category format')
      }
      break
  }
  
  return input.trim()
}

// 4. INSECURE DESIGN - Rate limiting middleware
export class RateLimiter {
  private static requests = new Map<string, { count: number; resetTime: number }>()
  
  static check(key: string, limit: number, windowMs: number): boolean {
    const now = Date.now()
    const record = this.requests.get(key)
    
    if (!record || now > record.resetTime) {
      this.requests.set(key, { count: 1, resetTime: now + windowMs })
      return true
    }
    
    if (record.count >= limit) {
      return false
    }
    
    record.count++
    return true
  }
}

// 5. SECURITY MISCONFIGURATION - Security headers
export function setSecurityHeaders(response: NextResponse): NextResponse {
  // Content Security Policy
  response.headers.set(
    'Content-Security-Policy',
    "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' https:; connect-src 'self' https://urqzfyvbkmibwhjlpyyo.supabase.co"
  )
  
  // Other security headers
  response.headers.set('X-Content-Type-Options', 'nosniff')
  response.headers.set('X-Frame-Options', 'DENY')
  response.headers.set('X-XSS-Protection', '1; mode=block')
  response.headers.set('Referrer-Policy', 'strict-origin-when-cross-origin')
  response.headers.set('Permissions-Policy', 'camera=(), microphone=(), geolocation=()')
  
  return response
}

// 6. VULNERABLE COMPONENTS - Dependency checking (placeholder)
export function checkDependencies(): boolean {
  // In production, implement automated dependency scanning
  // This is a placeholder for demonstration
  console.log('🔍 Checking for vulnerable dependencies...')
  return true
}

// 7. AUTHENTICATION FAILURES - Secure session management
export class SessionManager {
  private static sessions = new Map<string, { userId: string; expires: number; ip: string }>()
  
  static createSession(userId: string, ip: string): string {
    const sessionId = crypto.randomUUID()
    const expires = Date.now() + (24 * 60 * 60 * 1000) // 24 hours
    
    this.sessions.set(sessionId, { userId, expires, ip })
    return sessionId
  }
  
  static validateSession(sessionId: string, ip: string): any {
    const session = this.sessions.get(sessionId)
    
    if (!session || session.expires < Date.now() || session.ip !== ip) {
      this.sessions.delete(sessionId)
      return null
    }
    
    return session
  }
  
  static revokeSession(sessionId: string): void {
    this.sessions.delete(sessionId)
  }
}

// 8. INTEGRITY FAILURES - Request signing
export function signRequest(data: any): string {
  const timestamp = Date.now().toString()
  const payload = JSON.stringify(data) + timestamp
  const secret = getRequiredEnvVar('REQUEST_SIGNING_SECRET')
  const signature = crypto.createHmac('sha256', secret).update(payload).digest('hex')
  
  return `${timestamp}.${signature}`
}

export function verifyRequest(data: any, signature: string): boolean {
  const [timestamp, sig] = signature.split('.')
  const payload = JSON.stringify(data) + timestamp
  const expectedSig = crypto.createHmac('sha256', getRequiredEnvVar('REQUEST_SIGNING_SECRET')).update(payload).digest('hex')
  
  return sig === expectedSig && (Date.now() - parseInt(timestamp)) < 300000 // 5 minutes
}

// 9. LOGGING AND MONITORING - Security logging
export class SecurityLogger {
  static log(level: 'info' | 'warn' | 'error', event: string, details: any = {}) {
    const logEntry = {
      timestamp: new Date().toISOString(),
      level,
      event,
      details,
      ip: details.ip || 'unknown',
      userAgent: details.userAgent || 'unknown'
    }
    
    console.log(JSON.stringify(logEntry))
    
    // In production, send to security monitoring service
    if (level === 'error' || level === 'warn') {
      // Alert security team
      console.warn('🚨 SECURITY ALERT:', logEntry)
    }
  }
  
  static logAuthAttempt(ip: string, success: boolean, userAgent: string): void {
    this.log(
      success ? 'info' : 'warn',
      'authentication_attempt',
      { ip, success, userAgent }
    )
  }
  
  static logSuspiciousActivity(ip: string, activity: string, details: any): void {
    this.log('error', 'suspicious_activity', { ip, activity, ...details })
  }
}

// 10. SSRF PREVENTION - URL validation
export function validateURL(url: string): boolean {
  try {
    const parsed = new URL(url)
    
    // Allow only specific domains
    const allowedDomains = [
      'urqzfyvbkmibwhjlpyyo.supabase.co',
      'localhost',
      '127.0.0.1'
    ]
    
    return allowedDomains.includes(parsed.hostname)
  } catch {
    return false
  }
}

// Middleware for API routes
export function secureAPI(handler: (req: NextRequest) => Promise<NextResponse>) {
  return async (req: NextRequest): Promise<NextResponse> => {
    const ip = req.headers.get('x-forwarded-for') || req.headers.get('x-real-ip') || 'unknown'
    const userAgent = req.headers.get('user-agent') || 'unknown'
    
    try {
      // Rate limiting
      if (!RateLimiter.check(ip, 100, 60000)) { // 100 requests per minute
        SecurityLogger.logSuspiciousActivity(ip, 'rate_limit_exceeded', { userAgent })
        return NextResponse.json({ error: 'Rate limit exceeded' }, { status: 429 })
      }
      
      // Check for vulnerable dependencies
      if (!checkDependencies()) {
        SecurityLogger.log('error', 'vulnerable_dependencies_detected', { ip, userAgent })
        return NextResponse.json({ error: 'Service unavailable' }, { status: 503 })
      }
      
      // Execute handler
      const response = await handler(req)
      
      // Set security headers
      return setSecurityHeaders(response)
      
    } catch (error: any) {
      SecurityLogger.log('error', 'api_error', { ip, userAgent, error: error.message })
      return NextResponse.json({ error: 'Internal server error' }, { status: 500 })
    }
  }
}
