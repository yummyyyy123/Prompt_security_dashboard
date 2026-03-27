import { NextRequest, NextResponse } from 'next/server'
import { validateAdminCredentials, generateAdminToken } from '@/lib/admin-auth'
import { SecurityLogger } from '@/lib/security-logger'
import crypto from 'crypto'

function identityFp(value: string): string {
  const secret = process.env.SECURITY_IDENTITY_SECRET || ''
  return crypto.createHash('sha256').update(`${secret}:${value.toLowerCase()}`).digest('base64url')
}

// Persistent rate limiting using Supabase
export async function POST(request: NextRequest) {
  const ip = request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() ||
    request.headers.get('x-real-ip') ||
    'unknown'
  const userAgent = request.headers.get('user-agent') || 'unknown'

  try {
    // Check persistent rate limiting (30m window, 5 attempts)
    const isLimited = await SecurityLogger.isRateLimited(ip)
    if (isLimited) {
      console.warn(`🚨 Rate limit exceeded for IP: ${ip}`)
      await SecurityLogger.logRateLimit(ip, '/api/admin/auth')
      return NextResponse.json(
        {
          error: 'Too many login attempts. Access locked for 30 minutes for security.',
          timestamp: new Date().toISOString()
        },
        { status: 429 }
      )
    }

    const body = await request.json()
    const { username, password } = body

    const fp = typeof username === 'string' && username.length > 0 ? identityFp(username) : ''
    if (fp) {
      const identityLimited = await SecurityLogger.isIdentityRateLimited(fp, 30 * 60 * 1000, 8)
      if (identityLimited) {
        await SecurityLogger.logEvent({
          eventType: 'bruteforce_detected',
          severity: 'critical',
          ip,
          userAgent,
          endpointPath: '/api/admin/auth',
          requestMethod: 'POST',
          details: { identity_fp: fp, reason: 'identity_rate_limit' }
        })
        return NextResponse.json(
          { error: 'Too many login attempts. Access locked for 30 minutes for security.' },
          { status: 429 }
        )
      }
    }

    // Validate credentials using the library function (which uses bcrypt)
    if (!validateAdminCredentials(username, password)) {
      console.warn(`🚨 [AUTH] Failed login for user: ${username} (IP: ${ip})`)
      await SecurityLogger.logEvent({
        eventType: 'login_failure',
        severity: 'warning',
        ip,
        userAgent,
        details: { identity_fp: fp, auth_step: 'credentials' }
      })
      console.log('🛡️ [AUTH] Login failure event dispatched');

      return NextResponse.json(
        {
          error: 'Invalid credentials',
          timestamp: new Date().toISOString()
        },
        { status: 401 }
      )
    }

    // Generate token using our secure function
    const authResult = generateAdminToken(username, password)

    if (!authResult.success) {
      return NextResponse.json(
        {
          error: 'Token generation failed',
          message: authResult.error,
          timestamp: new Date().toISOString()
        },
        { status: 500 }
      )
    }

    await SecurityLogger.logEvent({
      eventType: 'login_success',
      severity: 'info',
      ip,
      userAgent,
      details: { log_class: 'noise', identity_fp: fp }
    })

    // Set secure HTTP-only cookie
    const response = NextResponse.json({
      success: true,
      message: 'Login successful',
      token: authResult.token, // Also return token for client-side storage
      timestamp: new Date().toISOString()
    })

    // Set HTTP-only secure cookie
    response.cookies.set('admin-token', authResult.token!, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 24 * 60 * 60, // 24 hours
      path: '/'
    })

    // Add security headers
    response.headers.set('X-Content-Type-Options', 'nosniff')
    response.headers.set('X-Frame-Options', 'DENY')
    response.headers.set('X-XSS-Protection', '1; mode=block')
    response.headers.set('Referrer-Policy', 'strict-origin-when-cross-origin')

    return response

  } catch (error: any) {
    console.error('💥 Login error:', error)
    return NextResponse.json(
      { error: 'Login failed: ' + (error?.message || 'Unknown error') },
      { status: 500 }
    )
  }
}

export async function DELETE(request: NextRequest) {
  try {
    console.log('🚪 Logout request received')

    // Clear the authentication cookie
    const response = NextResponse.json({
      message: 'Logout successful'
    })

    response.cookies.set('admin-token', '', {
      httpOnly: true,
      secure: false,
      sameSite: 'lax',
      maxAge: 0 // Immediately expire the cookie
    })

    console.log('🍪 Cookie cleared for logout')
    return response

  } catch (error: any) {
    console.error('💥 Logout error:', error)
    return NextResponse.json(
      { error: 'Logout failed: ' + (error?.message || 'Unknown error') },
      { status: 500 }
    )
  }
}
