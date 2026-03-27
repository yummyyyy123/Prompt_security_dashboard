// Fix 2FA - Always require OTP for admin login
import { NextRequest, NextResponse } from 'next/server'
import jwt from 'jsonwebtoken'
import { EmailOTP, OTPSession } from '../../../../lib/emailOTP'
import { SecurityLogger } from '../../../../lib/security-logger'
import crypto from 'crypto'

function identityFp(value: string): string {
  const secret = process.env.SECURITY_IDENTITY_SECRET || ''
  return crypto.createHash('sha256').update(`${secret}:${value.toLowerCase()}`).digest('base64url')
}

export async function POST(request: NextRequest) {
  const ip = request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() ||
    request.headers.get('x-real-ip') ||
    'unknown'
  const userAgent = request.headers.get('user-agent') || 'unknown'

  try {
    // Add CORS headers and handle host validation
    const origin = request.headers.get('origin') || ''
    const host = request.headers.get('host') || ''

    // Persistent rate limiting (30m window, 5 attempts)
    const isLimited = await SecurityLogger.isRateLimited(ip)
    if (isLimited) {
      console.warn(`🚨 Rate limit exceeded for IP: ${ip}`)
      await SecurityLogger.logRateLimit(ip, '/api/admin/auth/2fa-login')
      return NextResponse.json(
        {
          error: 'Too many verification attempts. Access locked for 30 minutes for security.',
          timestamp: new Date().toISOString()
        },
        { status: 429 }
      )
    }

    const { username, email, action, otp, tempToken } = await request.json()
    const JWT_SECRET = process.env.JWT_SECRET ?? ''
    const fpSource = typeof email === 'string' && email.length > 0 ? email : (typeof username === 'string' ? username : '')
    const fp = fpSource ? identityFp(fpSource) : ''
    if (fp) {
      const identityLimited = await SecurityLogger.isIdentityRateLimited(fp, 30 * 60 * 1000, 8)
      if (identityLimited) {
        await SecurityLogger.logEvent({
          eventType: 'bruteforce_detected',
          severity: 'critical',
          ip,
          userAgent,
          endpointPath: '/api/admin/auth/2fa-login',
          requestMethod: 'POST',
          details: { identity_fp: fp, reason: 'identity_rate_limit', step: 'otp_verify' }
        })
        return NextResponse.json(
          { error: 'Too many verification attempts. Access locked for 30 minutes for security.' },
          { status: 429 }
        )
      }
    }

    if (action === 'verify-otp') {
      // Step 2: Verify OTP
      if (!otp || !tempToken) {
        console.warn(`🚨 [2FA_LOGIN] MFA Bypass: Missing OTP or Token (IP: ${ip})`);
        await SecurityLogger.logEvent({
          eventType: 'mfa_bypass_attempt',
          severity: 'critical',
          ip,
          userAgent,
          details: { reason: 'missing_otp_or_token', identity_fp: fp }
        })
        console.log('🛡️ [2FA_LOGIN] MFA bypass log dispatched');

        return NextResponse.json({
          error: 'OTP and temporary token required'
        }, { status: 400 })
      }

      // Retrieve email from temporary session if not provided
      let effectiveEmail = email
      if (!effectiveEmail) {
        effectiveEmail = OTPSession.verifyTempSession(tempToken) || process.env.ADMIN_EMAIL
      }

      if (!effectiveEmail) {
        await SecurityLogger.logEvent({
          eventType: 'mfa_bypass_attempt',
          severity: 'critical',
          ip,
          userAgent,
          details: { reason: 'session_expired_or_invalid_token' }
        })

        return NextResponse.json({
          error: 'Session invalid or expired'
        }, { status: 401 })
      }

      // Verify OTP — strictly validate against stored OTP only
      let isValid = false

      try {
        isValid = await EmailOTP.verifyOTP(effectiveEmail, otp, ip)
      } catch (error) {
        // Database unavailable — cannot verify OTP safely, reject
        console.error('⚠️ Database error during OTP verification:', error)
        return NextResponse.json({
          error: 'Verification service unavailable. Please try again.'
        }, { status: 503 })
      }

      if (!isValid) {
        // Increment failed attempts
        try {
          await EmailOTP.incrementAttempts(effectiveEmail)
        } catch (error) {
          console.log('⚠️ Could not increment attempts (database not ready)')
        }
        console.warn(`🚨 [2FA_LOGIN] MFA Failure: Invalid OTP for IP ${ip}`);
        await SecurityLogger.logEvent({
          eventType: 'mfa_verify_failure',
          severity: 'warning',
          ip,
          userAgent,
          details: { identity_fp: fp, step: 'otp_verify' }
        })
        console.log('🛡️ [2FA_LOGIN] MFA failure log dispatched');

        return NextResponse.json({
          error: 'Invalid OTP. Please try again.'
        }, { status: 400 })
      }

      // Complete OTP verification
      const permanentToken = OTPSession.completeOTP(tempToken)

      if (!permanentToken) {
        return NextResponse.json({
          error: 'Session expired. Please try again.'
        }, { status: 400 })
      }

      await SecurityLogger.logEvent({
        eventType: 'mfa_verify_success',
        severity: 'info',
        ip,
        userAgent,
        details: { log_class: 'noise', identity_fp: fp, step: 'otp_verify' }
      })

      const token = jwt.sign(
        {
          username: username || process.env.ADMIN_USERNAME || 'admin',
          role: 'admin',
          twoFactorVerified: true,
          email: effectiveEmail.slice(-4) // Only store last 4 digits
        },
        JWT_SECRET,
        { expiresIn: '1h' }
      )

      const response = NextResponse.json({
        message: '2FA verification successful',
        requiresOTP: false,
        token
      }, {
        status: 200,
        headers: {
          'Access-Control-Allow-Origin': origin || '*',
          'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type, Authorization',
          'Access-Control-Allow-Credentials': 'true'
        }
      })

      response.cookies.set('admin-token', token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 3600 // 1 hour
      })

      return response

    } else {
      await SecurityLogger.logEvent({
        eventType: 'mfa_bypass_attempt',
        severity: 'warning',
        ip,
        userAgent,
        details: { action, reason: 'invalid_action' }
      })

      return NextResponse.json({
        error: 'Invalid action'
      }, { status: 401 })
    }

  } catch (error: any) {
    console.error('2FA login error:', error)
    return NextResponse.json({
      error: 'Login failed'
    }, { status: 500 })
  }
}

export async function GET(request: NextRequest) {
  try {
    const token = request.cookies.get('admin-token')?.value || ''
    const JWT_SECRET = process.env.JWT_SECRET ?? ''

    if (!token) {
      return NextResponse.json({
        authenticated: false,
        requiresOTP: false
      })
    }

    const decoded = jwt.verify(token, JWT_SECRET) as any

    return NextResponse.json({
      authenticated: true,
      requiresOTP: !decoded.twoFactorVerified,
      emailLastFour: decoded.email || null
    })

  } catch (error: any) {
    return NextResponse.json({
      authenticated: false,
      requiresOTP: false
    })
  }
}
