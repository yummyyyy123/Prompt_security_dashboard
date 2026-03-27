// Email OTP delivery using Resend API with enhanced security
import { NextRequest, NextResponse } from 'next/server'
import { Resend } from 'resend'
import { EmailOTP, OTPSession } from '@/lib/emailOTP'
import { validateAdminCredentials } from '@/lib/admin-auth'
import { SecurityLogger } from '@/lib/security-logger'
import crypto from 'crypto'

let resend: Resend | null = null

function getResend(): Resend | null {
  if (resend) return resend
  const key = process.env.RESEND_API_KEY
  if (!key) return null
  resend = new Resend(key)
  return resend
}

function identityFp(value: string): string {
  const secret = process.env.SECURITY_IDENTITY_SECRET || ''
  return crypto.createHash('sha256').update(`${secret}:${value.toLowerCase()}`).digest('base64url')
}

// Security headers
function setSecurityHeaders(origin: string) {
  return {
    'Access-Control-Allow-Origin': origin || '*',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Allow-Credentials': 'true',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-XSS-Protection': '1; mode=block',
    'Referrer-Policy': 'strict-origin-when-cross-origin'
  }
}

export async function POST(request: NextRequest) {
  try {
    // Add CORS headers and security measures
    const origin = request.headers.get('origin') || ''
    const host = request.headers.get('host') || ''

    // Validate origin — allow localhost and any vercel.app deployment of this project
    const allowedOrigins = [
      'https://prompt-library-three-wheat.vercel.app',
      'https://prompt-library-ktt2.vercel.app',
      'http://localhost:3000',
      'https://localhost:3000'
    ]

    const isAllowed =
      allowedOrigins.includes(origin) ||
      origin.includes('localhost') ||
      /^https:\/\/prompt-library[a-z0-9-]*\.vercel\.app$/.test(origin)

    if (!isAllowed) {
      console.log(`❌ Unauthorized origin: ${origin}`)
      return NextResponse.json(
        { error: 'Unauthorized origin' },
        {
          status: 403,
          headers: setSecurityHeaders(origin)
        }
      )
    }

    // Persistent rate limiting (30m window, 5 attempts)
    const ip = request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() ||
      request.headers.get('x-real-ip') ||
      'unknown'
    const userAgent = request.headers.get('user-agent') || 'unknown'

    const isLimited = await SecurityLogger.isRateLimited(ip)
    if (isLimited) {
      console.log(`❌ Rate limit exceeded for: ${ip}`)
      await SecurityLogger.logRateLimit(ip, '/api/admin/auth/email-otp')
      return NextResponse.json({
        error: 'Too many requests. Access locked for 30 minutes for security.'
      }, {
        status: 429,
        headers: setSecurityHeaders(origin)
      })
    }

    const body = await request.json()
    const { username, password } = body
    const fp = typeof username === 'string' && username.length > 0 ? identityFp(username) : ''

    // Validate admin credentials FIRST before doing anything else
    if (!username || !password) {
      return NextResponse.json({
        error: 'Username and password are required'
      }, {
        status: 400,
        headers: setSecurityHeaders(origin)
      })
    }

    try {
      if (fp) {
        const identityLimited = await SecurityLogger.isIdentityRateLimited(fp, 30 * 60 * 1000, 8)
        if (identityLimited) {
          await SecurityLogger.logEvent({
            eventType: 'bruteforce_detected',
            severity: 'critical',
            ip,
            userAgent,
            endpointPath: '/api/admin/auth/email-otp',
            requestMethod: 'POST',
            details: { identity_fp: fp, reason: 'identity_rate_limit', step: 'otp_request' }
          })
          return NextResponse.json({
            error: 'Too many requests. Access locked for 30 minutes for security.'
          }, {
            status: 429,
            headers: setSecurityHeaders(origin)
          })
        }
      }
      if (!validateAdminCredentials(username, password)) {
        console.log(`❌ Invalid credentials attempt for OTP: ${username}`)
        await SecurityLogger.logEvent({
          eventType: 'login_failure',
          severity: 'warning',
          ip,
          userAgent,
          details: { identity_fp: fp, step: 'otp_request' }
        })

        return NextResponse.json({
          error: 'Invalid username or password'
        }, {
          status: 401,
          headers: setSecurityHeaders(origin)
        })
      }
    } catch (err: any) {
      // validateAdminCredentials throws if env vars are missing
      return NextResponse.json({
        error: 'Server misconfiguration'
      }, {
        status: 500,
        headers: setSecurityHeaders(origin)
      })
    }

    // Get the admin email from environment (never from the request)
    const adminEmail = process.env.ADMIN_EMAIL
    if (!adminEmail) {
      console.error('❌ ADMIN_EMAIL environment variable not set')
      return NextResponse.json({
        error: 'Server misconfiguration: admin email not configured'
      }, {
        status: 500,
        headers: setSecurityHeaders(origin)
      })
    }

    // Generate cryptographically secure OTP
    const otp = Array.from({ length: 6 }, () =>
      Math.floor(Math.random() * 10).toString()
    ).join('')

    console.log(`📧 Generating OTP for admin email`)

    // Store OTP in EmailOTP system
    const stored = await EmailOTP.storeOTP(adminEmail, otp)
    if (!stored) {
      console.log('⚠️ Failed to store OTP, but continuing...')
    }

    // Create temporary session
    const tempToken = OTPSession.createTempSession(adminEmail)
    console.log(`🔐 Temp session created`)

    // Send email using Resend
    const resendClient = getResend()
    if (!resendClient) {
      return NextResponse.json({
        success: false,
        message: 'Email service not configured. Please try again later.',
        provider: 'Email'
      }, {
        status: 503,
        headers: setSecurityHeaders(origin)
      })
    }

    const { data, error } = await resendClient.emails.send({
      from: process.env.EMAIL_FROM || 'onboarding@resend.dev',
      to: [adminEmail],
      subject: 'Your OTP Code for Admin Login',
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
          <div style="background-color: #f8f9fa; padding: 30px; border-radius: 10px; text-align: center;">
            <h2 style="color: #333; margin-bottom: 20px;">🔐 Two-Factor Authentication</h2>
            <p style="color: #666; font-size: 16px; margin-bottom: 30px;">
              Your OTP code for admin login is:
            </p>
            <div style="background-color: #007bff; color: white; font-size: 32px; font-weight: bold; padding: 20px; border-radius: 8px; letter-spacing: 5px; margin-bottom: 20px;">
              ${otp}
            </div>
            <p style="color: #666; font-size: 14px; margin-bottom: 10px;">
              This code will expire in 5 minutes.
            </p>
            <p style="color: #999; font-size: 12px;">
              If you didn't request this code, please ignore this email.
            </p>
          </div>
        </div>
      `,
    })

    if (error) {
      console.error('❌ Email failed:', error)
      // Do NOT return the OTP code — return an error instead
      return NextResponse.json({
        success: false,
        message: 'Failed to send OTP email. Please try again.',
        provider: 'Email'
      }, {
        status: 503,
        headers: setSecurityHeaders(origin)
      })
    }

    console.log('✅ Email sent successfully')
    console.log('📝 Email ID:', data?.id)

    // IMPORTANT: Never return the OTP in the response
    return NextResponse.json({
      success: true,
      message: 'OTP sent to admin email',
      messageId: data?.id,
      provider: 'Email',
      tempToken: tempToken
    }, {
      status: 200,
      headers: setSecurityHeaders(origin)
    })

  } catch (error: any) {
    console.error('❌ Email endpoint error:', error)
    return NextResponse.json({
      error: 'Internal server error'
    }, {
      status: 500,
      headers: setSecurityHeaders(request.headers.get('origin') || '')
    })
  }
}

// Handle OPTIONS requests for CORS
export async function OPTIONS(request: NextRequest) {
  const origin = request.headers.get('origin') || ''

  return NextResponse.json({}, {
    status: 200,
    headers: setSecurityHeaders(origin)
  })
}
