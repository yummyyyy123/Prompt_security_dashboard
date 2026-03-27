import { NextRequest, NextResponse } from 'next/server'
import jwt from 'jsonwebtoken'
import bcrypt from 'bcryptjs'
import { SecurityLogger } from './security-logger'
import { detectVulnerabilityScanner, identifyScannerType, detectWafAttack } from '@/middleware-functions'

// Admin credentials — required environment variables (no defaults allowed)
// Enhanced environment variable validation
export function validateEnvironmentVariables() {
  const required = [
    'NEXT_PUBLIC_SUPABASE_URL',
    'SUPABASE_SERVICE_KEY',
    'JWT_SECRET'
  ];
  
  const optional = [
    'ADMIN_USERNAME',
    'ADMIN_PASSWORD',
    'REQUEST_SIGNING_SECRET',
    'GITHUB_TOKEN',
    'GITHUB_OWNER',
    'GITHUB_REPO'
  ];
  
  const missing: string[] = [];
  const present: string[] = [];
  
  // Check required variables
  for (const envVar of required) {
    if (!process.env[envVar]) {
      missing.push(envVar);
    } else {
      present.push(envVar);
    }
  }
  
  // Check optional variables
  for (const envVar of optional) {
    if (process.env[envVar]) {
      present.push(envVar);
    }
  }
  
  return {
    required,
    optional,
    missing,
    present,
    isValid: missing.length === 0,
    configuredCount: present.length,
    totalRequired: required.length
  };
}

export function getRequiredEnvVar(name: string): string {
  const value = process.env[name];
  if (!value) {
    throw new Error(`Required environment variable ${name} is not configured`);
  }
  return value;
}

export function getOptionalEnvVar(name: string, defaultValue: string = ''): string {
  return process.env[name] || defaultValue;
}

function getEnvVar(name: string): string {
  const value = process.env[name];
  if (value === undefined) {
    throw new Error(`Environment variable ${name} is not set`);
  }
  return value;
}

const ADMIN_USERNAME = getOptionalEnvVar('ADMIN_USERNAME', '')
const ADMIN_PASSWORD = getOptionalEnvVar('ADMIN_PASSWORD', '')
function getJwtSecret(): string | null {
  return process.env.JWT_SECRET || null
}

interface AdminAuthResult {
  success: boolean
  token?: string
  error?: string
}

export function validateAdminCredentials(username: string, password: string): boolean {
  if (!ADMIN_USERNAME || !ADMIN_PASSWORD) {
    throw new Error('Server misconfiguration: admin credentials not set')
  }

  const usernameMatch = username === ADMIN_USERNAME

  // Use bcrypt for password comparison
  try {
    const passwordMatch = bcrypt.compareSync(password, ADMIN_PASSWORD)
    return usernameMatch && passwordMatch
  } catch (error) {
    console.error('💥 Bcrypt comparison error:', error)
    return false
  }
}

export function authenticateAdmin(request: NextRequest): AdminAuthResult {
  try {
    // Get authorization header or cookie
    const authHeader = request.headers.get('authorization')
    const cookieToken = request.cookies.get('admin-token')?.value

    let token = ''
    if (authHeader && authHeader.startsWith('Bearer ')) {
      token = authHeader.substring(7)
    } else if (cookieToken) {
      token = cookieToken
    }

    if (!token) {
      return { success: false, error: 'Missing or invalid authentication' }
    }

    try {
      const JWT_SECRET = getJwtSecret()
      if (!JWT_SECRET) {
        return { success: false, error: 'Server misconfiguration: JWT_SECRET not set' }
      }

      // Verify JWT token
      const decoded = jwt.verify(token, JWT_SECRET) as any

      // Check if token is for admin
      if (decoded.role !== 'admin') {
        return { success: false, error: 'Invalid admin credentials' }
      }

      // Check if token is expired
      if (decoded.exp && Date.now() > decoded.exp * 1000) {
        return { success: false, error: 'Token expired' }
      }

      return { success: true }
    } catch (jwtError) {
      return { success: false, error: 'Invalid token' }
    }
  } catch (error) {
    return { success: false, error: 'Authentication failed' }
  }
}

export function generateAdminToken(username: string, password: string): AdminAuthResult {
  try {
    const JWT_SECRET = getJwtSecret()
    if (!JWT_SECRET) {
      return { success: false, error: 'Server misconfiguration: JWT_SECRET not set' }
    }

    // Validate credentials
    if (!validateAdminCredentials(username, password)) {
      // Log login failure
      logLoginAttempt(username, false, 'unknown', 'unknown').catch(console.error)
      return { success: false, error: 'Invalid credentials' }
    }

    // Generate JWT token
    const token = jwt.sign(
      {
        username: ADMIN_USERNAME,
        role: 'admin',
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + (24 * 60 * 60) // 24 hours
      },
      JWT_SECRET
    )

    // Log login success
    logLoginAttempt(username, true, 'unknown', 'unknown').catch(console.error)

    return { success: true, token }
  } catch (error) {
    return { success: false, error: 'Token generation failed' }
  }
}

// Helper function to log login attempts
async function logLoginAttempt(username: string, success: boolean, ip: string, userAgent: string) {
  try {
    await SecurityLogger.logEvent({
      eventType: success ? 'login_success' : 'login_failure',
      severity: success ? 'info' : 'warning',
      ip,
      userAgent,
      details: {
        username: success ? '[REDACTED_USER]' : username,
        login_method: 'admin_panel',
        timestamp: new Date().toISOString()
      }
    })
  } catch (error) {
    console.error('Failed to log login attempt:', error)
  }
}

// Middleware for admin API routes
export function withAdminAuth(handler: (req: NextRequest) => Promise<NextResponse>) {
  return async (request: NextRequest): Promise<NextResponse> => {
    try {
      const ip = request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() ||
        request.headers.get('x-real-ip') ||
        'unknown'
      const userAgent = request.headers.get('user-agent') || 'unknown'
      const url = new URL(request.url)
      const path = url.pathname
      const geo = (request as any).geo || {}
      const asnNumber = request.headers.get('x-vercel-ip-as-number')
      const asnName = request.headers.get('x-vercel-ip-as-name')
      const country = request.headers.get('x-vercel-ip-country') || geo?.country
      const region = request.headers.get('x-vercel-ip-country-region') || geo?.region
      const city = request.headers.get('x-vercel-ip-city') || geo?.city
      const datacenterLikely = !!(asnName && /(amazon|google|microsoft|digitalocean|ovh|linode|hetzner)/i.test(asnName))
      const intel = { country, region, city, asn_number: asnNumber, asn_name: asnName, datacenter_likely: datacenterLikely }

      // Check for scanners BEFORE authentication
      const isScanner = detectVulnerabilityScanner(userAgent, path)
      const wafHit = detectWafAttack(path, url.searchParams.toString(), {
        'user-agent': userAgent,
        'referer': request.headers.get('referer'),
        'accept-language': request.headers.get('accept-language')
      })
      
      // Enhanced curl detection with multiple patterns
      const curlPatterns = [
        userAgent.toLowerCase().includes('curl'),
        userAgent.toLowerCase().startsWith('curl'),
        userAgent.match(/curl/i) !== null,
        userAgent.includes('curl/'),
        userAgent.includes('libcurl'),
        userAgent.toLowerCase().includes('curl/')
      ];
      const isCurl = curlPatterns.some(pattern => pattern) && !isScanner; // Only curl if NOT scanner

      if (isScanner) {
        const scannerType = identifyScannerType(userAgent)
        console.log(`🚨 SCANNER DETECTED: ${scannerType} from IP=${ip}`)
        
        await SecurityLogger.logEvent({
          eventType: 'vulnerability_scan_detected',
          severity: 'critical',
          ip,
          userAgent,
          endpointPath: path,
          details: {
            ...intel,
            scanner_type: scannerType,
            detection_method: 'user_agent',
            path,
            access_denied_reason: 'scanner_detected_admin_route'
          }
        })

        return NextResponse.json(
          {
            error: 'Access denied',
            reason: 'Scanner detected - access blocked',
            scanner_type: scannerType,
            timestamp: new Date().toISOString()
          },
          { status: 403 }
        )
      }

      if (wafHit) {
        await SecurityLogger.logEvent({
          eventType: 'waf_attack_detected',
          severity: wafHit.score >= 70 ? 'critical' : 'warning',
          ip,
          userAgent,
          endpointPath: path,
          details: {
            ...intel,
            attack_type: wafHit.attack_type,
            match: wafHit.match,
            score: wafHit.score
          }
        })
      }

      if (isCurl) {
        console.log(`🔍 CURL DETECTED: IP=${ip}`)
        
        await SecurityLogger.logEvent({
          eventType: 'unauthorized_api_access',
          severity: 'warning',
          ip,
          userAgent,
          endpointPath: path,
          details: {
            ...intel,
            detection_method: 'user_agent',
            path,
            access_denied_reason: 'curl_detected_admin_route',
            request_type: 'curl'
          }
        })
      }

      const auth = authenticateAdmin(request)

      if (!auth.success) {
        // Log unauthorized attempt to the database
        await SecurityLogger.logEvent({
          eventType: 'unauthorized_access',
          severity: 'warning',
          ip,
          userAgent,
          endpointPath: path,
          details: {
            ...intel,
            path,
            access_denied_reason: 'unauthorized_admin_access',
            auth_method: auth.error?.includes('token') ? 'token' : 'missing_auth'
          }
        })

        return NextResponse.json(
          {
            error: 'Unauthorized',
            message: auth.error || 'Authentication required',
            timestamp: new Date().toISOString()
          },
          { status: 401 }
        )
      }

      // Add security headers
      const response = await handler(request)

      // Add security headers to response
      response.headers.set('X-Content-Type-Options', 'nosniff')
      response.headers.set('X-Frame-Options', 'DENY')
      response.headers.set('X-XSS-Protection', '1; mode=block')
      response.headers.set('Referrer-Policy', 'strict-origin-when-cross-origin')

      return response
    } catch (error: any) {
      console.error('💥 Admin Auth Middleware Error:', error)
      return NextResponse.json(
        {
          error: 'Unauthorized',
          message: 'An unexpected authentication error occurred',
          timestamp: new Date().toISOString()
        },
        { status: 401 }
      )
    }
  }
}

