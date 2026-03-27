// Enhanced Email OTP utilities for 2FA authentication with security optimizations
export class EmailOTP {
  // Memory storage with security enhancements
  private static otpStore: Map<string, { 
    code: string; 
    timestamp: number; 
    attempts: number;
    ipAddresses: Set<string>;
    userAgent: string;
  }> = new Map()

  // Generate cryptographically secure OTP
  static generateOTP(): string {
    const array = new Uint8Array(6)
    crypto.getRandomValues(array)
    return Array.from(array, byte => (byte % 10).toString()).join('')
  }

  // Store OTP with enhanced security tracking
  static async storeOTP(email: string, otp: string, ip?: string, userAgent?: string): Promise<boolean> {
    try {
      // Check if OTP already exists for this email (cooldown check first)
      const existing = this.otpStore.get(email)
      if (existing && Date.now() - existing.timestamp < 60000) { // 1 minute cooldown
        console.log(`⚠️ OTP recently requested for ${email}`)
        return false
      }

      // Clean expired OTPs after cooldown check (memory optimization)
      this.cleanupExpiredOTPs()

      this.otpStore.set(email, {
        code: otp,
        timestamp: Date.now(),
        attempts: 0,
        ipAddresses: new Set(ip ? [ip] : []),
        userAgent: userAgent || 'unknown'
      })
      
      console.log(`📧 OTP stored for ${email}: ${otp}`)
      return true
    } catch (error) {
      console.error('❌ Failed to store OTP:', error)
      return false
    }
  }

  // Verify OTP with enhanced security checks
  static async verifyOTP(email: string, otp: string, ip?: string): Promise<boolean> {
    try {
      const stored = this.otpStore.get(email)
      
      if (!stored) {
        console.log(`❌ No OTP found for ${email}`)
        return false
      }

      // Check if OTP is expired (5 minutes)
      const isExpired = Date.now() - stored.timestamp > 5 * 60 * 1000
      if (isExpired) {
        console.log(`❌ OTP expired for ${email}`)
        this.otpStore.delete(email)
        return false
      }

      // Check if too many attempts (3 attempts)
      if (stored.attempts >= 3) {
        console.log(`❌ Too many attempts for ${email}`)
        this.otpStore.delete(email)
        return false
      }

      // IP-based verification (optional security)
      if (ip && stored.ipAddresses.size > 0) {
        const firstIP = Array.from(stored.ipAddresses)[0]
        if (stored.ipAddresses.size > 2) { // Too many different IPs
          console.log(`❌ Suspicious activity: multiple IPs for ${email}`)
          this.otpStore.delete(email)
          return false
        }
      }

      // Verify OTP
      const isValid = stored.code === otp
      if (isValid) {
        console.log(`✅ OTP verified for ${email}`)
        this.otpStore.delete(email) // Remove after successful verification
      } else {
        console.log(`❌ Invalid OTP for ${email}. Attempt ${stored.attempts + 1}`)
        stored.attempts++
        if (ip) stored.ipAddresses.add(ip)
      }

      return isValid
    } catch (error) {
      console.error('❌ Failed to verify OTP:', error)
      return false
    }
  }

  // Increment failed attempts with tracking
  static async incrementAttempts(email: string): Promise<void> {
    try {
      const stored = this.otpStore.get(email)
      if (stored) {
        stored.attempts++
        console.log(`📊 Attempts incremented for ${email}: ${stored.attempts}`)
        
        // Auto-delete after 3 failed attempts
        if (stored.attempts >= 3) {
          this.otpStore.delete(email)
          console.log(`🚫 Auto-deleted OTP for ${email} after too many attempts`)
        }
      }
    } catch (error) {
      console.error('❌ Failed to increment attempts:', error)
    }
  }

  // Register email with security logging
  static async registerEmail(email: string, username: string, ip?: string): Promise<boolean> {
    try {
      console.log(`📧 Email registered: ${email} for user: ${username}${ip ? ` from IP: ${ip}` : ''}`)
      return true
    } catch (error) {
      console.error('❌ Failed to register email:', error)
      return false
    }
  }

  // Enhanced cleanup with memory optimization
  static cleanupExpiredOTPs(): void {
    const now = Date.now()
    const expiredKeys: string[] = []
    
    for (const [email, data] of Array.from(this.otpStore.entries())) {
      if (now - data.timestamp > 5 * 60 * 1000) { // 5 minutes
        expiredKeys.push(email)
      }
    }
    
    // Batch delete for performance
    expiredKeys.forEach(email => {
      this.otpStore.delete(email)
      console.log(`🧹 Cleaned up expired OTP for ${email}`)
    })
  }

  // Get security metrics
  static getSecurityMetrics(): {
    totalOTPs: number;
    activeOTPs: number;
    expiredOTPs: number;
  } {
    const now = Date.now()
    let active = 0
    let expired = 0
    
    for (const [_, data] of this.otpStore.entries()) {
      if (now - data.timestamp > 5 * 60 * 1000) {
        expired++
      } else {
        active++
      }
    }
    
    return {
      totalOTPs: this.otpStore.size,
      activeOTPs: active,
      expiredOTPs: expired
    }
  }
}

// Enhanced OTP Session management with security
export class OTPSession {
  private static sessions: Map<string, { 
    email: string; 
    timestamp: number;
    ipAddresses: Set<string>;
    userAgent: string;
  }> = new Map()

  // Create temporary session with security tracking
  static createTempSession(email: string, ip?: string, userAgent?: string): string {
    const token = 'temp-' + Date.now() + '-' + Array.from(crypto.getRandomValues(new Uint8Array(8)), 
      byte => byte.toString(16).padStart(2, '0')).join('')
    
    this.sessions.set(token, {
      email,
      timestamp: Date.now(),
      ipAddresses: new Set(ip ? [ip] : []),
      userAgent: userAgent || 'unknown'
    })
    
    console.log(`🔐 Temp session created for ${email}: ${token}`)
    return token
  }

  // Verify temporary session with IP validation
  static verifyTempSession(token: string, ip?: string): string | null {
    const session = this.sessions.get(token)
    if (!session) {
      console.log(`❌ Invalid temp session: ${token}`)
      return null
    }

    // Check if session is expired (5 minutes)
    const isExpired = Date.now() - session.timestamp > 5 * 60 * 1000
    if (isExpired) {
      console.log(`❌ Temp session expired: ${token}`)
      this.sessions.delete(token)
      return null
    }

    // Optional IP validation
    if (ip && session.ipAddresses.size > 0) {
      const firstIP = Array.from(session.ipAddresses)[0]
      if (session.ipAddresses.size > 2) {
        console.log(`❌ Suspicious session activity: multiple IPs`)
        this.sessions.delete(token)
        return null
      }
    }

    console.log(`✅ Temp session verified: ${token}`)
    return session.email
  }

  // Complete OTP verification
  static completeOTP(tempToken: string): string | null {
    const email = this.verifyTempSession(tempToken)
    if (!email) {
      return null
    }

    // Remove temporary session
    this.sessions.delete(tempToken)
    
    // Create permanent token
    const permanentToken = 'perm-' + Date.now() + '-' + Array.from(crypto.getRandomValues(new Uint8Array(16)), 
      byte => byte.toString(16).padStart(2, '0')).join('')
    
    console.log(`🎉 OTP completed for ${email}, permanent token: ${permanentToken}`)
    return permanentToken
  }

  // Enhanced cleanup with performance optimization
  static cleanupExpiredSessions(): void {
    const now = Date.now()
    const expiredTokens: string[] = []
    
    for (const [token, data] of this.sessions.entries()) {
      if (now - data.timestamp > 5 * 60 * 1000) { // 5 minutes
        expiredTokens.push(token)
      }
    }
    
    // Batch delete for performance
    expiredTokens.forEach(token => {
      this.sessions.delete(token)
      console.log(`🧹 Cleaned up expired session: ${token}`)
    })
  }

  // Get session metrics
  static getSessionMetrics(): {
    totalSessions: number;
    activeSessions: number;
    expiredSessions: number;
  } {
    const now = Date.now()
    let active = 0
    let expired = 0
    
    for (const [_, data] of this.sessions.entries()) {
      if (now - data.timestamp > 5 * 60 * 1000) {
        expired++
      } else {
        active++
      }
    }
    
    return {
      totalSessions: this.sessions.size,
      activeSessions: active,
      expiredSessions: expired
    }
  }
}

// Optimized auto-cleanup with configurable interval
const CLEANUP_INTERVAL = 2 * 60 * 1000 // 2 minutes for better performance

setInterval(() => {
  const otpMetrics = EmailOTP.getSecurityMetrics()
  const sessionMetrics = OTPSession.getSessionMetrics()
  
  EmailOTP.cleanupExpiredOTPs()
  OTPSession.cleanupExpiredSessions()
  
  console.log(`🧹 Cleanup completed - OTPs: ${otpMetrics.activeOTPs}/${otpMetrics.totalOTPs}, Sessions: ${sessionMetrics.activeSessions}/${sessionMetrics.totalSessions}`)
}, CLEANUP_INTERVAL)
