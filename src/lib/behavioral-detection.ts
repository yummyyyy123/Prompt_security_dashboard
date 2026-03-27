import { NextRequest } from 'next/server'
import { createClient } from '@supabase/supabase-js'

const supabase = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL!,
  process.env.SUPABASE_SERVICE_ROLE_KEY!
)

// Request tracking for behavioral analysis
interface RequestHistory {
  ip: string
  requests: Array<{
    timestamp: number
    endpoint: string
    method: string
    userAgent: string
    headers: Record<string, string>
    responseStatus?: number
  }>
  uniqueEndpoints: Set<string>
  uniqueUserAgents: Set<string>
  timeWindow: number // 5 minutes
  lastActivity: number
}

const requestHistory = new Map<string, RequestHistory>()

// Advanced scanner detection patterns
const ADVANCED_SCANNER_PATTERNS = {
  // Request patterns
  highFrequency: { threshold: 50, window: 5 * 60 * 1000 }, // 50 requests in 5 minutes
  endpointVariety: { threshold: 20, window: 5 * 60 * 1000 }, // 20 different endpoints
  userAgentVariety: { threshold: 5, window: 5 * 60 * 1000 }, // 5 different user agents
  
  // Suspicious endpoint patterns
  adminEndpoints: [/\/admin\//i, /\/config\//i, /\/backup\//i, /\/debug\//i],
  sensitiveFiles: [/\/\.env/i, /\/config\//i, /\/secret/i, /\/key/i],
  databaseEndpoints: [/\/db\//i, /\/sql/i, /\/query/i, /\/database/i],
  
  // Header patterns
  suspiciousHeaders: [
    'x-scanner', 'x-vulnerability-scan', 'x-security-test',
    'x-automation', 'x-penetration-test', 'x-crawler'
  ],
  
  // User-Agent patterns (beyond basic)
  automatedTools: [
    /python-requests/i, /axios/i, /node-fetch/i, /httpie/i,
    /postman/i, /insomnia/i, /rest-assured/i, /restsharp/i
  ],
  
  // Timing patterns
  rapidRequests: { interval: 100, count: 5 }, // 5 requests in 100ms
  consistentTiming: { variance: 50, count: 10 } // 10 requests with <50ms variance
}

// Geolocation analysis
interface GeolocationData {
  ip: string
  country: string
  city: string
  timestamp: number
}

const geoHistory = new Map<string, GeolocationData[]>()

// Threat intelligence
const knownMaliciousIPs = new Set<string>()
const knownScanners = new Set<string>()

// Initialize threat intelligence
async function initializeThreatIntelligence() {
  try {
    // Load known malicious IPs from database
    const { data } = await supabase
      .from('threat_intelligence')
      .select('ip_address, threat_type')
      .eq('active', true)
    
    data?.forEach(item => {
      if (item.threat_type === 'malicious') {
        knownMaliciousIPs.add(item.ip_address)
      } else if (item.threat_type === 'scanner') {
        knownScanners.add(item.ip_address)
      }
    })
  } catch (error) {
    console.error('Failed to load threat intelligence:', error)
  }
}

// Enhanced IP geolocation lookup
async function getGeolocation(ip: string): Promise<{ country: string; city: string } | null> {
  try {
    // Use a free geolocation API or database
    const response = await fetch(`http://ip-api.com/json/${ip}`)
    const data = await response.json()
    
    if (data.status === 'success') {
      return {
        country: data.country,
        city: data.city
      }
    }
    return null
  } catch (error) {
    console.error('Geolocation lookup failed:', error)
    return null
  }
}

// Impossible travel detection
function detectImpossibleTravel(ip: string, currentGeo: { country: string; city: string }): boolean {
  const history = geoHistory.get(ip)
  if (!history || history.length === 0) return false
  
  const lastLocation = history[history.length - 1]
  const now = Date.now()
  const timeDiff = now - lastLocation.timestamp
  
  // If locations are different and time is less than 1 hour, it's impossible travel
  if (
    (lastLocation.country !== currentGeo.country || lastLocation.city !== currentGeo.city) &&
    timeDiff < (60 * 60 * 1000) // 1 hour
  ) {
    return true
  }
  
  return false
}

// Update geolocation history
function updateGeoHistory(ip: string, geo: { country: string; city: string }) {
  const history = geoHistory.get(ip) || []
  history.push({
    ip,
    country: geo.country,
    city: geo.city,
    timestamp: Date.now()
  })
  
  // Keep only last 24 hours of data
  const cutoff = Date.now() - (24 * 60 * 60 * 1000)
  geoHistory.set(ip, history.filter(entry => entry.timestamp > cutoff))
}

// Behavioral analysis
function analyzeBehavioralPatterns(history: RequestHistory): {
  riskScore: number
  reasons: string[]
  isAutomated: boolean
  isScanner: boolean
} {
  const reasons: string[] = []
  let riskScore = 0
  
  // High frequency requests
  if (history.requests.length > ADVANCED_SCANNER_PATTERNS.highFrequency.threshold) {
    riskScore += 30
    reasons.push(`High frequency: ${history.requests.length} requests`)
  }
  
  // Endpoint variety
  if (history.uniqueEndpoints.size > ADVANCED_SCANNER_PATTERNS.endpointVariety.threshold) {
    riskScore += 25
    reasons.push(`High endpoint variety: ${history.uniqueEndpoints.size} endpoints`)
  }
  
  // User agent variety
  if (history.uniqueUserAgents.size > ADVANCED_SCANNER_PATTERNS.userAgentVariety.threshold) {
    riskScore += 20
    reasons.push(`Multiple user agents: ${history.uniqueUserAgents.size} agents`)
  }
  
  // Check for automated tool patterns
  const automatedUA = Array.from(history.uniqueUserAgents).some(ua => 
    ADVANCED_SCANNER_PATTERNS.automatedTools.some(pattern => pattern.test(ua))
  )
  
  if (automatedUA) {
    riskScore += 35
    reasons.push('Automated tool detected')
  }
  
  // Check for suspicious endpoints
  const suspiciousEndpoints = history.requests.filter(req => 
    ADVANCED_SCANNER_PATTERNS.adminEndpoints.some(pattern => pattern.test(req.endpoint)) ||
    ADVANCED_SCANNER_PATTERNS.sensitiveFiles.some(pattern => pattern.test(req.endpoint))
  )
  
  if (suspiciousEndpoints.length > 0) {
    riskScore += 40
    reasons.push(`Accessing ${suspiciousEndpoints.length} suspicious endpoints`)
  }
  
  // Timing analysis
  const timestamps = history.requests.map(req => req.timestamp).sort()
  let rapidCount = 0
  
  for (let i = 1; i < timestamps.length; i++) {
    if (timestamps[i] - timestamps[i-1] < ADVANCED_SCANNER_PATTERNS.rapidRequests.interval) {
      rapidCount++
    }
  }
  
  if (rapidCount >= ADVANCED_SCANNER_PATTERNS.rapidRequests.count) {
    riskScore += 30
    reasons.push('Rapid request pattern detected')
  }
  
  const isAutomated = riskScore > 50 || automatedUA
  const isScanner = riskScore > 70 || suspiciousEndpoints.length > 0
  
  return { riskScore, reasons, isAutomated, isScanner }
}

// Main behavioral detection function
export async function detectBehavioralThreats(request: NextRequest): Promise<{
  isThreat: boolean
  riskScore: number
  threatType: string
  reasons: string[]
  shouldBlock: boolean
}> {
  const ip = request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() || 'unknown'
  const userAgent = request.headers.get('user-agent') || 'unknown'
  const endpoint = new URL(request.url).pathname
  const method = request.method || 'GET'
  
  // Initialize threat intelligence
  if (knownMaliciousIPs.size === 0) {
    await initializeThreatIntelligence()
  }
  
  // Check against known threats
  if (knownMaliciousIPs.has(ip)) {
    return {
      isThreat: true,
      riskScore: 100,
      threatType: 'known_malicious_ip',
      reasons: ['IP is in threat intelligence database'],
      shouldBlock: true
    }
  }
  
  if (knownScanners.has(ip)) {
    return {
      isThreat: true,
      riskScore: 80,
      threatType: 'known_scanner_ip',
      reasons: ['IP is known scanner'],
      shouldBlock: true
    }
  }
  
  // Update request history
  const history = requestHistory.get(ip) || {
    ip,
    requests: [],
    uniqueEndpoints: new Set(),
    uniqueUserAgents: new Set(),
    timeWindow: 5 * 60 * 1000,
    lastActivity: Date.now()
  }
  
  // Add current request
  const headers: Record<string, string> = {}
  request.headers.forEach((value, key) => {
    headers[key] = value
  })
  
  history.requests.push({
    timestamp: Date.now(),
    endpoint,
    method,
    userAgent,
    headers
  })
  
  history.uniqueEndpoints.add(endpoint)
  history.uniqueUserAgents.add(userAgent)
  history.lastActivity = Date.now()
  
  // Clean old requests
  const cutoff = Date.now() - history.timeWindow
  history.requests = history.requests.filter(req => req.timestamp > cutoff)
  
  requestHistory.set(ip, history)
  
  // Behavioral analysis
  const analysis = analyzeBehavioralPatterns(history)
  
  // Geolocation analysis
  const geo = await getGeolocation(ip)
  if (geo) {
    const impossibleTravel = detectImpossibleTravel(ip, geo)
    if (impossibleTravel) {
      analysis.riskScore += 50
      analysis.reasons.push('Impossible travel detected')
    }
    updateGeoHistory(ip, geo)
  }
  
  // Check for suspicious headers
  const suspiciousHeaders = ADVANCED_SCANNER_PATTERNS.suspiciousHeaders.filter(header =>
    request.headers.get(header)
  )
  
  if (suspiciousHeaders.length > 0) {
    analysis.riskScore += 25
    analysis.reasons.push(`Suspicious headers: ${suspiciousHeaders.join(', ')}`)
  }
  
  // Determine threat level
  const isThreat = analysis.riskScore > 60
  const shouldBlock = analysis.riskScore > 80
  let threatType = 'behavioral_anomaly'
  
  if (analysis.isScanner) {
    threatType = 'automated_scanner'
  } else if (analysis.isAutomated) {
    threatType = 'automated_tool'
  } else if (analysis.riskScore > 80) {
    threatType = 'high_risk_behavior'
  } else if (analysis.riskScore > 60) {
    threatType = 'suspicious_behavior'
  }
  
  return {
    isThreat,
    riskScore: analysis.riskScore,
    threatType,
    reasons: analysis.reasons,
    shouldBlock
  }
}

// Clean up old data
setInterval(() => {
  const now = Date.now()
  const cutoff = now - (24 * 60 * 60 * 1000) // 24 hours
  
  // Clean request history
  for (const [ip, history] of requestHistory.entries()) {
    if (history.lastActivity < cutoff) {
      requestHistory.delete(ip)
    }
  }
  
  // Clean geo history
  for (const [ip, history] of geoHistory.entries()) {
    const filtered = history.filter(entry => entry.timestamp > cutoff)
    if (filtered.length === 0) {
      geoHistory.delete(ip)
    } else {
      geoHistory.set(ip, filtered)
    }
  }
}, 60 * 60 * 1000) // Run every hour
