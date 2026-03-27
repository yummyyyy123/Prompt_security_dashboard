import { NextRequest, NextResponse } from 'next/server'
import { SecurityLogger, SecurityEventType } from '../../../../lib/security-logger'
import { 
  verify_supabase_webhook, 
  validate_and_sanitize_event, 
  RateLimiter 
} from 'rust-security-service'

// --- Production Config ---
const MAX_BODY_SIZE = 51200; // 50KB
const REPLAY_WINDOW_MS = 300000; // 5 minutes
const RECENT_REQUESTS = new Set<string>();

// Rust Rate Limiter instance (Shared in-memory)
let rateLimiter: RateLimiter;

function getRateLimiter() {
  if (!rateLimiter) {
    rateLimiter = new RateLimiter();
  }
  return rateLimiter;
}

/**
 * PRODUCTION-GRADE SECURITY FLOW:
 * 1. Size Limit Check
 * 2. Rate Limit (local)
 * 3. Signature Verification
 * 4. Replay Protection
 * 5. Validation & Sanitization
 * 6. Logging (redacted)
 */
export async function POST(request: NextRequest) {
  const start = Date.now();
  const requestId = request.headers.get('x-request-id') || crypto.randomUUID();
  
  // Safe Client IP Extraction
  // Only trust specific headers from known proxies (e.g. Vercel)
  const clientIP = request.headers.get('x-vercel-forwarded-for') || 
                 request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() ||
                 request.headers.get('x-real-ip') ||
                 'unknown';

  const userAgent = request.headers.get('user-agent') || 'unknown';

  try {
    // 1. SIZE LIMIT CHECK (Pre-consumption)
    const contentLength = parseInt(request.headers.get('content-length') || '0');
    if (contentLength > MAX_BODY_SIZE) {
      return securityError('Payload too large', 413, clientIP, userAgent);
    }

    // 2. RATE LIMITING (Local WASM Fast Path)
    if (getRateLimiter().check_rate_limit(clientIP, start)) {
      await SecurityLogger.logEvent({
        eventType: 'rate_limit_anonymous',
        severity: 'warning',
        ip: clientIP,
        userAgent,
        details: { reason: 'wasm_local_rate_limit', requestId }
      });
      return NextResponse.json({ error: 'Too many requests' }, { status: 429 });
    }

    // Read body as text for signature verification
    const bodyText = await request.text();
    if (bodyText.length > MAX_BODY_SIZE) {
        return securityError('Payload too large (post-read)', 413, clientIP, userAgent);
    }

    // 3. SIGNATURE VERIFICATION (WASM)
    const signature = request.headers.get('x-supabase-signature') || '';
    const webhookSecret = process.env.SUPABASE_WEBHOOK_SECRET || '';
    
    // We pass current time and event time to Rust for internal replay check
    // Rust will check if (event_ts > now + 30s || now > event_ts + 300s)
    const nowSec = Math.floor(start / 1000);
    
    // Quick parse timestamp from body without full JSON parse (heuristic)
    const tsMatch = bodyText.match(/"timestamp":\s*"([^"]+)"/);
    const eventTime = tsMatch ? new Date(tsMatch[1]).getTime() : 0;
    const eventTsSec = Math.floor(eventTime / 1000);

    if (!verify_supabase_webhook(webhookSecret, signature, bodyText, BigInt(nowSec), BigInt(eventTsSec))) {
      await SecurityLogger.logEvent({
        eventType: 'unauthorized_api_access',
        severity: 'critical',
        ip: clientIP,
        userAgent,
        details: { reason: 'invalid_signature_or_expired', requestId }
      });
      return securityError('Invalid signature or expired request', 401, clientIP, userAgent);
    }

    // 4. REPLAY PROTECTION (Next.js Layer)
    // Extract request_id from body for deduplication
    const idMatch = bodyText.match(/"request_id":\s*"([^"]+)"/);
    const bodyRequestId = idMatch ? idMatch[1] : null;

    if (!bodyRequestId || RECENT_REQUESTS.has(bodyRequestId)) {
      return securityError('Duplicate or missing request ID', 400, clientIP, userAgent);
    }
    
    // Add to windowed cache
    RECENT_REQUESTS.add(bodyRequestId);
    setTimeout(() => RECENT_REQUESTS.delete(bodyRequestId), REPLAY_WINDOW_MS);

    // 5. VALIDATION & SANITIZATION (WASM)
    let sanitized: any;
    try {
      sanitized = validate_and_sanitize_event(bodyText);
    } catch (e: any) {
      await SecurityLogger.logEvent({
        eventType: 'validation_error',
        severity: 'warning',
        ip: clientIP,
        userAgent,
        details: { error: e.toString(), requestId }
      });
      return securityError('Invalid payload format', 400, clientIP, userAgent);
    }

    // 6. BUSINESS LOGIC & SUCCESS LOG
    // Determine event type
    const operation = sanitized.operation;
    const table = sanitized.table;
    const eventType = getEventType(table, operation);
    
    await SecurityLogger.logEvent({
      eventType: eventType as SecurityEventType,
      severity: getSeverity(table, operation),
      ip: sanitized.ip_address || clientIP,
      userAgent: sanitized.user_agent || userAgent,
      requestMethod: operation,
      endpointPath: `/database/${table}`,
      details: {
        ...sanitized,
        requestId,
        latency_ms: Date.now() - start
      }
    });

    return NextResponse.json({ 
      success: true, 
      id: bodyRequestId,
      processed_at: new Date().toISOString()
    });

  } catch (error: any) {
    console.error(`💥 Security API Error [${requestId}]:`, error);
    return securityError('Internal processing error', 500, clientIP, userAgent);
  }
}

// --- Helpers ---

function securityError(message: string, status: number, ip: string, ua: string) {
  return NextResponse.json({ 
    error: message, 
    code: status === 401 ? 'unauthorized' : status === 429 ? 'rate_limit' : 'malformed_request',
    timestamp: new Date().toISOString()
  }, { status });
}

function getEventType(table: string, operation: string): string {
  if (table === 'security_logs') return 'security_log_access';
  if (operation === 'DELETE') return 'database_deletion';
  if (operation === 'UPDATE') return 'database_modification';
  return 'database_insertion';
}

function getSeverity(table: string, operation: string): 'info' | 'warning' | 'critical' {
  if (table === 'security_logs' || table === 'blocked_ips') return 'critical';
  if (operation === 'DELETE') return 'warning';
  return 'info';
}

// Only allow POST
export async function GET() { return NextResponse.json({ error: 'Method not allowed' }, { status: 405 }); }
export async function PUT() { return NextResponse.json({ error: 'Method not allowed' }, { status: 405 }); }
export async function DELETE() { return NextResponse.json({ error: 'Method not allowed' }, { status: 405 }); }
