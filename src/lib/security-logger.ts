import { createClient } from '@supabase/supabase-js'

let supabase: any = null

function getSupabase() {
    if (supabase) return supabase

    const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL
    const supabaseKey = process.env.SUPABASE_SERVICE_KEY || process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY

    if (!supabaseUrl || !supabaseKey) {
        console.warn('⚠️  Supabase environment variables missing in SecurityLogger');
        return null
    }

    try {
        supabase = createClient(supabaseUrl, supabaseKey)
        return supabase
    } catch (e) {
        console.error('Failed to init Supabase in SecurityLogger:', e)
        return null
    }
}

export type SecurityEventType =
    | 'vulnerability_scan'     // High-confidence scanner (Nikto, sqlmap)
    | 'recon_probe'            // Probing honeypot paths (/.env)
    | 'honeypot'               // Explicit hit on a honeypot path
    | 'exploit_attempt'        // WAF payload match (SQLi, XSS)
    | 'suspicious_request'     // Score 6-8 signal cluster
    | 'api_access_monitored'   // Score 3-5 signal cluster
    | 'login_failure'
    | 'login_success'
    | 'mfa_requested'
    | 'mfa_verify_failure'
    | 'mfa_verify_success'
    | 'mfa_bypass_attempt'
    | 'rate_limit_triggered'
    | 'unauthorized_access'
    | 'unauthorized_api_access'
    | 'file_manipulation_attempt'
    | 'suspicious_curl_request'
    | 'file_access_denied'
    | 'rate_limit_anonymous'
    | 'direct_database_access'
    | 'security_log_access'
    | 'database_deletion'
    | 'database_modification'
    | 'database_insertion'
    | 'vulnerability_scan_detected'
    | 'waf_attack_detected'
    | 'bruteforce_detected'
    | 'challenge_gate_blocked'
    | 'ip_auto_banned'
    | 'validation_error'
    | 'replay_attack_detected'

export interface SecurityEventOptions {
    eventType: SecurityEventType
    severity?: 'info' | 'warning' | 'critical' | 'high'
    ip?: string
    userAgent?: string
    details?: Record<string, any>
    requestMethod?: string
    endpointPath?: string
    requestSize?: number
    responseStatus?: number
}

type SecurityLogClass = 'noise' | 'threat'

const SENSITIVE_PATTERNS = [
    /password/i, /username/i, /credential/i, /token/i, /secret/i,
    /auth/i, /key/i, /private/i, /confidential/i, /ssn/i,
    /credit_card/i, /bank_account/i, /admin/i, /login/i,
    /session/i, /jwt/i, /bearer/i, /hash/i, /salt/i
];

const SENSITIVE_FIELDS = [
    'password', 'username', 'email', 'token', 'secret', 'key',
    'auth', 'private', 'confidential', 'credential', 'admin',
    'login', 'session', 'jwt', 'bearer', 'hash', 'salt',
    'ssn', 'credit_card', 'bank_account', 'api_key', 'access_token'
];

function sanitizeData(data: any, depth: number = 0): any {
    if (depth > 10) return '[MAX_DEPTH_REACHED]';
    if (data === null || data === undefined) return data;
    if (typeof data === 'string') {
        const lowerStr = data.toLowerCase();
        if (SENSITIVE_PATTERNS.some(pattern => pattern.test(lowerStr))) {
            return '[REDACTED_SENSITIVE_STRING]';
        }
        if (lowerStr.startsWith('eyj') && lowerStr.includes('.')) {
            return '[REDACTED_TOKEN]';
        }
        return data;
    }
    if (typeof data === 'object') {
        if (Array.isArray(data)) {
            return data.map(item => sanitizeData(item, depth + 1));
        }
        const sanitized: any = {};
        for (const [key, value] of Object.entries(data)) {
            const lowerKey = key.toLowerCase();
            const isSensitive = SENSITIVE_FIELDS.some(field =>
                lowerKey.includes(field) || lowerKey === field
            );
            if (isSensitive) {
                sanitized[key] = '[REDACTED_SENSITIVE]';
            } else if (typeof value === 'object' && value !== null) {
                sanitized[key] = sanitizeData(value, depth + 1);
            } else {
                sanitized[key] = value;
            }
        }
        return sanitized;
    }
    return data;
}

function sanitizeDetails(details: Record<string, any>): Record<string, any> {
    if (!details) return {};
    const sanitized = sanitizeData(details);
    if (sanitized.username) sanitized.username = '[REDACTED_USER]';
    if (sanitized.password) sanitized.password = '[REDACTED_PASS]';
    if (sanitized.email) {
        const email = sanitized.email as string;
        if (email && email.includes('@')) {
            const [username, domain] = email.split('@');
            const redactedUsername = username.length > 2
                ? username.substring(0, 2) + '*'.repeat(username.length - 2)
                : '*'.repeat(username.length);
            sanitized.email = `${redactedUsername}@${domain}`;
        }
    }
    return sanitized;
}

const discordAlertDedupe = new Map<string, number>()

function shouldSendDiscordAlert(key: string, windowMs: number): boolean {
    const now = Date.now()
    const last = discordAlertDedupe.get(key) || 0
    if (now - last < windowMs) return false
    discordAlertDedupe.set(key, now)
    return true
}

async function sendDiscordSecurityAlert(payload: {
    eventType: string
    severity: string
    ip?: string
    endpointPath?: string
    requestMethod?: string
    details: Record<string, any>
}) {
    const webhookUrl = process.env.SECURITY_ALERT_WEBHOOK
    if (!webhookUrl) return

    const ip = payload.ip || 'unknown'
    const path = payload.endpointPath || 'unknown'
    const method = payload.requestMethod || 'unknown'
    const reason = payload.details?.reason || payload.details?.attack_type || payload.details?.access_denied_reason || ''
    const country = payload.details?.country || ''
    const asn = payload.details?.asn_name || payload.details?.asn_number || ''
    const datacenter = payload.details?.datacenter_likely ? 'yes' : 'no'

    const dedupeKey = `${payload.eventType}:${ip}:${path}:${reason}`
    if (!shouldSendDiscordAlert(dedupeKey, 60_000)) return

    const title = `Security Alert: ${payload.eventType}`
    const descriptionParts = [
        `severity: ${payload.severity}`,
        `ip: ${ip}`,
        `request: ${method} ${path}`,
        reason ? `reason: ${reason}` : null,
        country ? `country: ${country}` : null,
        asn ? `asn: ${asn}` : null,
        `datacenter: ${datacenter}`
    ].filter(Boolean)

    const controller = new AbortController()
    const timeout = setTimeout(() => controller.abort(), 2500)
    try {
        await fetch(webhookUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                embeds: [{
                    title,
                    description: descriptionParts.join('\n').slice(0, 3900)
                }]
            }),
            signal: controller.signal
        })
    } catch (e: any) {
        console.error('Discord security alert failed:', e?.message || e)
    } finally {
        clearTimeout(timeout)
    }
}

export class SecurityLogger {
    static async logEvent(options: SecurityEventOptions) {
        const {
            eventType,
            severity = 'info',
            ip,
            userAgent,
            details = {},
            requestMethod,
            endpointPath,
            requestSize,
            responseStatus
        } = options

        try {
            const client = getSupabase()
            if (!client) return

            const normalizedSeverity = severity === 'high' ? 'critical' : severity
            const logClass: SecurityLogClass =
                details.log_class === 'noise' || details.log_class === 'threat'
                    ? details.log_class
                    : this.classifyEvent(eventType, normalizedSeverity)

            if (normalizedSeverity === 'critical' || process.env.NODE_ENV !== 'production') {
                console.log(`🛡️  Security Event: [${eventType.toUpperCase()}] at ${ip || 'unknown'} (Score: ${details.threat_score || 0})`)
            }

            const sanitizedDetails = sanitizeDetails(details);

            const { error } = await client
                .from('security_logs')
                .insert([{
                    event_type: eventType,
                    severity: normalizedSeverity,
                    ip_address: ip,
                    user_agent: userAgent,
                    details: {
                        ...sanitizedDetails,
                        log_class: logClass,
                        request_method: requestMethod,
                        endpoint_path: endpointPath,
                        request_size: requestSize,
                        response_status: responseStatus
                    }
                }])

            if (error) {
                console.error(`❌ [${eventType.toUpperCase()}] Failed to write to security_logs:`, error.message)
            } else {
                if (process.env.NODE_ENV !== 'production' || normalizedSeverity === 'critical') {
                    console.log(`✅ [${eventType.toUpperCase()}] Security event recorded successfully`);
                }
            }

            if (normalizedSeverity === 'critical') {
                await sendDiscordSecurityAlert({
                    eventType,
                    severity: normalizedSeverity,
                    ip,
                    endpointPath,
                    requestMethod,
                    details: { ...sanitizedDetails, log_class: logClass }
                })
            }
        } catch (err) {
            console.error('❌ SecurityLogger error:', err)
        }
    }

    static classifyEvent(eventType: SecurityEventType, severity: 'info' | 'warning' | 'critical' | 'high'): SecurityLogClass {
        if (severity === 'critical' || severity === 'high') return 'threat'
        if (['api_access_monitored', 'login_success', 'mfa_verify_success'].includes(eventType)) return 'noise'
        return 'threat'
    }

    // --- FUNCTIONAL RATE LIMIT HELPERS (For API routes, NOT Middleware) ---
    
    static async isRateLimited(ip: string): Promise<boolean> {
        try {
            const client = getSupabase()
            if (!client) return false
            const thirtyMinutesAgo = new Date(Date.now() - 30 * 60 * 1000).toISOString()
            const { count, error } = await client
                .from('security_logs')
                .select('*', { count: 'exact', head: true })
                .eq('ip_address', ip)
                .in('event_type', ['login_failure', 'mfa_verify_failure', 'mfa_bypass_attempt'])
                .gt('created_at', thirtyMinutesAgo)
            if (error) return false
            return (count || 0) >= 5
        } catch { return false }
    }

    static async isIdentityRateLimited(identityFp: string, windowMs: number, limit: number): Promise<boolean> {
        try {
            const client = getSupabase()
            if (!client) return false
            const since = new Date(Date.now() - windowMs).toISOString()
            const { count, error } = await client
                .from('security_logs')
                .select('*', { count: 'exact', head: true })
                .eq('details->>identity_fp', identityFp)
                .in('event_type', ['login_failure', 'mfa_verify_failure', 'mfa_bypass_attempt'])
                .gt('created_at', since)
            if (error) return false
            return (count || 0) >= limit
        } catch { return false }
    }

    // --- HELPER LOGGERS (Compatibility) ---

    static async logRateLimit(ip: string, path: string) {
        await this.logEvent({ eventType: 'rate_limit_triggered', severity: 'critical', ip, details: { path } })
    }

    static async logUnauthorized(path: string, ip?: string, userAgent?: string) {
        await this.logEvent({ eventType: 'unauthorized_access', severity: 'warning', ip, userAgent, details: { path } })
    }

    static async logSuspiciousCurl(ip: string, userAgent: string, endpoint: string, method: string, details?: Record<string, any>) {
        await this.logEvent({ eventType: 'suspicious_curl_request', severity: 'warning', ip, userAgent, requestMethod: method, endpointPath: endpoint, details: { detected_pattern: 'curl_user_agent', ...details } })
    }

    static async logFileManipulation(ip: string, userAgent: string, operation: string, endpoint: string, details?: Record<string, any>) {
        await this.logEvent({ eventType: 'file_manipulation_attempt', severity: 'critical', ip, userAgent, requestMethod: operation, endpointPath: endpoint, details: { file_operation: operation, ...details } })
    }

    static async logUnauthorizedApiAccess(ip: string, userAgent: string, endpoint: string, method: string, details?: Record<string, any>) {
        await this.logEvent({ eventType: 'unauthorized_api_access', severity: 'warning', ip, userAgent, requestMethod: method, endpointPath: endpoint, details: { access_denied_reason: 'unauthenticated', ...details } })
    }

    static async logFileAccessDenied(ip: string, userAgent: string, endpoint: string, method: string, details?: Record<string, any>) {
        await this.logEvent({ eventType: 'file_access_denied', severity: 'warning', ip, userAgent, requestMethod: method, endpointPath: endpoint, details: { access_denied_reason: 'file_permission_denied', ...details } })
    }

    static async logAnonymousRateLimit(ip: string, endpoint: string, requestCount: number) {
        await this.logEvent({ eventType: 'rate_limit_anonymous', severity: 'warning', ip, endpointPath: endpoint, details: { request_count: requestCount, limit_exceeded: true } })
    }


    static async getLogs(filter = 'all', limit = 50) {
        try {
            const client = getSupabase()
            if (!client) return { data: [], error: 'Supabase client not initialized' }

            let query = client
                .from('security_logs')
                .select('*')
                .order('created_at', { ascending: false })
                .limit(limit)

            if (filter === 'critical') {
                query = query.eq('severity', 'critical')
            } else if (filter === 'warnings') {
                query = query.eq('severity', 'warning')
            } else if (filter === 'noise') {
                query = query.eq('details->>log_class', 'noise')
            } else if (filter === 'threats') {
                query = query.or('details->>log_class.eq.threat,details->>log_class.is.null')
            }

            const { data, error } = await query
            return { data: data || [], error }
        } catch (err) {
            console.error('❌ SecurityLogger.getLogs crash:', err)
            return { data: [], error: err }
        }
    }
}
