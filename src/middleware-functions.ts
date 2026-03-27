import { createClient } from '@supabase/supabase-js'
import { SecurityLogger, SecurityEventType } from '../lib/security-logger'
import { NextRequest } from 'next/server'

let supabase: any = null

function getSupabase() {
    if (supabase) return supabase
    const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL
    const serviceKey = process.env.SUPABASE_SERVICE_KEY
    const anonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY
    const supabaseKey = serviceKey || anonKey

    if (!supabaseUrl || !supabaseKey) return null
    try {
        supabase = createClient(supabaseUrl, supabaseKey)
        return supabase
    } catch {
        return null
    }
}

export interface SecurityContext {
    signals: Set<string>;
    threatScore: number;
    ip: string;
    userAgent: string;
    path: string;
    method: string;
    requestId: string;
    waitUntil: (promise: Promise<any>) => void;
    headers: Headers;
}

/**
 * Robust path normalization for security context
 */
export function normalizePath(pathname: string): string {
    try {
        const decoded = decodeURIComponent(pathname);
        return decoded
            .replace(/\/+/g, '/') // Collapse multiple slashes
            .replace(/\/+$/, '')  // Trim trailing slash
            .toLowerCase() || '/';
    } catch {
        return pathname.toLowerCase() || '/';
    }
}

/**
 * Trusted IP extraction (Hardened for Vercel)
 */
export function getClientIP(request: NextRequest): string {
    // Priority 1: Vercel Verified Proxy IP
    const vercelIp = request.headers.get('x-vercel-forwarded-for');
    if (vercelIp) return vercelIp;

    // Priority 2: Cloudflare Platform IP
    const cfIp = request.headers.get('cf-connecting-ip');
    if (cfIp) return cfIp;

    // Priority 3: Standard Proxy headers
    const forwarded = request.headers.get('x-forwarded-for');
    if (forwarded) return forwarded.split(',')[0].trim();

    return request.headers.get('x-real-ip') || 'unknown';
}

/**
 * Check if an IP is manually blocked in Supabase
 */
export async function isIPBlocked(ip: string): Promise<boolean> {
    try {
        const client = getSupabase();
        if (!client) return false;

        const { data, error } = await client
            .from('blocked_ips')
            .select('expires_at')
            .eq('ip_address', ip)
            .gt('expires_at', new Date().toISOString())
            .maybeSingle();

        if (error) {
            console.error('🛡️ [BAN_CHECK_ERROR]:', error.message);
            return false;
        }

        return !!data;
    } catch (err) {
        console.error('🛡️ [BAN_CHECK_CRASH]:', err);
        return false;
    }
}

/**
 * Automatically block an IP for a persistent duration (Default: 24h)
 */
export async function autoBanIP(ip: string, durationHours: number = 24): Promise<boolean> {
    try {
        const client = getSupabase();
        if (!client) return false;

        const expiresAt = new Date(Date.now() + durationHours * 60 * 60 * 1000).toISOString();

        // Check if already blocked to avoid redundant inserts
        const { data: existing } = await client
            .from('blocked_ips')
            .select('id')
            .eq('ip_address', ip)
            .gt('expires_at', new Date().toISOString())
            .maybeSingle();

        if (existing) return true;

        const { error } = await client
            .from('blocked_ips')
            .upsert({
                ip_address: ip,
                expires_at: expiresAt
            }, { onConflict: 'ip_address' });

        if (error) {
            console.error('🛡️ [AUTO_BAN_ERROR]:', error.message);
            return false;
        }

        return true;
    } catch (err) {
        console.error('🛡️ [AUTO_BAN_CRASH]:', err);
        return false;
    }
}

/**
 * Signal Collection with Advanced Fingerprinting
 */
export function collectSignals(ctx: SecurityContext, searchParams: string) {
    const ua = ctx.userAgent.toLowerCase();
    const path = ctx.path;

    // 1. Scanner Fingerprinting (UA & NSE Signatures)
    const scanners = [
        { name: 'nmap', score: 5, patterns: [/nmap/i, /Mozilla\/5\.0 \(compatible; Nmap Scripting Engine/i] },
        { name: 'nikto', score: 6, patterns: [/nikto/i, /\(Nikto\//i] },
        { name: 'sqlmap', score: 6, patterns: [/sqlmap/i] },
        { name: 'burp', score: 5, patterns: [/burp/i, /BurpSuite/i] },
        { name: 'zap', score: 5, patterns: [/owasp-zap/i, /ZAP\//i] },
        { name: 'masscan', score: 6, patterns: [/masscan/i] },
        { name: 'nuclei', score: 6, patterns: [/nuclei/i] },
        { name: 'acunetix', score: 6, patterns: [/acunetix/i] },
        { name: 'metasploit', score: 6, patterns: [/metasploit/i, /msf-test/i] }
    ];

    for (const scanner of scanners) {
        if (scanner.patterns.some(p => p.test(ua))) {
            ctx.signals.add(`scanner_${scanner.name}`);
            ctx.threatScore += scanner.score;
        }
    }

    // 2. Behavioral Nmap/NSE Markers
    if (ctx.headers.has('x-nmap-id') || ctx.headers.has('x-nmap-script')) {
        ctx.signals.add('nse_explicit_header');
        ctx.threatScore += 6;
    }
    
    // Nmap default behavior: often lacks 'Accept' or has very unique 'Accept'/'Connection' combos
    const hasAccept = ctx.headers.has('accept');
    if (!hasAccept && ctx.threatScore >= 4) {
        ctx.signals.add('suspicious_header_profile');
        ctx.threatScore += 2;
    }

    // 3. Honeypot Path Detection
    const honeypots = [
        { name: 'env', score: 9, patterns: [/^\/\.env/i, /\.env\./i] },
        { name: 'git', score: 9, patterns: [/^\/\.git/i] },
        { name: 'admin_panel', score: 6, patterns: [/\/wp-admin/i, /\/phpmyadmin/i, /\/administrator/i, /\/admin\.php/i] },
        { name: 'config', score: 6, patterns: [/\/config\.php/i, /\/settings\.py/i, /\/web\.config/i] },
        { name: 'system_files', score: 9, patterns: [/\/etc\/passwd/i, /\/id_rsa/i, /\/boot\.ini/i] }
    ];

    for (const hp of honeypots) {
        if (hp.patterns.some(p => p.test(path))) {
            ctx.signals.add(`honeypot_${hp.name}`);
            ctx.threatScore += hp.score;
        }
    }

    // 4. WAF Payload Detection (Hardened Regex)
    const wafChecks = [
        { name: 'sqli', score: 5, patterns: [/union\s+select/i, /sleep\(/i, /information_schema/i, /benchmark\(/i] },
        { name: 'xss', score: 4, patterns: [/<script/i, /onerror=/i, /javascript:/i, /onload=/i] },
        { name: 'cmd', score: 5, patterns: [/;\s*cat\s+/i, /\|\s*curl\s+/i, /&&\s*wget\s+/i, /;\s*id\s+/i] },
        { name: 'traversal', score: 5, patterns: [/\.\.\//i, /%2e%2e\//i] }
    ];

    const target = `${path}?${searchParams}`.toLowerCase();
    for (const check of wafChecks) {
        if (check.patterns.some(p => p.test(target))) {
            ctx.signals.add(`waf_${check.name}`);
            ctx.threatScore += check.score;
        }
    }

    // 5. Stealth Reconnaissance & Bypass Headers
    const stealthProbes = [
        { name: 'nikto_bypass', score: 4, patterns: [/x-nikto-ignore/i] },
        { name: 'recon_paths', score: 2, patterns: [/\/.aws\//i, /\/.ssh\//i, /\/\.well-known\/.*config/i] },
        { name: 'benign_recon_paths', score: 1, patterns: [/\/\.well-known\//i, /\/robots\.txt/i, /\/sitemap\.xml/i] },
        { name: 'scanner_tool_headers', score: 4, patterns: [/x-scanner/i, /x-vulnerability-scanner/i] }
    ];

    for (const probe of stealthProbes) {
        if (probe.patterns.some(p => p.test(target)) || probe.patterns.some(p => p.test(ua))) {
            ctx.signals.add(`stealth_${probe.name}`);
            ctx.threatScore += probe.score;
        }
    }

    // 6. Browser Metadata Consistency
    const isLikelyBrowser = !!(
        ctx.headers.get('sec-fetch-mode') ||
        ctx.headers.get('sec-ch-ua') ||
        ctx.headers.get('sec-fetch-site')
    );
    
    // FALSE POSITIVE MITIGATION
    if (!isLikelyBrowser) {
        const tools = ['curl', 'httpie', 'postman', 'insomnia', 'python', 'axios', 'node-fetch'];
        if (tools.some(t => ua.includes(t))) {
            ctx.signals.add('tool_request');
            // Tool usage alone is 0, but combined with others it adds a 'non-browser' multiplier
            if (ctx.threatScore > 0) ctx.threatScore += 1;
        } else {
            ctx.signals.add('missing_browser_headers');
            ctx.threatScore += 1;
        }
    }

    // 6. Behavioral: Multiple Signal Multiplier (Scanners often hit multiple triggers)
    if (ctx.signals.size >= 2) {
        ctx.signals.add('aggressive_probing_pattern');
        ctx.threatScore += (ctx.signals.size * 2); // Exponential boost for multi-signal hits
    }

    // 7. Whitelisting (Health Checks / Internal)
    const whiteListUAs = ['uptime', 'vercel-health', 'status-check', 'healthcheck', 'googlebot', 'bingbot'];
    if (whiteListUAs.some(h => ua.includes(h)) && ctx.threatScore < 9) {
        ctx.threatScore = 0; 
        ctx.signals.add('whitelisted_agent');
    }
}

/**
 * Targetted Triage Logging
 */
export function triggerSecurityLog(ctx: SecurityContext, additional: Record<string, any> = {}) {
    if (ctx.threatScore < 3) return;

    // Taxonomy Classification
    let eventType: SecurityEventType = 'api_access_monitored';
    if (ctx.threatScore >= 9) {
        eventType = 'vulnerability_scan';
    } else if (ctx.signals.has('honeypot_env') || ctx.signals.has('honeypot_git') || ctx.signals.has('honeypot_admin_panel')) {
        eventType = 'honeypot';
    } else if (ctx.signals.has('waf_sqli') || ctx.signals.has('waf_cmd')) {
        eventType = 'exploit_attempt';
    } else if (ctx.threatScore >= 6) {
        eventType = 'suspicious_request';
    }

    const isCritical = ctx.threatScore >= 9 || ctx.signals.has('honeypot_env') || ctx.signals.has('honeypot_git') || ctx.signals.has('honeypot_system_files');
    const severity = isCritical ? 'critical' : ctx.threatScore >= 6 ? 'warning' : 'info';

    const logPromise = SecurityLogger.logEvent({
        eventType,
        severity,
        ip: ctx.ip,
        userAgent: ctx.userAgent,
        requestMethod: ctx.method,
        endpointPath: ctx.path,
        details: {
            ...additional,
            signals: Array.from(ctx.signals),
            threat_score: ctx.threatScore,
            request_id: ctx.requestId,
            triage_tier: eventType
        }
    }).catch(err => {
        console.error(`🛡️ [SECURITY_LOG_FAIL] [${ctx.requestId}]:`, err);
    });

    // --- AUTO-BAN ENFORCEMENT ---
    const isHoneypotHit = Array.from(ctx.signals).some(s => s.startsWith('honeypot_'));
    if (ctx.threatScore >= 9 || isHoneypotHit) {
        const banPromise = autoBanIP(ctx.ip).then((success: boolean) => {
            if (success) {
                return SecurityLogger.logEvent({
                    eventType: 'ip_auto_banned' as any,
                    severity: 'critical',
                    ip: ctx.ip,
                    userAgent: ctx.userAgent,
                    details: { 
                        reason: 'threat_score_threshold_met', 
                        score: ctx.threatScore,
                        requestId: ctx.requestId 
                    }
                });
            }
        }).catch((err: any) => {
            console.error(`🛡️ [AUTO_BAN_TRIAGE_FAIL]:`, err);
        });

        if (ctx.waitUntil) {
            ctx.waitUntil(banPromise);
        }
    }

    if (ctx.waitUntil) {
        ctx.waitUntil(logPromise);
    }
}

// --- LEGACY COMPATIBILITY WRAPPERS (Deprecated) ---

export function detectVulnerabilityScanner(userAgent: string, pathname: string): boolean {
    const ctx = createSimpleCtx(userAgent, pathname);
    collectSignals(ctx, '');
    return ctx.threatScore >= 5;
}

export function identifyScannerType(userAgent: string): string {
    const scanners = [
        { name: 'Nmap', patterns: [/nmap/i] },
        { name: 'Nikto', patterns: [/nikto/i] },
        { name: 'sqlmap', patterns: [/sqlmap/i] },
        { name: 'Burp Suite', patterns: [/burp/i] },
        { name: 'OWASP ZAP', patterns: [/zap/i] }
    ];
    for (const s of scanners) {
        if (s.patterns.some(p => p.test(userAgent))) return s.name;
    }
    return 'Unknown Scanner';
}

export function detectWafAttack(pathname: string, search: string, headers: Record<string, string | null>) {
    const ctx = createSimpleCtx(headers['user-agent'] || 'unknown', pathname);
    collectSignals(ctx, search);
    if (ctx.signals.size > 0) {
        const firstSignal = Array.from(ctx.signals)[0];
        return { 
            attack_type: firstSignal, 
            match: 'regex_match', 
            score: ctx.threatScore 
        };
    }
    return null;
}

export function logSecurityEventWithLimit() {}

function createSimpleCtx(ua: string, path: string): SecurityContext {
    return {
        signals: new Set(),
        threatScore: 0,
        ip: 'unknown',
        userAgent: ua,
        path: normalizePath(path),
        method: 'GET',
        requestId: 'legacy',
        waitUntil: () => {},
        headers: new Headers({ 'user-agent': ua })
    };
}
