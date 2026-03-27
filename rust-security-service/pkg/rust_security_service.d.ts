/* tslint:disable */
/* eslint-disable */

export class RateLimiter {
    free(): void;
    [Symbol.dispose](): void;
    /**
     * Returns true if BLOCKED
     */
    check_rate_limit(ip: string, now_ms: number): boolean;
    constructor();
}

export class SecurityResult {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    success: boolean;
    readonly data: any | undefined;
    readonly error: string | undefined;
}

export function validate_and_sanitize_event(event_json: string): any;

export function verify_internal_token(provided: string, expected: string): boolean;

export function verify_supabase_webhook(secret: string, signature_header: string, body: string, now_ts_sec: bigint, event_ts_sec: bigint): boolean;
