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

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly __wbg_get_securityresult_success: (a: number) => number;
    readonly __wbg_ratelimiter_free: (a: number, b: number) => void;
    readonly __wbg_securityresult_free: (a: number, b: number) => void;
    readonly __wbg_set_securityresult_success: (a: number, b: number) => void;
    readonly ratelimiter_check_rate_limit: (a: number, b: number, c: number, d: number) => number;
    readonly ratelimiter_new: () => number;
    readonly securityresult_data: (a: number) => number;
    readonly securityresult_error: (a: number, b: number) => void;
    readonly validate_and_sanitize_event: (a: number, b: number, c: number) => void;
    readonly verify_internal_token: (a: number, b: number, c: number, d: number) => number;
    readonly verify_supabase_webhook: (a: number, b: number, c: number, d: number, e: number, f: number, g: bigint, h: bigint) => number;
    readonly __wbindgen_export: (a: number, b: number) => number;
    readonly __wbindgen_export2: (a: number, b: number, c: number, d: number) => number;
    readonly __wbindgen_add_to_stack_pointer: (a: number) => number;
    readonly __wbindgen_export3: (a: number, b: number, c: number) => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
