/**
 * Simple XSS sanitation utility
 */
export function sanitizeString(str: string): string {
    if (!str || typeof str !== 'string') return str

    return str
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;')
        .replace(/\//g, '&#x2F;')
}

/**
 * Sanitize an object of strings
 */
export function sanitizeObject<T extends Record<string, any>>(obj: T): T {
    const sanitized = { ...obj }

    for (const key in sanitized) {
        if (typeof sanitized[key] === 'string') {
            sanitized[key] = sanitizeString(sanitized[key]) as any
        } else if (Array.isArray(sanitized[key])) {
            sanitized[key] = sanitized[key].map((item: any) =>
                typeof item === 'string' ? sanitizeString(item) : item
            ) as any
        }
    }

    return sanitized
}
