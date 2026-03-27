import { NextRequest, NextResponse } from 'next/server'
import { withAdminAuth } from '@/lib/admin-auth'

async function handler(request: NextRequest) {
    try {
        const { ip: targetIP } = await request.json()
        
        if (targetIP) {
            // Clear rate limits for specific IP
            console.log(`🧹 Clearing rate limits for IP: ${targetIP}`)
            // Call the global function to clear in-memory cache
            if (typeof (globalThis as any).clearSecurityRateLimits === 'function') {
                (globalThis as any).clearSecurityRateLimits(targetIP);
            }
        } else {
            // Clear all rate limits
            console.log('🧹 Clearing all rate limits')
            // Call the global function to clear all in-memory cache
            if (typeof (globalThis as any).clearSecurityRateLimits === 'function') {
                (globalThis as any).clearSecurityRateLimits();
            }
        }
        
        return NextResponse.json({
            success: true,
            message: targetIP 
                ? `Rate limits cleared for IP: ${targetIP}` 
                : 'All rate limits cleared',
            clearedAt: new Date().toISOString()
        })
        
    } catch (error: any) {
        console.error('💥 Clear rate limit API error:', error)
        return NextResponse.json(
            { error: 'Internal server error', details: error.message },
            { status: 500 }
        )
    }
}

export const POST = withAdminAuth(handler)

// Get current rate limit status
async function getStatus() {
    try {
        return NextResponse.json({
            message: 'Rate limit status endpoint',
            note: 'Rate limits are stored in-memory and cleared via POST endpoint',
            timestamp: new Date().toISOString()
        })
    } catch (error: any) {
        console.error('💥 Rate limit status error:', error)
        return NextResponse.json(
            { error: 'Failed to get status', details: error.message },
            { status: 500 }
        )
    }
}

export const GET = withAdminAuth(getStatus)
