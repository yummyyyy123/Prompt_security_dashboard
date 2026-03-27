import { NextRequest, NextResponse } from 'next/server'
import { withAdminAuth } from '@/lib/admin-auth'
import { supabase } from '@/lib/supabase'

// POST: Block IP for 1 day (no reason required)
async function handler(request: NextRequest) {
    try {
        const { ip } = await request.json()
        
        if (!ip) {
            return NextResponse.json({ error: 'IP address is required' }, { status: 400 })
        }
        
        // Calculate expiry time (1 day from now)
        const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000)
        
        // Delete any existing block for this IP
        await supabase.from('blocked_ips').delete().eq('ip_address', ip)
        
        // Insert new 1-day block
        const { error } = await supabase.from('blocked_ips').insert({
            ip_address: ip,
            expires_at: expiresAt.toISOString()
        })
        
        if (error) {
            console.error('❌ Failed to block IP:', error)
            return NextResponse.json({ error: 'Failed to block IP' }, { status: 500 })
        }
        
        console.log(`🚫 IP ${ip} blocked for 1 day`)
        
        return NextResponse.json({
            success: true,
            message: `IP ${ip} blocked for 1 day`,
            blockedAt: new Date().toISOString(),
            expiresAt: expiresAt.toISOString()
        })
        
    } catch (error: any) {
        console.error('💥 Block IP API error:', error)
        return NextResponse.json(
            { error: 'Internal server error', details: error.message },
            { status: 500 }
        )
    }
}

// GET: List blocked IPs
async function getBlockedIPs() {
    try {
        const { data, error } = await supabase
            .from('blocked_ips')
            .select('*')
            .gt('expires_at', new Date().toISOString())
            .order('blocked_at', { ascending: false })
        
        if (error) {
            console.error('❌ Failed to fetch blocked IPs:', error)
            return NextResponse.json({ error: 'Failed to fetch blocked IPs' }, { status: 500 })
        }
        
        return NextResponse.json({
            success: true,
            blocked_ips: data || [],
            count: data?.length || 0
        })
        
    } catch (error: any) {
        console.error('💥 Get blocked IPs error:', error)
        return NextResponse.json(
            { error: 'Internal server error', details: error.message },
            { status: 500 }
        )
    }
}

export const POST = withAdminAuth(handler)
export const GET = withAdminAuth(getBlockedIPs)

// Note: No DELETE endpoint - blocks auto-expire after 1 day
