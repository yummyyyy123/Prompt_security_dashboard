import { NextRequest, NextResponse } from 'next/server'
import { withAdminAuth } from '@/lib/admin-auth'
import { SecurityLogger } from '@/lib/security-logger'

async function handler(request: NextRequest) {
    const { searchParams } = new URL(request.url)
    const filter = searchParams.get('filter') || 'all'
    const limit = parseInt(searchParams.get('limit') || '50')

    try {
        const { data, error } = await SecurityLogger.getLogs(filter, limit)

        if (error) {
            console.error('❌ Error in security logs API:', error)
            return NextResponse.json({ error: 'Failed to fetch security logs' }, { status: 500 })
        }

        // Apply additional filtering for new event types
        let filteredData = data || []
        
        if (filter === 'curl') {
            filteredData = filteredData.filter((log: any) => 
                log.event_type.includes('curl') || log.event_type.includes('suspicious')
            )
        } else if (filter === 'file') {
            filteredData = filteredData.filter((log: any) => 
                log.event_type.includes('file')
            )
        } else if (filter === 'api') {
            filteredData = filteredData.filter((log: any) => 
                log.event_type.includes('api_access') || log.event_type.includes('unauthorized')
            )
        } else if (filter === 'database') {
            filteredData = filteredData.filter((log: any) => 
                log.event_type.includes('database') || 
                log.event_type.includes('security_log') ||
                log.event_type.includes('direct_database_access')
            )
        } else if (filter === 'scanner') {
            filteredData = filteredData.filter((log: any) => 
                log.event_type.includes('vulnerability_scan') ||
                log.event_type.includes('behavioral_scanner') ||
                log.event_type.includes('recon_probe') ||
                log.event_type.includes('exploit_attempt') ||
                log.event_type.includes('suspicious_request') ||
                log.event_type.includes('honeypot')
            )
        } else if (filter === 'threats') {
            filteredData = filteredData.filter((log: any) => log.details?.log_class === 'threat')
        } else if (filter === 'noise') {
            filteredData = filteredData.filter((log: any) => log.details?.log_class === 'noise')
        }

        return NextResponse.json({ logs: filteredData })
    } catch (err) {
        console.error('💥 Security logs API crash:', err)
        return NextResponse.json({ error: 'Internal server error' }, { status: 500 })
    }
}

export const GET = withAdminAuth(handler)
