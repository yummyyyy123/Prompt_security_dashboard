import { NextRequest, NextResponse } from 'next/server'
import { withAdminAuth } from '../../../../lib/admin-auth'
import { supabase } from '../../../../lib/supabase'

export const POST = withAdminAuth(async (request: NextRequest) => {
  try {
    const { dryRun = false } = await request.json()

    // Run cleanup function
    const { data, error } = await supabase
      .rpc('cleanup_security_logs')

    if (error) {
      console.error('Failed to cleanup security logs:', error)
      return NextResponse.json(
        { error: 'Failed to cleanup security logs' },
        { status: 500 }
      )
    }

    const deletedCount = data || 0

    console.log(`✅ Security log cleanup completed: ${deletedCount} logs deleted`)

    return NextResponse.json({
      message: 'Security log cleanup completed',
      deletedCount,
      timestamp: new Date().toISOString()
    })

  } catch (error) {
    console.error('Error in cleanup logs:', error)
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    )
  }
})

// Get cleanup statistics with pagination
export const GET = withAdminAuth(async (request: NextRequest) => {
  try {
    const { searchParams } = new URL(request.url)
    
    // Parse pagination parameters with validation
    const page = Math.max(1, parseInt(searchParams.get('page') || '1'))
    const limit = Math.min(100, Math.max(1, parseInt(searchParams.get('limit') || '50')))
    const offset = (page - 1) * limit
    
    // Validate parameters
    if (isNaN(page) || isNaN(limit) || limit < 1 || limit > 100) {
      return NextResponse.json(
        { error: 'Invalid pagination parameters' },
        { status: 400 }
      )
    }

    // Get paginated logs with filters
    const { data: allLogs, error: allLogsError } = await supabase
      .from('security_logs')
      .select('id, ip_address, event_type, severity, details, created_at, acknowledged_at, acknowledged_by')
      .order('created_at', { ascending: false })
      .range(offset, limit)
    
    if (allLogsError) {
      return NextResponse.json(
        { error: 'Failed to fetch security logs' },
        { status: 500 }
      )
    }

    // Get total count with pagination
    const { count: totalLogCount, error: totalError } = await supabase
      .from('security_logs')
      .select('*', { count: 'exact', head: true })
    
    if (totalError) {
      return NextResponse.json(
        { error: 'Failed to get total count' },
        { status: 500 }
      )
    }

    // Get acknowledged IPs count
    const { count: ackCount, error: ackError } = await supabase
      .from('threat_acknowledgments')
      .select('*', { count: 'exact', head: true })
      .gt('expires_at', new Date().toISOString())

    if (ackError) {
      return NextResponse.json(
        { error: 'Failed to get acknowledgment count' },
        { status: 500 }
      )
    }

    return NextResponse.json({
      logs: allLogs || [],
      pagination: {
        page,
        limit,
        offset,
        total: totalLogCount || 0,
        totalPages: Math.ceil((totalLogCount || 0) / limit)
      },
      statistics: {
        totalLogs: totalLogCount || 0,
        acknowledgedIPs: ackCount || 0,
        needsCleanup: (allLogs || []).length > 1000 // Suggest cleanup if >1000 logs
      },
      timestamp: new Date().toISOString()
    })

  } catch (error) {
    console.error('Error getting cleanup statistics:', error)
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    )
  }
})
