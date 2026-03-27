import { NextRequest, NextResponse } from 'next/server'
import { withAdminAuth } from '../../../../../lib/admin-auth'
import { supabase } from '../../../../../lib/supabase'

export const GET = withAdminAuth(async (request: NextRequest) => {
  try {
    const { searchParams } = new URL(request.url)
    
    // Parse pagination parameters
    const page = parseInt(searchParams.get('page') || '1')
    const limit = parseInt(searchParams.get('limit') || '50')
    const offset = (page - 1) * limit
    
    // Validate parameters
    if (page < 1 || limit < 1 || limit > 100) {
      return NextResponse.json(
        { error: 'Invalid pagination parameters' },
        { status: 400 }
      )
    }

    // Parse filters
    const severity = searchParams.get('severity')
    const ipFilter = searchParams.get('ip')
    const eventType = searchParams.get('event_type')
    const startDate = searchParams.get('start_date')
    const endDate = searchParams.get('end_date')

    // Build query
    let query = supabase
      .from('security_logs')
      .select('id, ip_address, event_type, severity, details, created_at, acknowledged_at, acknowledged_by')
      .order('created_at', { ascending: false })
      .range(offset, limit)

    // Apply filters
    if (severity) {
      query = query.eq('severity', severity)
    }
    if (ipFilter) {
      query = query.eq('ip_address', ipFilter)
    }
    if (eventType) {
      query = query.eq('event_type', eventType)
    }
    if (startDate) {
      query = query.gte('created_at', startDate)
    }
    if (endDate) {
      query = query.lte('created_at', endDate)
    }

    const { data, error, count } = await query

    if (error) {
      return NextResponse.json(
        { error: 'Failed to fetch security logs' },
        { status: 500 }
      )
    }

    // Get total count for pagination
    let countQuery = supabase
      .from('security_logs')
      .select('*', { count: 'exact', head: true })

    if (severity) {
      countQuery = countQuery.eq('severity', severity)
    }
    if (ipFilter) {
      countQuery = countQuery.eq('ip_address', ipFilter)
    }
    if (eventType) {
      countQuery = countQuery.eq('event_type', eventType)
    }
    if (startDate) {
      countQuery = countQuery.gte('created_at', startDate)
    }
    if (endDate) {
      countQuery = countQuery.lte('created_at', endDate)
    }

    const { count: totalCount } = await countQuery

    return NextResponse.json({
      logs: data || [],
      pagination: {
        page,
        limit,
        offset,
        total: totalCount || 0,
        totalPages: Math.ceil((totalCount || 0) / limit)
      },
      filters: {
        severity,
        ip: ipFilter,
        event_type: eventType,
        start_date: startDate,
        end_date: endDate
      }
    })

  } catch (error) {
    console.error('Error fetching security logs:', error)
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    )
  }
})
