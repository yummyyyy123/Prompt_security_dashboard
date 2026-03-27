import { NextRequest, NextResponse } from 'next/server'
import { withAdminAuth } from '../../../../lib/admin-auth'

export const POST = withAdminAuth(async (request: NextRequest) => {
  try {
    const body = await request.json()
    
    console.log('🧪 TEST: Full request body:', JSON.stringify(body, null, 2))
    console.log('🧪 TEST: Request headers:', JSON.stringify(Object.fromEntries(request.headers.entries()), null, 2))
    
    return NextResponse.json({
      message: 'Request received successfully',
      received: {
        body: body,
        bodyKeys: Object.keys(body),
        contentType: request.headers.get('content-type'),
        userAgent: request.headers.get('user-agent'),
        timestamp: new Date().toISOString()
      }
    })

  } catch (error) {
    console.error('🧪 TEST: Error parsing request:', error)
    return NextResponse.json(
      { error: 'Failed to parse request', details: error instanceof Error ? error.message : String(error) },
      { status: 400 }
    )
  }
})

// GET endpoint for testing
export const GET = withAdminAuth(async (request: NextRequest) => {
  return NextResponse.json({
    message: 'Test endpoint working',
    expectedFormat: {
      post: {
        description: 'Send a POST request to this endpoint',
        body: {
          ipAddress: '192.168.1.1',
          notes: 'Test acknowledgment'
        },
        headers: {
          'Content-Type': 'application/json',
          'Authorization': 'Bearer YOUR_JWT_TOKEN'
        }
      }
    },
    examples: [
      { field: 'ipAddress', value: '192.168.1.1' },
      { field: 'ip', value: '192.168.1.1' },
      { field: 'ip_address', value: '192.168.1.1' },
      { field: 'targetIp', value: '192.168.1.1' },
      { field: 'address', value: '192.168.1.1' }
    ],
    timestamp: new Date().toISOString()
  })
})
