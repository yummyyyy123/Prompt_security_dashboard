import { NextRequest, NextResponse } from 'next/server'
import { withAdminAuth } from '../../../../lib/admin-auth'
import { SecurityLogger } from '../../../../lib/security-logger'

async function handler(request: NextRequest) {
    try {
        const ip = request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() ||
                  request.headers.get('x-real-ip') ||
                  'unknown'
        const userAgent = request.headers.get('user-agent') || 'unknown'

        // Log file manipulation attempt
        await SecurityLogger.logFileManipulation(
            ip,
            userAgent,
            'POST',
            '/api/admin/security/test-upload',
            {
                reason: 'test_file_upload',
                content_type: request.headers.get('content-type'),
                file_size: request.headers.get('content-length'),
                test_mode: true
            }
        )

        return NextResponse.json({
            success: true,
            message: 'File upload test completed',
            timestamp: new Date().toISOString()
        })

    } catch (error: any) {
        console.error('❌ File upload test error:', error)
        
        return NextResponse.json({
            success: false,
            error: 'File upload test failed',
            details: error.message,
            timestamp: new Date().toISOString()
        }, { status: 500 })
    }
}

export const POST = withAdminAuth(handler)

// Only allow POST requests
export async function GET() {
    return NextResponse.json(
        { error: 'Method not allowed' },
        { status: 405 }
    )
}
