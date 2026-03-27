import { NextRequest, NextResponse } from 'next/server'
import { withAdminAuth } from '../../../../lib/admin-auth'
import { SecurityLogger } from '../../../../lib/security-logger'

async function handler(request: NextRequest) {
    try {
        // Test direct database logging by simulating a trigger call
        const testEvent = {
            operation: 'INSERT',
            table: 'test_table',
            user: 'service_role',
            timestamp: new Date().toISOString(),
            request_id: 'test_' + Date.now(),
            old_data: null,
            new_data: {
                id: 'test_123',
                title: 'Test Security Event',
                description: 'This is a test to verify database logging works',
                created_at: new Date().toISOString()
            },
            ip_address: request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() || 'test_ip',
            user_agent: 'Test Database Logger',
            details: {
                test_mode: true,
                triggered_by: 'admin_test_endpoint',
                verification: 'database_logging_test'
            }
        }

        // Log the test event directly using SecurityLogger
        await SecurityLogger.logEvent({
            eventType: 'direct_database_access',
            severity: 'info',
            ip: testEvent.ip_address,
            userAgent: testEvent.user_agent,
            requestMethod: testEvent.operation,
            endpointPath: `/database/${testEvent.table}`,
            details: {
                database_user: testEvent.user,
                table_name: testEvent.table,
                operation: testEvent.operation,
                timestamp: testEvent.timestamp,
                request_id: testEvent.request_id,
                old_data: testEvent.old_data,
                new_data: testEvent.new_data,
                source: 'test_endpoint',
                threat_payload: {
                    operation_type: testEvent.operation,
                    target_table: testEvent.table,
                    data_size: JSON.stringify(testEvent.new_data || {}).length,
                    has_sensitive_data: false,
                    test_mode: true
                },
                ...testEvent.details
            }
        })

        return NextResponse.json({
            success: true,
            message: 'Database logging test completed',
            test_event: testEvent,
            timestamp: new Date().toISOString()
        })

    } catch (error: any) {
        console.error('❌ Database logging test error:', error)
        
        return NextResponse.json({
            success: false,
            error: 'Database logging test failed',
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
