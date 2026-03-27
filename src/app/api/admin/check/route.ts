import { NextRequest, NextResponse } from 'next/server'
import { authenticateAdmin } from '../../../../lib/admin-auth'
import jwt from 'jsonwebtoken'

export async function GET(request: NextRequest) {
  try {
    const auth = authenticateAdmin(request)

    if (!auth.success) {
      return NextResponse.json({
        authenticated: false,
        error: auth.error || 'Unauthorized'
      }, { status: 401 })
    }

    // Get token for decoding user info
    const token = request.cookies.get('admin-token')?.value ||
      request.headers.get('authorization')?.split(' ')[1] || ''

    const JWT_SECRET = process.env.JWT_SECRET ?? ''
    const decoded = jwt.verify(token, JWT_SECRET) as any

    return NextResponse.json({
      authenticated: true,
      user: {
        username: decoded.username,
        role: decoded.role
      }
    })
  } catch (error: any) {
    return NextResponse.json({
      authenticated: false,
      error: 'Invalid session'
    }, { status: 401 })
  }
}

