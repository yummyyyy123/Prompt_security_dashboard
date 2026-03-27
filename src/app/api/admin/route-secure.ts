import { NextRequest, NextResponse } from 'next/server'
import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'

const JWT_SECRET = process.env.JWT_SECRET ?? ''
const ADMIN_USERNAME = process.env.ADMIN_USERNAME ?? ''
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD ?? ''

export async function POST(request: NextRequest) {
  try {
    const { username, password } = await request.json()

    // Reject if env vars not configured
    if (!ADMIN_USERNAME || !ADMIN_PASSWORD || !JWT_SECRET) {
      return NextResponse.json({ error: 'Server misconfiguration' }, { status: 500 })
    }

    // Validate credentials
    if (username !== ADMIN_USERNAME) {
      return NextResponse.json(
        { error: 'Invalid credentials' },
        { status: 401 }
      )
    }

    // Check password (in production, compare with bcrypt hash)
    const isValidPassword = password === ADMIN_PASSWORD
    // In production: const isValidPassword = await bcrypt.compare(password, ADMIN_PASSWORD)

    if (!isValidPassword) {
      return NextResponse.json(
        { error: 'Invalid credentials' },
        { status: 401 }
      )
    }

    // Generate JWT token
    const token = jwt.sign(
      { username, role: 'admin' },
      JWT_SECRET,
      { expiresIn: '24h' }
    )

    // Set HTTP-only cookie
    const response = NextResponse.json({
      message: 'Login successful',
      user: { username, role: 'admin' }
    })

    response.cookies.set('admin-token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 24 * 60 * 60 // 24 hours
    })

    return response

  } catch (error) {
    console.error('Login error:', error)
    return NextResponse.json(
      { error: 'Login failed' },
      { status: 500 }
    )
  }
}

export async function DELETE(request: NextRequest) {
  try {
    const response = NextResponse.json({
      message: 'Logout successful'
    })

    response.cookies.delete('admin-token')

    return response

  } catch (error) {
    console.error('Logout error:', error)
    return NextResponse.json(
      { error: 'Logout failed' },
      { status: 500 }
    )
  }
}
