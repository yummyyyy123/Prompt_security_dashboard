// Test Twilio credentials and SMS sending
import { NextRequest, NextResponse } from 'next/server'

export async function GET(request: NextRequest) {
  try {
    console.log('🔍 Testing Twilio credentials...')

    const accountSid = process.env.TWILIO_ACCOUNT_SID
    const authToken = process.env.TWILIO_AUTH_TOKEN
    const twilioPhone = process.env.TWILIO_PHONE_NUMBER

    const credentials = {
      accountSid: accountSid ? 'SET' : 'NOT SET',
      authToken: authToken ? 'SET' : 'NOT SET',
      twilioPhone: twilioPhone ? 'SET' : 'NOT SET'
    }

    console.log('🔑 Twilio credentials check:', credentials)

    let smsTest = null
    if (accountSid && authToken && twilioPhone) {
      try {
        console.log('📱 Testing SMS send...')
        const twilio = require('twilio')(accountSid, authToken)

        const message = await twilio.messages.create({
          body: 'Test OTP: 123456. This is a test message.',
          from: twilioPhone,
          to: '09948655838' // Test phone number
        })

        smsTest = {
          success: true,
          messageId: message.sid,
          status: message.status
        }
        console.log('✅ Test SMS sent:', smsTest)

      } catch (error: any) {
        smsTest = {
          success: false,
          error: error.message
        }
        console.error('❌ Test SMS failed:', error)
      }
    }

    return NextResponse.json({
      message: 'Twilio test results',
      credentials: credentials,
      smsTest: smsTest,
      timestamp: new Date().toISOString()
    })

  } catch (error: any) {
    console.error('❌ Test endpoint error:', error)
    return NextResponse.json({
      error: error.message,
      timestamp: new Date().toISOString()
    }, { status: 500 })
  }
}

export async function POST(request: NextRequest) {
  try {
    const body = await request.json()
    const { phone } = body

    console.log(`📱 Testing SMS send to ${phone}...`)

    const accountSid = process.env.TWILIO_ACCOUNT_SID
    const authToken = process.env.TWILIO_AUTH_TOKEN
    const twilioPhone = process.env.TWILIO_PHONE_NUMBER

    if (!accountSid || !authToken || !twilioPhone) {
      return NextResponse.json({
        error: 'Twilio not configured',
        credentials: {
          accountSid: !!accountSid,
          authToken: !!authToken,
          twilioPhone: !!twilioPhone
        }
      }, { status: 400 })
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString()
    console.log(`🔍 Test OTP: ${otp}`)

    const twilio = require('twilio')(accountSid, authToken)

    const message = await twilio.messages.create({
      body: `Test OTP: ${otp}. This is a test SMS.`,
      from: twilioPhone,
      to: phone
    })

    return NextResponse.json({
      success: true,
      otp: otp,
      messageId: message.sid,
      status: message.status,
      message: 'Test SMS sent successfully'
    })

  } catch (error: any) {
    console.error('❌ Test SMS error:', error)
    return NextResponse.json({
      error: error.message,
      details: error.code || 'Unknown error'
    }, { status: 500 })
  }
}
