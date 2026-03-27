'use client'

import React, { useState } from 'react'
import { motion } from 'framer-motion'
import { Shield, Eye, EyeOff, Lock, User, AlertCircle, Smartphone, ArrowLeft } from 'lucide-react'
import { useRouter } from 'next/navigation'

export default function TwoFactorLogin() {
  const [step, setStep] = useState<'password' | 'otp'>('password')
  const [credentials, setCredentials] = useState({
    username: '',
    password: '',
    phone: '',
    otp: ''
  })
  const [showPassword, setShowPassword] = useState(false)
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState('')
  const [tempToken, setTempToken] = useState('')
  const [phoneLastFour, setPhoneLastFour] = useState('')
  const [resendTimer, setResendTimer] = useState(0)
  const router = useRouter()

  const handlePasswordSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    setIsLoading(true)

    try {
      const response = await fetch('/api/admin/auth/2fa-login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          username: credentials.username,
          password: credentials.password,
          phone: credentials.phone,
          action: 'password'
        })
      })

      const data = await response.json()

      if (response.ok) {
        if (data.requiresOTP) {
          setTempToken(data.tempToken)
          setPhoneLastFour(data.phoneLastFour)
          setStep('otp')
          startResendTimer(data.expiresIn)
        } else {
          router.push('/admin')
        }
      } else {
        setError(data.error || 'Login failed')
      }
    } catch (error) {
      setError('Network error. Please try again.')
    } finally {
      setIsLoading(false)
    }
  }

  const handleOTPVerification = async () => {
    setError('')
    setIsLoading(true)

    try {
      const response = await fetch('/api/admin/auth/2fa-login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          username: credentials.username,
          phone: credentials.phone,
          otp: credentials.otp,
          tempToken,
          action: 'verify-otp'
        })
      })

      const data = await response.json()

      if (response.ok) {
        router.push('/admin')
      } else {
        setError(data.error || 'OTP verification failed')
      }
    } catch (error) {
      setError('Network error. Please try again.')
    } finally {
      setIsLoading(false)
    }
  }

  const handleResendOTP = async () => {
    setError('')
    setIsLoading(true)

    try {
      const response = await fetch('/api/admin/auth/2fa-login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          username: credentials.username,
          password: credentials.password,
          phone: credentials.phone,
          action: 'password'
        })
      })

      const data = await response.json()

      if (response.ok && data.requiresOTP) {
        setTempToken(data.tempToken)
        startResendTimer(data.expiresIn)
        setError('OTP resent successfully')
        setTimeout(() => setError(''), 3000)
      } else {
        setError(data.error || 'Failed to resend OTP')
      }
    } catch (error) {
      setError('Network error. Please try again.')
    } finally {
      setIsLoading(false)
    }
  }

  const startResendTimer = (seconds: number) => {
    setResendTimer(seconds)
    const timer = setInterval(() => {
      setResendTimer((prev) => {
        if (prev <= 1) {
          clearInterval(timer)
          return 0
        }
        return prev - 1
      })
    }, 1000)
  }

  const formatPhoneNumber = (phone: string) => {
    // Format as 09XX XXX XXXX (11 digits)
    if (phone.length === 11) {
      return `${phone.slice(0, 4)} ${phone.slice(4, 7)} ${phone.slice(7)}`
    }
    return phone
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 dark:from-gray-900 dark:to-gray-800 flex items-center justify-center p-4">
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5 }}
        className="w-full max-w-md"
      >
        <div className="bg-white dark:bg-gray-800 rounded-2xl shadow-xl p-8">
          <div className="text-center mb-8">
            <div className="inline-flex items-center justify-center w-16 h-16 bg-blue-100 dark:bg-blue-900 rounded-full mb-4">
              <Shield className="w-8 h-8 text-blue-600 dark:text-blue-400" />
            </div>
            <h1 className="text-2xl font-bold text-gray-900 dark:text-white">
              Admin Login
            </h1>
            <p className="text-gray-600 dark:text-gray-400 mt-2">
              {step === 'password' ? 'Enter your credentials' : 'Enter the OTP sent to your phone'}
            </p>
          </div>

          {step === 'password' && (
            <form onSubmit={handlePasswordSubmit} className="space-y-6">
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                  Username
                </label>
                <div className="relative">
                  <User className="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-gray-400" />
                  <input
                    type="text"
                    value={credentials.username}
                    onChange={(e) => setCredentials({ ...credentials, username: e.target.value })}
                    className="w-full pl-10 pr-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent dark:bg-gray-700 dark:text-white"
                    placeholder="Enter your username"
                    required
                  />
                </div>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                  Password
                </label>
                <div className="relative">
                  <Lock className="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-gray-400" />
                  <input
                    type={showPassword ? 'text' : 'password'}
                    value={credentials.password}
                    onChange={(e) => setCredentials({ ...credentials, password: e.target.value })}
                    className="w-full pl-10 pr-10 py-2 border border-gray-300 dark:border-gray-600 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent dark:bg-gray-700 dark:text-white"
                    placeholder="Enter your password"
                    required
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    className="absolute right-3 top-1/2 transform -translate-y-1/2 text-gray-400 hover:text-gray-600 dark:hover:text-gray-300"
                  >
                    {showPassword ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
                  </button>
                </div>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                  Phone Number
                </label>
                <div className="relative">
                  <Smartphone className="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-gray-400" />
                  <input
                    type="tel"
                    value={credentials.phone}
                    onChange={(e) => setCredentials({ ...credentials, phone: e.target.value })}
                    className="w-full pl-10 pr-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent dark:bg-gray-700 dark:text-white"
                    placeholder="09XXXXXXXXX"
                    maxLength={11}
                    pattern="09[0-9]{9}"
                    required
                  />
                </div>
                <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
                  Enter your 11-digit mobile number for 2FA
                </p>
              </div>

              {error && (
                <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg p-3">
                  <div className="flex items-center gap-2">
                    <AlertCircle className="w-4 h-4 text-red-600 dark:text-red-400" />
                    <p className="text-sm text-red-800 dark:text-red-200">{error}</p>
                  </div>
                </div>
              )}

              <button
                type="submit"
                disabled={isLoading || !credentials.username || !credentials.password || credentials.phone.length !== 11}
                className="w-full py-3 bg-blue-600 hover:bg-blue-700 text-white rounded-lg font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {isLoading ? 'Verifying...' : 'Continue'}
              </button>

              <div className="text-center">
                <p className="text-sm text-gray-600 dark:text-gray-400">
                  You will receive a 6-digit OTP via SMS after password verification
                </p>
              </div>
            </form>
          )}

          {step === 'otp' && (
            <div className="space-y-6">
              <div className="text-center">
                <Smartphone className="w-12 h-12 text-blue-600 dark:text-blue-400 mx-auto mb-4" />
                <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-2">
                  Two-Factor Authentication
                </h3>
                <p className="text-sm text-gray-600 dark:text-gray-400">
                  Enter the 6-digit code sent to {formatPhoneNumber(credentials.phone.replace(/(\d{4})(\d{3})(\d{4})/, '$1 $2 $3'))}
                </p>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                  OTP Code
                </label>
                <input
                  type="text"
                  value={credentials.otp}
                  onChange={(e) => setCredentials({ ...credentials, otp: e.target.value })}
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent dark:bg-gray-700 dark:text-white text-center text-2xl font-mono"
                  placeholder="000000"
                  maxLength={6}
                  pattern="[0-9]{6}"
                  required
                />
              </div>

              <div className="flex items-center justify-between">
                <button
                  type="button"
                  onClick={() => setStep('password')}
                  className="flex items-center gap-2 text-sm text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white"
                >
                  <ArrowLeft className="w-4 h-4" />
                  Back to Login
                </button>

                <button
                  type="button"
                  onClick={handleResendOTP}
                  disabled={resendTimer > 0 || isLoading}
                  className="text-sm text-blue-600 dark:text-blue-400 hover:text-blue-800 dark:hover:text-blue-300 disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  {resendTimer > 0 ? `Resend in ${resendTimer}s` : 'Resend OTP'}
                </button>
              </div>

              {error && (
                <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg p-3">
                  <div className="flex items-center gap-2">
                    <AlertCircle className="w-4 h-4 text-red-600 dark:text-red-400" />
                    <p className="text-sm text-red-800 dark:text-red-200">{error}</p>
                  </div>
                </div>
              )}

              <button
                onClick={handleOTPVerification}
                disabled={isLoading || credentials.otp.length !== 6}
                className="w-full py-3 bg-blue-600 hover:bg-blue-700 text-white rounded-lg font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {isLoading ? 'Verifying...' : 'Verify OTP'}
              </button>

              <div className="text-center">
                <p className="text-xs text-gray-500 dark:text-gray-400">
                  OTP is valid for 5 minutes
                </p>
              </div>
            </div>
          )}
        </div>
      </motion.div>
    </div>
  )
}
