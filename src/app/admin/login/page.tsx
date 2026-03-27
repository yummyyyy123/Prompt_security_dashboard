'use client'

import React, { useState } from 'react'
import { motion } from 'framer-motion'
import { Shield, Eye, EyeOff, Lock, User, AlertCircle, ArrowLeft, Mail } from 'lucide-react'
import { useRouter } from 'next/navigation'

export default function AdminLogin() {
  const [step, setStep] = useState<'credentials' | 'otp'>('credentials')
  const [credentials, setCredentials] = useState({ username: '', password: '' })
  const [otp, setOtp] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState('')
  const [tempToken, setTempToken] = useState('')
  const [resendTimer, setResendTimer] = useState(0)
  const router = useRouter()

  // Step 1: verify username + password, then trigger OTP send (server picks the admin email)
  const handleCredentialsSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    setIsLoading(true)

    try {
      const response = await fetch('/api/admin/auth/email-otp', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username: credentials.username,
          password: credentials.password
        })
      })

      const data = await response.json()

      if (response.ok && data.success) {
        setTempToken(data.tempToken || '')
        setStep('otp')
        startResendTimer(300)
      } else {
        setError(data.error || 'Login failed. Please check your credentials.')
      }
    } catch {
      setError('Network error. Please try again.')
    } finally {
      setIsLoading(false)
    }
  }

  // Step 2: verify OTP
  const handleOTPVerification = async () => {
    setError('')
    setIsLoading(true)

    try {
      const response = await fetch('/api/admin/auth/2fa-login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username: credentials.username,
          otp,
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
    } catch {
      setError('Network error. Please try again.')
    } finally {
      setIsLoading(false)
    }
  }

  const handleResendOTP = async () => {
    setError('')
    setIsLoading(true)

    try {
      const response = await fetch('/api/admin/auth/email-otp', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username: credentials.username,
          password: credentials.password
        })
      })

      const data = await response.json()

      if (response.ok && data.success) {
        setTempToken(data.tempToken || '')
        startResendTimer(300)
        setError('OTP resent successfully')
        setTimeout(() => setError(''), 3000)
      } else {
        setError(data.error || 'Failed to resend OTP')
      }
    } catch {
      setError('Network error. Please try again.')
    } finally {
      setIsLoading(false)
    }
  }

  const startResendTimer = (seconds: number) => {
    setResendTimer(seconds)
    const timer = setInterval(() => {
      setResendTimer((prev) => {
        if (prev <= 1) { clearInterval(timer); return 0 }
        return prev - 1
      })
    }, 1000)
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
            <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Admin Login</h1>
            <p className="text-gray-600 dark:text-gray-400 mt-2">
              {step === 'credentials'
                ? 'Enter your admin credentials'
                : 'Enter the OTP sent to the admin email'}
            </p>
          </div>

          {/* Step 1: Username + Password */}
          {step === 'credentials' && (
            <form onSubmit={handleCredentialsSubmit} className="space-y-6">
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
                    autoComplete="username"
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
                    autoComplete="current-password"
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

              {error && (
                <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg p-3">
                  <div className="flex items-center gap-2">
                    <AlertCircle className="w-4 h-4 text-red-600 dark:text-red-400 shrink-0" />
                    <p className="text-sm text-red-800 dark:text-red-200">{error}</p>
                  </div>
                </div>
              )}

              <button
                type="submit"
                disabled={isLoading || !credentials.username || !credentials.password}
                className="w-full py-3 bg-blue-600 hover:bg-blue-700 text-white rounded-lg font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {isLoading ? 'Verifying…' : 'Verify & Send OTP'}
              </button>

              <div className="text-center">
                <p className="text-sm text-gray-600 dark:text-gray-400">
                  🔐 Two-factor authentication enabled for enhanced security
                </p>
                <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
                  A 6-digit OTP will be sent to the admin email after credential verification
                </p>
              </div>
            </form>
          )}

          {/* Step 2: OTP */}
          {step === 'otp' && (
            <div className="space-y-6">
              <div className="text-center">
                <Mail className="w-12 h-12 text-blue-600 dark:text-blue-400 mx-auto mb-4" />
                <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-2">
                  Two-Factor Authentication
                </h3>
                <p className="text-sm text-gray-600 dark:text-gray-400">
                  A 6-digit OTP has been sent to the admin email address.
                </p>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                  OTP Code
                </label>
                <input
                  type="text"
                  value={otp}
                  onChange={(e) => setOtp(e.target.value.replace(/\D/g, '').slice(0, 6))}
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent dark:bg-gray-700 dark:text-white text-center text-2xl font-mono tracking-widest"
                  placeholder="000000"
                  maxLength={6}
                  inputMode="numeric"
                  autoComplete="one-time-code"
                  required
                />
              </div>

              <div className="flex items-center justify-between">
                <button
                  type="button"
                  onClick={() => { setStep('credentials'); setOtp(''); setError('') }}
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
                    <AlertCircle className="w-4 h-4 text-red-600 dark:text-red-400 shrink-0" />
                    <p className="text-sm text-red-800 dark:text-red-200">{error}</p>
                  </div>
                </div>
              )}

              <button
                onClick={handleOTPVerification}
                disabled={isLoading || otp.length !== 6}
                className="w-full py-3 bg-blue-600 hover:bg-blue-700 text-white rounded-lg font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {isLoading ? 'Verifying…' : 'Verify OTP'}
              </button>

              <div className="text-center">
                <p className="text-xs text-gray-500 dark:text-gray-400">OTP is valid for 5 minutes</p>
              </div>
            </div>
          )}
        </div>
      </motion.div>
    </div>
  )
}
