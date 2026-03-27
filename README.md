# Security Dashboard

Isolated security dashboard for the Prompt Library application with admin authentication, MFA, and security monitoring.

## Features

- 🔐 **Admin Authentication** with MFA/2FA support
- 🛡️ **Security Monitoring** with real-time logs and alerts
- 📊 **Dashboard Interface** for security event management
- 🦀 **Rust WASM Integration** for enhanced security operations
- 🔒 **IP Blocking** and rate limiting
- 📧 **Security Configuration** management

## Architecture

This is a standalone security dashboard extracted from the main prompt library application to provide:

- **Isolated Security**: Dedicated security infrastructure
- **Enhanced Protection**: MFA-required authentication
- **Rust Security**: WASM-based security operations
- **Separate Deployment**: Independent Vercel project

## Setup

1. Install dependencies:
```bash
npm install
```

2. Configure environment variables:
```bash
cp .env.local.example .env.local
# Edit .env.local with your actual values
```

3. Build Rust WASM:
```bash
cd rust-security-service
wasm-pack build --target web --out-dir ../pkg
```

4. Start development server:
```bash
npm run dev
```

## Security Features

- **Multi-Factor Authentication**: Email OTP with time-based codes
- **Session Management**: Secure JWT tokens with expiration
- **Rate Limiting**: Advanced rate limiting with sliding windows
- **Input Validation**: Rust-based payload validation and sanitization
- **Security Logging**: Comprehensive audit trail
- **IP Management**: Manual IP blocking with automatic expiration

## Deployment

Deployed to Vercel with environment variables configured for production security operations.

## Repository

This is part of a microservices architecture:
- **Main App**: Public prompt library functionality
- **Security Dashboard**: Isolated security operations (this repo)
