const path = require('path')

/** @type {import('next').NextConfig} */
const nextConfig = {
  experimental: {
    // Remove rust-security-service from here to avoid conflict
  },
  webpack: (config, { isServer }) => {
    config.experiments = { ...config.experiments, asyncWebAssembly: true }
    
    // Fix module resolution issues
    config.resolve.alias = {
      ...config.resolve.alias,
      '@': path.resolve(__dirname, 'src'),
    }
    
    return config
  },
  transpilePackages: ['rust-security-service']
}

module.exports = nextConfig
