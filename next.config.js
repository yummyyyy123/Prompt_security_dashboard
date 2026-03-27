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
    
    // Handle WASM files
    config.experiments = { ...config.experiments, asyncWebAssembly: true }
    
    return config
  }
}

module.exports = nextConfig
