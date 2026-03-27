/** @type {import('next').NextConfig} */
const nextConfig = {
  experimental: {
    // Remove rust-security-service from here to avoid conflict
  },
  webpack: (config, { isServer }) => {
    config.experiments = { ...config.experiments, asyncWebAssembly: true }
    return config
  },
  transpilePackages: ['rust-security-service']
}

module.exports = nextConfig
