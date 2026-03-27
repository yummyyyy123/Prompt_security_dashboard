/** @type {import('next').NextConfig} */
const nextConfig = {
  experimental: {
    serverComponentsExternalPackages: ['rust-security-service']
  },
  webpack: (config) => {
    config.experiments = { ...config.experiments, asyncWebAssembly: true }
  }
}

module.exports = nextConfig
