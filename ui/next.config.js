const createNextIntlPlugin = require("next-intl/plugin");
const withNextIntl = createNextIntlPlugin("./i18n.ts");

const internalApiBase = process.env.INTERNAL_API_BASE ?? "http://manager:8080";

/** @type {import('next').NextConfig} */
const nextConfig = {
  output: "standalone",

  // Prevent @react-pdf/renderer from being bundled server-side (it's client-only)
  serverExternalPackages: ["@react-pdf/renderer"],

  webpack: (config) => {
    // canvas is an optional peer dep of @react-pdf/renderer; not needed in browser
    config.resolve.alias = { ...config.resolve.alias, canvas: false };
    return config;
  },

  // Proxy API calls to Manager in production (avoids CORS for same-origin requests)
  async rewrites() {
    return [
      {
        source:      "/api/:path*",
        destination: `${internalApiBase}/api/:path*`,
      },
    ];
  },

  // Static security headers (CSP is handled dynamically in middleware.ts)
  async headers() {
    return [
      {
        source: "/(.*)",
        headers: [
          { key: "X-Frame-Options",        value: "DENY" },
          { key: "X-Content-Type-Options",  value: "nosniff" },
          { key: "Referrer-Policy",         value: "strict-origin-when-cross-origin" },
          { key: "X-XSS-Protection",        value: "1; mode=block" },
          { key: "Permissions-Policy",      value: "camera=(), microphone=(), geolocation=()" },
        ],
      },
    ];
  },
};

module.exports = withNextIntl(nextConfig);
