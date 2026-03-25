const createNextIntlPlugin = require("next-intl/plugin");
const withNextIntl = createNextIntlPlugin("./i18n.ts");

const internalApiBase = process.env.INTERNAL_API_BASE ?? "http://manager:8080";
const publicApiUrl = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8080";

function originOf(url) {
  try {
    return new URL(url).origin;
  } catch {
    return null;
  }
}

const connectSrc = ["'self'", "ws:", "wss:"];
const publicApiOrigin = originOf(publicApiUrl);
if (publicApiOrigin && !connectSrc.includes(publicApiOrigin)) {
  connectSrc.push(publicApiOrigin);
}

/** @type {import('next').NextConfig} */
const nextConfig = {
  output: "standalone",

  // Proxy API calls to Manager in production (avoids CORS for same-origin requests)
  async rewrites() {
    return [
      {
        source:      "/api/:path*",
        destination: `${internalApiBase}/api/:path*`,
      },
    ];
  },

  // Security headers
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
          {
            key: "Content-Security-Policy",
            value: [
              "default-src 'self'",
              "script-src 'self' 'unsafe-inline' 'unsafe-eval'",   // Next.js requires these in dev
              "style-src 'self' 'unsafe-inline' fonts.googleapis.com",
              "font-src 'self' fonts.gstatic.com",
              `connect-src ${connectSrc.join(" ")}`,
              "img-src 'self' data:",
            ].join("; "),
          },
        ],
      },
    ];
  },
};

module.exports = withNextIntl(nextConfig);
