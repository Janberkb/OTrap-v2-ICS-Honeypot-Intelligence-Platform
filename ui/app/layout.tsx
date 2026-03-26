// app/layout.tsx
import type { Metadata, Viewport } from "next";
import { headers } from "next/headers";
import "./globals.css";

export const metadata: Metadata = {
  title:       "OTrap — OT Deception Platform",
  description: "Enterprise ICS/OT Honeypot Management Console",
  robots:      "noindex, nofollow",
  icons: {
    icon:     [{ url: "/brand/icon.svg", type: "image/svg+xml" }],
    shortcut: [{ url: "/brand/icon.svg", type: "image/svg+xml" }],
  },
};

export const viewport: Viewport = {
  themeColor: "#111216",
};

// Reading x-nonce causes Next.js to automatically apply the nonce
// to all inline scripts it generates (RSC payloads, router state, etc.),
// which is required for nonce-based CSP to work without blocking hydration.
export default async function RootLayout({ children }: { children: React.ReactNode }) {
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const _nonce = (await headers()).get("x-nonce");

  return (
    <html lang="en" className="dark" data-theme="brand">
      <body>{children}</body>
    </html>
  );
}
