// app/layout.tsx
import type { Metadata, Viewport } from "next";
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

export default function RootLayout({ children }: { children: React.ReactNode }) {
  const activeTheme = "brand";

  return (
    <html lang="en" className="dark" data-theme={activeTheme}>
      <body>{children}</body>
    </html>
  );
}
