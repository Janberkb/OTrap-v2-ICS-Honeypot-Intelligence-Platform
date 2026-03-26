// middleware.ts — Route protection + per-request CSP nonce
import { NextRequest, NextResponse } from "next/server";
import { INTERNAL_API_BASE } from "@/lib/internal-api";

const PUBLIC_PATHS = ["/login"];
const ADMIN_PATHS  = ["/admin"];

// ─── Nonce helpers ────────────────────────────────────────────────────────────

function generateNonce(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  // btoa works in Edge Runtime; avoid Buffer which is Node-only
  return btoa(String.fromCharCode(...bytes));
}

const _publicApiOrigin = (() => {
  try {
    return new URL(process.env.NEXT_PUBLIC_API_URL ?? "").origin;
  } catch {
    return null;
  }
})();

function buildCSP(nonce: string): string {
  const connectSrc = ["'self'", "ws:", "wss:"];
  if (_publicApiOrigin && !connectSrc.includes(_publicApiOrigin)) {
    connectSrc.push(_publicApiOrigin);
  }

  const isDev = process.env.NODE_ENV === "development";

  return [
    "default-src 'self'",
    // In dev, keep unsafe-eval so Next.js fast-refresh works
    isDev
      ? `script-src 'self' 'nonce-${nonce}' 'unsafe-eval'`
      : `script-src 'self' 'nonce-${nonce}'`,
    "style-src 'self' 'unsafe-inline' fonts.googleapis.com",
    "font-src 'self' fonts.gstatic.com",
    `connect-src ${connectSrc.join(" ")}`,
    "img-src 'self' data:",
  ].join("; ");
}

// ─── Middleware ───────────────────────────────────────────────────────────────

export async function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl;
  const nonce = generateNonce();

  // Build request headers that carry the nonce forward to server components
  const requestHeaders = new Headers(request.headers);
  requestHeaders.set("x-nonce", nonce);

  // Allow public paths — still apply CSP
  if (PUBLIC_PATHS.some((p) => pathname.startsWith(p))) {
    const response = NextResponse.next({ request: { headers: requestHeaders } });
    response.headers.set("Content-Security-Policy", buildCSP(nonce));
    return response;
  }

  // Check session cookie
  const sessionCookie = request.cookies.get("otrap_session");
  if (!sessionCookie?.value) {
    return NextResponse.redirect(new URL("/login", request.url));
  }

  // For admin routes, verify role server-side
  if (ADMIN_PATHS.some((p) => pathname.startsWith(p))) {
    try {
      const res = await fetch(`${INTERNAL_API_BASE}/api/v1/auth/me`, {
        headers: { Cookie: `otrap_session=${sessionCookie.value}` },
        cache:   "no-store",
      });
      if (!res.ok) {
        return NextResponse.redirect(new URL("/login", request.url));
      }
      const user = await res.json();
      if (user.role !== "superadmin") {
        return NextResponse.redirect(new URL("/dashboard", request.url));
      }
    } catch {
      return NextResponse.redirect(new URL("/login", request.url));
    }
  }

  const response = NextResponse.next({ request: { headers: requestHeaders } });
  response.headers.set("Content-Security-Policy", buildCSP(nonce));
  return response;
}

export const config = {
  matcher: ["/((?!_next/static|_next/image|favicon.ico|api/|brand/|.*\\.(?:svg|png|jpg|jpeg|webp|ico)$).*)"],
};
