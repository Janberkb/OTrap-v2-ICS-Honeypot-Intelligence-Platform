// middleware.ts — Server-side route protection
import { NextRequest, NextResponse } from "next/server";
import { INTERNAL_API_BASE } from "@/lib/internal-api";

const PUBLIC_PATHS = ["/login"];
const ADMIN_PATHS  = ["/admin"];

export async function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl;

  // Allow public paths
  if (PUBLIC_PATHS.some((p) => pathname.startsWith(p))) {
    return NextResponse.next();
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

  return NextResponse.next();
}

export const config = {
  matcher: ["/((?!_next/static|_next/image|favicon.ico|api/|brand/|.*\\.(?:svg|png|jpg|jpeg|webp|ico)$).*)"],
};
