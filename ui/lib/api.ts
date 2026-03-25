export function apiPath(path: string): string {
  const normalized = path.startsWith("/") ? path : `/${path}`;
  if (normalized.startsWith("/api/")) {
    return normalized;
  }
  return `/api/v1${normalized}`;
}

export function apiOrigin(): string {
  const raw = process.env.NEXT_PUBLIC_API_URL?.trim();
  return raw ? raw.replace(/\/$/, "") : "";
}

export function streamUrl(path = "/stream"): string {
  const normalized = path.startsWith("/api/") ? path : apiPath(path);
  const origin = apiOrigin();
  return origin ? `${origin}${normalized}` : normalized;
}
