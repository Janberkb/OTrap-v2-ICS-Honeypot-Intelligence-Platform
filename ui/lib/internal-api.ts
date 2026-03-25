export const INTERNAL_API_BASE =
  process.env.INTERNAL_API_BASE ??
  process.env.NEXT_PUBLIC_API_URL ??
  "http://manager:8080";
