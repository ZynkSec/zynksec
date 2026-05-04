/**
 * Next.js 15 config — Zynksec dashboard.
 *
 * Phase 4 Sprint 1: read-only scan list + detail view.  No
 * special build features needed yet (no images CDN, no rewrites,
 * no headers).  Kept minimal so the build surface stays small;
 * future sprints can layer on as concrete needs land.
 */
/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  poweredByHeader: false,
};

export default nextConfig;
