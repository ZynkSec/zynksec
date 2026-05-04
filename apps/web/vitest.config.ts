import path from "node:path";

import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

/**
 * Vitest config — Phase 4 Sprint 1 minimum.
 *
 * happy-dom over jsdom: 2-3x faster startup, identical API for
 * what the smoke test needs (queries + classlist assertions).
 *
 * Path alias mirrors tsconfig.json so test files can import
 * from "@/components/..." just like production code.
 */
export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "."),
    },
  },
  test: {
    environment: "happy-dom",
    globals: false,
    include: ["**/*.test.ts", "**/*.test.tsx"],
    exclude: ["node_modules/**", ".next/**"],
  },
});
