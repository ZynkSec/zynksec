import { redirect } from "next/navigation";

/**
 * Root page — redirects to /scans, the only meaningful view in
 * Phase 4 Sprint 1.  Future sprints replace this with a proper
 * dashboard home (project picker, recent activity, etc.) once
 * those concepts have UI scope.
 */
export default function HomePage(): never {
  redirect("/scans");
}
