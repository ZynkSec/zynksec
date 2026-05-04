"use client";

import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { useTransition, type ReactElement } from "react";

import { Badge } from "@/components/ui/badge";
import { ALL_SEVERITIES, severityBadgeVariant } from "@/lib/severity";
import type { Severity } from "@/lib/api/types";
import { cn } from "@/lib/utils";

/**
 * URL-persisted severity multi-select.  Phase 4 Sprint 1.
 *
 * Each chip toggles its severity in the ``?severity=`` search
 * param.  All four chips off → no filter (param removed).  All
 * four on is the same as no filter visually, but we still record
 * the explicit selection in the URL so a copy-pasted link
 * behaves predictably.
 *
 * Implementation notes:
 *   - Uses ``router.push`` + ``startTransition`` so the URL
 *     update doesn't block the UI; Next streams the updated
 *     server-component render in.
 *   - ``scroll: false`` on the push so toggling a chip doesn't
 *     yank the page back to the top.
 *   - ``aria-pressed`` on each chip so screen readers announce
 *     toggle state.
 */
export interface SeverityFilterProps {
  selected: ReadonlySet<Severity>;
}

export function SeverityFilter({ selected }: SeverityFilterProps): ReactElement {
  const router = useRouter();
  const pathname = usePathname();
  const searchParams = useSearchParams();
  const [pending, startTransition] = useTransition();

  function toggle(severity: Severity): void {
    const next = new Set(selected);
    if (next.has(severity)) {
      next.delete(severity);
    } else {
      next.add(severity);
    }
    const params = new URLSearchParams(searchParams.toString());
    if (next.size === 0) {
      params.delete("severity");
    } else {
      // Order tokens by canonical severity ranking so the URL is
      // stable across click-orderings ("?severity=critical,high"
      // not "?severity=high,critical" if the user clicked high
      // then critical).  Stable URLs cache better and read
      // better.
      const ordered = ALL_SEVERITIES.filter((s) => next.has(s)).join(",");
      params.set("severity", ordered);
    }
    const qs = params.toString();
    const target = qs ? `${pathname}?${qs}` : pathname;
    startTransition(() => {
      router.push(target, { scroll: false });
    });
  }

  return (
    <div
      role="group"
      aria-label="Filter findings by severity"
      className={cn("flex flex-wrap items-center gap-2", pending && "opacity-70")}
    >
      <span className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
        Severity
      </span>
      {ALL_SEVERITIES.map((severity) => {
        const active = selected.has(severity);
        return (
          <button
            key={severity}
            type="button"
            onClick={() => toggle(severity)}
            aria-pressed={active}
            className={cn(
              "rounded-full border px-2 py-0.5 transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-ring",
              active ? "border-foreground" : "border-transparent opacity-60 hover:opacity-100",
            )}
          >
            <Badge variant={severityBadgeVariant(severity)}>{severity}</Badge>
          </button>
        );
      })}
      {selected.size > 0 && (
        <button
          type="button"
          onClick={() => {
            const params = new URLSearchParams(searchParams.toString());
            params.delete("severity");
            const qs = params.toString();
            const target = qs ? `${pathname}?${qs}` : pathname;
            startTransition(() => {
              router.push(target, { scroll: false });
            });
          }}
          className="text-xs text-muted-foreground transition-colors hover:text-foreground"
        >
          Clear
        </button>
      )}
    </div>
  );
}
