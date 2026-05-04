/**
 * Badge — shadcn/ui-style primitive used to tag severity, status,
 * scanner family, etc.  Variants:
 *   - default / secondary / outline / destructive — standard shadcn.
 *   - severity-{low,medium,high,critical} — Zynksec-specific,
 *     mapped to the --severity-* CSS tokens defined in globals.css.
 *   - status-{queued,running,completed,failed} — Zynksec-specific,
 *     for the scan-status pill in the list and detail headers.
 *
 * Implemented with class-variance-authority so variant prop names
 * are type-safe at call sites.  No Radix dependency — the badge
 * is a plain styled <span>.
 */
import { cva, type VariantProps } from "class-variance-authority";
import type { HTMLAttributes, ReactElement } from "react";

import { cn } from "@/lib/utils";

const badgeVariants = cva(
  "inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium transition-colors",
  {
    variants: {
      variant: {
        default: "bg-primary text-primary-foreground",
        secondary: "bg-secondary text-secondary-foreground",
        outline: "border text-foreground",
        destructive: "bg-destructive text-destructive-foreground",
        // Severity scale.  Background + foreground both keyed off
        // the same hue with manual contrast tuning so each level is
        // legible against the card background.
        "severity-low": "bg-[hsl(var(--severity-low)/0.15)] text-[hsl(var(--severity-low))]",
        "severity-medium":
          "bg-[hsl(var(--severity-medium)/0.15)] text-[hsl(var(--severity-medium))]",
        "severity-high": "bg-[hsl(var(--severity-high)/0.15)] text-[hsl(var(--severity-high))]",
        "severity-critical":
          "bg-[hsl(var(--severity-critical)/0.2)] text-[hsl(var(--severity-critical))]",
        // Scan-status palette.  Greens / ambers / reds chosen to
        // line up with the severity tokens so the eye reads them
        // as the same family.
        "status-queued": "bg-muted text-muted-foreground",
        "status-running":
          "bg-[hsl(var(--severity-medium)/0.15)] text-[hsl(var(--severity-medium))]",
        "status-completed": "bg-[hsl(var(--severity-low)/0.15)] text-[hsl(var(--severity-low))]",
        "status-failed":
          "bg-[hsl(var(--severity-critical)/0.2)] text-[hsl(var(--severity-critical))]",
      },
    },
    defaultVariants: {
      variant: "default",
    },
  },
);

export interface BadgeProps
  extends HTMLAttributes<HTMLSpanElement>, VariantProps<typeof badgeVariants> {}

export function Badge({ className, variant, ...props }: BadgeProps): ReactElement {
  return <span className={cn(badgeVariants({ variant }), className)} {...props} />;
}

export { badgeVariants };
