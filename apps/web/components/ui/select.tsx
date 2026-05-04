/**
 * NativeSelect — a <select> styled to fit the form.
 *
 * Phase 4 Sprint 2 deliberately avoids the full shadcn
 * Select primitive (which pulls in @radix-ui/react-select +
 * react-popover for the listbox).  The form has three pickers
 * with at most a handful of options each; native <select> is
 * accessible by default and the styling difference is small.
 *
 * If a future sprint needs typeahead, multi-select, or icons in
 * options, swap to the Radix-based primitive at that point.
 */
import { forwardRef, type SelectHTMLAttributes } from "react";

import { cn } from "@/lib/utils";

export type NativeSelectProps = SelectHTMLAttributes<HTMLSelectElement>;

export const NativeSelect = forwardRef<HTMLSelectElement, NativeSelectProps>(function NativeSelect(
  { className, children, ...props },
  ref,
) {
  return (
    <select
      ref={ref}
      className={cn(
        "flex h-9 w-full rounded-md border border-input bg-transparent px-3 py-1 text-sm shadow-sm transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-50",
        className,
      )}
      {...props}
    >
      {children}
    </select>
  );
});
