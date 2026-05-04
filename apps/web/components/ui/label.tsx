/**
 * Label — semantic <label> styled to match the rest of the form
 * primitives.  No @radix-ui/react-label dependency this sprint;
 * the native element handles `htmlFor` + click-to-focus the same
 * way Radix does.
 */
import { forwardRef, type LabelHTMLAttributes } from "react";

import { cn } from "@/lib/utils";

export const Label = forwardRef<HTMLLabelElement, LabelHTMLAttributes<HTMLLabelElement>>(
  function Label({ className, ...props }, ref) {
    return (
      <label
        ref={ref}
        className={cn(
          "text-sm font-medium leading-none peer-disabled:cursor-not-allowed peer-disabled:opacity-70",
          className,
        )}
        {...props}
      />
    );
  },
);
