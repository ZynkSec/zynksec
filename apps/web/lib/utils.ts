/**
 * cn() — Tailwind className merger.  Standard shadcn helper:
 * ``clsx`` flattens conditional class lists, ``tailwind-merge``
 * dedups conflicting Tailwind utilities (so ``cn("p-2", "p-4")``
 * yields ``"p-4"`` not ``"p-2 p-4"``).
 */
import { type ClassValue, clsx } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]): string {
  return twMerge(clsx(inputs));
}
