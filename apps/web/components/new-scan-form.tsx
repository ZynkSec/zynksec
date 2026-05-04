"use client";

import { useRouter } from "next/navigation";
import { useMemo, useState, type FormEvent, type ReactElement } from "react";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { NativeSelect } from "@/components/ui/select";
import { ApiError, createScan } from "@/lib/api/client";
import type {
  ScanCreateRequest,
  ScanProfile,
  ScannerCatalog,
  Target,
  TargetKind,
} from "@/lib/api/types";
import { cn } from "@/lib/utils";

/**
 * NewScanForm — Phase 4 Sprint 2.
 *
 * Two target sources:
 *   - "existing" (default): pick from the listTargets() dropdown.
 *     Submit uses target_id; the backend resolves URL + project
 *     from the Target row.
 *   - "url": paste a one-off URL with explicit kind.  Submit uses
 *     target_url; no Target row is created (Sprint 3 adds Target
 *     CRUD UI; for now this is the escape hatch).
 *
 * Scanner picker is kind-aware:
 *   - kind=web_app or kind=api → ZAP only (no scanner choice
 *     surfaced; field is auto-set to "zap" and hidden so the
 *     operator picks the scan_profile instead).
 *   - kind=repo → four code scanners (gitleaks default,
 *     plus semgrep / osv-scanner / trivy).
 *
 * Scan profile picker only renders when the kind has profiles
 * (web_app + api).  Defaults to PASSIVE.
 *
 * On submit:
 *   - 202 → router.push(`/scans/${response.id}`).
 *   - ApiError → render the canonical envelope's message inline.
 *   - Network error → render a generic "could not reach API"
 *     message; no stack trace exposure (CLAUDE.md §6).
 *
 * No client-side polling for status — the detail page already
 * shows it.  Auto-refresh / polling is a future UX sprint.
 */
type TargetSource = "existing" | "url";

const HTTPS_OR_HTTP_RE = /^https?:\/\//i;

export interface NewScanFormProps {
  targets: Target[];
  catalog: ScannerCatalog;
}

export function NewScanForm({ targets, catalog }: NewScanFormProps): ReactElement {
  const router = useRouter();

  // Form state.  Local-only — no global store, no URL params,
  // no Form library.  The form is single-submit-and-redirect, so
  // useState is the right shape.
  const [source, setSource] = useState<TargetSource>(targets.length > 0 ? "existing" : "url");
  const [targetId, setTargetId] = useState<string>(targets[0]?.id ?? "");
  const [pastedUrl, setPastedUrl] = useState<string>("");
  const [pastedKind, setPastedKind] = useState<TargetKind>("web_app");
  const [scanner, setScanner] = useState<string>("");
  const [scanProfile, setScanProfile] = useState<ScanProfile>("PASSIVE");
  const [submitting, setSubmitting] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  // Resolve the active kind.  Existing-target source reads from
  // the chosen Target row; URL source reads the explicit picker.
  const activeKind: TargetKind = useMemo(() => {
    if (source === "existing") {
      return targets.find((t) => t.id === targetId)?.kind ?? "web_app";
    }
    return pastedKind;
  }, [source, targetId, targets, pastedKind]);

  const kindCatalog = catalog.kinds[activeKind];

  // Reset scanner + profile to the kind's defaults whenever the
  // active kind changes.  ``useMemo`` over an effect keeps the
  // computation deterministic without an extra render.
  const defaultScanner = useMemo(
    () =>
      kindCatalog.scanners.find((s) => s.is_default)?.name ?? kindCatalog.scanners[0]?.name ?? "",
    [kindCatalog],
  );
  // If the current scanner state isn't valid for this kind, fall
  // back to the kind's default.  Done at render time (no effect)
  // so the chosen scanner is always one this kind supports.
  const effectiveScanner = useMemo(() => {
    const valid = kindCatalog.scanners.some((s) => s.name === scanner);
    return valid ? scanner : defaultScanner;
  }, [kindCatalog, scanner, defaultScanner]);

  const showScannerPicker = kindCatalog.scanners.length > 1;
  const showScanProfilePicker = kindCatalog.scan_profiles.length > 0;

  // Submit-button-disabled rules — keep the user from POSTing
  // a payload the API will reject.
  const isUrlValid = HTTPS_OR_HTTP_RE.test(pastedUrl);
  const canSubmit =
    !submitting &&
    effectiveScanner !== "" &&
    ((source === "existing" && targetId !== "") || (source === "url" && isUrlValid));

  async function handleSubmit(e: FormEvent<HTMLFormElement>): Promise<void> {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      const body: ScanCreateRequest = {
        scanner: effectiveScanner,
        ...(showScanProfilePicker ? { scan_profile: scanProfile } : {}),
        ...(source === "existing" ? { target_id: targetId } : { target_url: pastedUrl }),
      };
      const scan = await createScan(body);
      router.push(`/scans/${scan.id}`);
    } catch (err) {
      setSubmitting(false);
      if (err instanceof ApiError) {
        // Canonical envelope's message field — operator-facing
        // copy; the code field is the machine-readable token.
        setError(err.body.message);
      } else {
        setError("Could not reach the API. Check that the backend is running.");
      }
    }
  }

  return (
    <form onSubmit={handleSubmit} className="space-y-6">
      {error && (
        <div
          role="alert"
          className="rounded-md border border-destructive/50 bg-destructive/5 p-4 text-sm text-destructive"
        >
          {error}
        </div>
      )}

      {/* Target source toggle */}
      <fieldset className="space-y-3">
        <legend className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
          Target
        </legend>
        <div className="flex gap-2">
          <Button
            type="button"
            variant={source === "existing" ? "default" : "outline"}
            size="sm"
            onClick={() => setSource("existing")}
            disabled={targets.length === 0}
            aria-pressed={source === "existing"}
          >
            Existing target
          </Button>
          <Button
            type="button"
            variant={source === "url" ? "default" : "outline"}
            size="sm"
            onClick={() => setSource("url")}
            aria-pressed={source === "url"}
          >
            New URL
          </Button>
        </div>

        {source === "existing" ? (
          targets.length === 0 ? (
            <p className="text-sm text-muted-foreground">
              No targets yet — paste a URL instead, or create one via the API (Target CRUD UI lands
              in the next sprint).
            </p>
          ) : (
            <div className="space-y-1.5">
              <Label htmlFor="target-id">Target</Label>
              <NativeSelect
                id="target-id"
                value={targetId}
                onChange={(e) => setTargetId(e.target.value)}
              >
                {targets.map((t) => (
                  <option key={t.id} value={t.id}>
                    {t.name} ({t.kind}) — {t.url}
                  </option>
                ))}
              </NativeSelect>
            </div>
          )
        ) : (
          <div className="grid gap-3 md:grid-cols-[2fr_1fr]">
            <div className="space-y-1.5">
              <Label htmlFor="target-url">URL</Label>
              <Input
                id="target-url"
                type="url"
                placeholder="https://example.com/"
                value={pastedUrl}
                onChange={(e) => setPastedUrl(e.target.value)}
                aria-invalid={pastedUrl !== "" && !isUrlValid}
                required
              />
              {pastedUrl !== "" && !isUrlValid && (
                <p className="text-xs text-destructive">URL must start with http:// or https://</p>
              )}
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="target-kind">Kind</Label>
              <NativeSelect
                id="target-kind"
                value={pastedKind}
                onChange={(e) => setPastedKind(e.target.value as TargetKind)}
              >
                <option value="web_app">web_app</option>
                <option value="api">api</option>
                <option value="repo">repo</option>
              </NativeSelect>
            </div>
          </div>
        )}
      </fieldset>

      {/* Scanner picker — only shown when there's more than one choice */}
      {showScannerPicker && (
        <div className="space-y-1.5">
          <Label htmlFor="scanner">Scanner</Label>
          <NativeSelect
            id="scanner"
            value={effectiveScanner}
            onChange={(e) => setScanner(e.target.value)}
          >
            {kindCatalog.scanners.map((s) => (
              <option key={s.name} value={s.name}>
                {s.name}
                {s.is_default ? " (default)" : ""}
              </option>
            ))}
          </NativeSelect>
        </div>
      )}

      {/* Scan profile picker — only when the kind has profiles */}
      {showScanProfilePicker && (
        <div className="space-y-1.5">
          <Label htmlFor="scan-profile">Scan profile</Label>
          <NativeSelect
            id="scan-profile"
            value={scanProfile}
            onChange={(e) => setScanProfile(e.target.value as ScanProfile)}
          >
            {kindCatalog.scan_profiles.map((p) => (
              <option key={p} value={p}>
                {p}
              </option>
            ))}
          </NativeSelect>
        </div>
      )}

      <div className="flex items-center gap-3">
        <Button type="submit" disabled={!canSubmit} className={cn(submitting && "opacity-80")}>
          {submitting ? "Submitting…" : "Start scan"}
        </Button>
      </div>
    </form>
  );
}
