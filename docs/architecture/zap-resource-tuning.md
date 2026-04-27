# ZAP container resource tuning

> **Status:** Phase 1 Sprint 3 — current tuning is `mem_limit: 6g` + `-Xmx3500m`.
> **When to read this:** before changing the ZAP container's `mem_limit`, the JVM `-Xmx*` arg, or both. They have to move together.

## TL;DR

```
cgroup mem_limit (6 GiB)  >=  Xmx (3500 MiB)  +  non-heap JVM overhead (~2.5 GiB)
```

If `Xmx` sits above ~70 % of `mem_limit`, the kernel SIGKILLs the JVM before it can throw `OutOfMemoryError`. You see ExitCode=0, OOMKilled=false, and a worker that just gets a `ConnectError` mid-scan with no breadcrumb. That's the failure mode this doc exists to prevent.

## What's being tuned

ZAP runs as a Java daemon inside the `zynksec-zap` container. Two separate ceilings cap its memory:

1. **The cgroup ceiling.** `mem_limit` in `docker-compose.yml`. Enforced by the host kernel's memory cgroup controller. When the container's RSS hits this number, the kernel OOM killer fires and SIGKILLs whichever process inside the cgroup is using the most memory (almost always `java`). No graceful exit, no Java stack trace, no `OutOfMemoryError`.

2. **The JVM heap ceiling.** `-Xmx` on the `java` command line. Enforced by the JVM itself. When the heap hits this number, the JVM throws `OutOfMemoryError`, which propagates out of whatever ZAP rule was running and surfaces as a structured ZAP error response. Painful but recoverable and diagnosable.

You want failures to land in **case 2**, not case 1. That requires `-Xmx` strictly less than `mem_limit`, with enough headroom for everything the JVM allocates _outside_ the heap.

## Why "Xmx ≈ 70 % of cgroup" specifically

A modern HotSpot JVM running ZAP allocates several pools that don't count toward `-Xmx`:

| Pool | Typical size for ZAP | Notes |
| --- | --- | --- |
| Metaspace (class metadata) | 100-300 MiB | Grows with loaded plugins; ZAP has many. |
| Code cache (JIT-compiled methods) | ~250 MiB | Default `ReservedCodeCacheSize=240m`. |
| Direct byte buffers (NIO, Netty) | 100-500 MiB | ZAP's HTTP layer + add-ons use these. |
| Native libraries (zlib, OpenSSL, etc.) | 50-150 MiB | One-time per-process. |
| Thread stacks | ~1 MiB × thread count | At `threadPerHost = 4` plus daemon threads, ~50-100 MiB. |
| OS page cache for ZAP's session DB (HSQLDB) | varies | RSS shows this; charged to cgroup. |

Sum: typically **1.5-2.5 GiB of non-heap RSS** on a real, uninterrupted AGGRESSIVE scan. If `mem_limit` minus `-Xmx` is smaller than that, the cgroup trips while the heap still has headroom — the worst possible outcome (no OOMError, just SIGKILL).

The 60-70 % rule of thumb gives 30-40 % cgroup headroom for non-heap. At `mem_limit: 6g`, that's ~2.5 GiB of headroom against `-Xmx3500m` (3500 / 6144 ≈ 57 %). At `mem_limit: 2g` (Sprint 0/1's setting), 70 % was 1400 MiB, which is exactly what `zap.sh`'s auto-sized `-Xmx` was hitting before Sprint 3.

> **Why 6 GiB and not 5 GiB?** Sprint 3 originally shipped 5 GiB. An uninterrupted AGGRESSIVE run on a thin subpath (`/rest/products/search?q=apple`) peaked at **5.10 GiB total RSS** — exactly at the cgroup cap, with no kernel OOM but zero headroom. Earlier runs in the same suite peaked at only ~2 GiB because concurrent worker tasks were trampling each other's ZAP sessions and forcing GC; once `worker_concurrency=1` made each scan run to completion uninterrupted, the true non-heap footprint surfaced. 6 GiB restores the documented headroom under that real number.

## The current numbers

```yaml
# docker-compose.yml (Sprint 3)
mem_limit: 6g          # 6442450944 bytes
memswap_limit: 6g      # disable swap — we want memory pressure to hit the OOM killer fast
command:
  - zap.sh
  - -Xmx3500m          # JVM max heap, set via zap.sh's CLI arg path
  - -daemon
  ...
```

`3500 MiB / 6144 MiB ≈ 57 %`. Verified empirically (peak total RSS observed in the AGGRESSIVE integration test):

- AGGRESSIVE scan on `juice-shop:3000/rest/user/login` peaks at ~5.1 GiB total RSS — well inside the 6 GiB cgroup with the documented ~1 GiB of remaining headroom.
- SAFE_ACTIVE on `juice-shop:3000/rest/products/search?q=apple` peaks at ~1.7 GiB total RSS (Sprint 2 sidecar).
- PASSIVE peaks at ~700-900 MiB.

The 6 GiB cap is shared across all profiles. PASSIVE and SAFE_ACTIVE just don't use the headroom.

## Why we set Xmx via `zap.sh` CLI arg, not `_JAVA_OPTIONS`

`zap.sh` in `zaproxy/zap-stable:latest` does three things to the heap, in order of precedence:

1. Auto-sizes `-Xmx` to `(host RAM) / 4`.
2. Hardcodes `-Xmx1959m` if it can't read host memory (e.g., inside a container without `/proc/meminfo` matching the host).
3. **Iterates over `$@`. Any token starting with `-Xmx` overrides the above.**

Steps 1 and 2 explicitly ignore `_JAVA_OPTIONS` and `JAVA_TOOL_OPTIONS` — the env-var approach simply doesn't work on this image. Step 3 is the only mechanism that survives the launcher.

So the override path is: pass `-Xmx3500m` as a `command:` arg to `zap.sh`. zap.sh consumes it (assigns to `JMEM`), forwards the rest to `java`. Verified live with:

```bash
docker compose exec zap sh -c "ps -ef | grep -E 'java.*Xmx' | grep -v grep"
# java -Xmx3500m -jar /zap/zap-2.17.0.jar -daemon -host 0.0.0.0 -port 8090 ...
```

If you ever see `-Xmx1959m` in that output, the override didn't take effect — most likely the `command:` list was edited and `-Xmx*` was removed. Re-add it.

## When to revisit

- **A new ZAP minor version changes `zap.sh`'s arg parser.** Verify with `ps -ef | grep Xmx` after an image bump.
- **A new scan profile needs more heap than 3500m.** Bump `mem_limit` AND `-Xmx*` together, keeping the ~70 % ratio.
- **You're seeing ExitCode=0 + OOMKilled=false + a worker `ConnectError` mid-scan.** Classic cgroup-OOM-of-child-of-PID-1 signature. Run `dmesg | grep CONSTRAINT_MEMCG` for confirmation, then either lower the scan's heap pressure or raise `mem_limit`. Don't just bump `-Xmx` — that makes the next OOM happen faster.
- **You're seeing real `java.lang.OutOfMemoryError` in ZAP's logs.** This is the _good_ failure mode — diagnostic and recoverable. Either lower the per-scan heap pressure (smaller target, lower attack strength) or bump `-Xmx` AND `mem_limit` together.

## See also

- `packages/scanners/src/zynksec_scanners/zap/plugin.py` — `_apply_aggressive_policy` is the highest-pressure path.
- `docker-compose.yml` `zap:` service — the comment block above `mem_limit` repeats the short version of this math.
- CLAUDE.md §14 — the "known gotchas" log; the cgroup-OOM-as-ExitCode-0 quirk lives there.
