# Zynksec target lab

> ⚠️ **WARNING — these images contain real, known vulnerabilities.**
> Do **NOT** expose them on a network you don't fully control.
> Compose places them behind the `lab` profile and on the
> `zynksec-targets` network (`internal: true` — no host ports, no
> outbound internet). See `docs/04_phase0_scaffolding.md` §0.17 /
> §0.19 for the full rationale.

Bring them up via:

```
docker compose \
  -f docker-compose.yml \
  -f target-lab/compose-targets.yml \
  --profile lab \
  up -d
```

Only ZAP reaches these targets (it bridges `zynksec-scan` and
`zynksec-targets`). The API and the worker cannot, by design.

## OWASP Juice Shop (`juice-shop`)

- Image: `bkimminich/juice-shop:latest`
- Upstream: <https://github.com/juice-shop/juice-shop>
- Challenge catalog: ~100 (SQLi, XSS, broken auth, SSRF, IDOR,
  cryptographic failures, insecure deserialization, ...).

### Well-known credentials (from the Juice Shop docs)

| User                 | Password                   |
| -------------------- | -------------------------- |
| `admin@juice-sh.op`  | `admin123`                 |
| `jim@juice-sh.op`    | `ncc-1701`                 |
| `bender@juice-sh.op` | `OhG0dPlease1nsertLiquor!` |

These are public and intentionally weak — part of the challenge set.

## Phase roadmap

| Phase | Targets added                                    |
| ----- | ------------------------------------------------ |
| 0     | OWASP Juice Shop                                 |
| 1     | DVWA, OWASP WebGoat                              |
| 3     | Internal Zynksec Benchmark Suite (purpose-built) |
