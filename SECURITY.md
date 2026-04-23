# Security policy

## Reporting a vulnerability

If you believe you've found a security vulnerability in Zynksec, **please do not open a public GitHub issue.** Public disclosure before a fix is available puts users at risk.

Report it privately through one of these channels:

1. **GitHub Security Advisory** (preferred): use the [Report a vulnerability](https://github.com/ZynkSec/zynksec/security/advisories/new) link on this repository. This creates a private, encrypted channel where we can collaborate on triage and disclosure.
2. **Email**: `security@zynksec.dev` (PGP key fingerprint will be published here once Zynksec leaves pre-alpha).

When reporting, please include:

- A clear description of the vulnerability and its potential impact.
- Steps to reproduce, ideally with a minimal proof-of-concept.
- The version / commit SHA you tested against.
- Any suggested mitigations or patches if you have them.

## What you can expect

Zynksec is a solo, pre-alpha project. Response times reflect that:

| Stage                               | Target                                             |
| ----------------------------------- | -------------------------------------------------- |
| Acknowledgement of report           | Within 5 business days                             |
| Initial triage and severity rating  | Within 14 business days                            |
| Fix or mitigation plan communicated | Within 30 business days for High / Critical        |
| Public disclosure                   | Coordinated with reporter after a fix is available |

If a vulnerability is being actively exploited, we will move faster.

## Scope

This policy covers:

- The Zynksec codebase in this repository (`ZynkSec/zynksec`).
- Official Zynksec Docker images.
- Official Zynksec documentation that gives security-sensitive guidance.

Out of scope:

- Vulnerabilities in **upstream dependencies** (OWASP ZAP, Nuclei, FastAPI, Next.js, etc.) — please report those to the respective projects. We are happy to coordinate if it affects how Zynksec uses them.
- Vulnerabilities in **target applications** that Zynksec scans — those are findings, not Zynksec bugs.
- Issues that require an attacker to already have administrative access to a Zynksec deployment.

## Safe harbor

We will not pursue legal action against good-faith security research that:

- Stays within the scope above.
- Avoids privacy violations, destruction of data, or service disruption.
- Gives us reasonable time to remediate before public disclosure.
- Does not exploit findings beyond what's necessary to confirm the vulnerability.

## Hall of fame

Once Zynksec leaves pre-alpha, security researchers who responsibly disclose vulnerabilities will be credited here (with their permission).
