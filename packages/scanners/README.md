# zynksec-scanners

Scanner plugin contract + engine implementations.

`ScannerPlugin` in `base.py` is the abstract interface every engine
implements (docs/03 §6, docs/04 §0.10). CLAUDE.md §3 (O — Open/Closed):
adding a new scanner means subclassing `ScannerPlugin`, never
modifying the worker.

## Status

Phase 0 Week 1: contract stub only. Week 3 lands the first concrete
subclass (ZAP) under `zynksec_scanners.zap`. Phase 1 adds Nuclei +
testssl; Phase 2 adds ProjectDiscovery (Subfinder / httpx / Katana /
Naabu) + Interactsh; Phase 3 adds SAST / SCA / secrets engines.
