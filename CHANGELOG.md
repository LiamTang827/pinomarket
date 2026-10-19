# Changelog

## v0.2 — 2026-10-19

- Add offline artifact auditing and independent market accounting.
- Export serviced-order openings for AEAD verification; never export waiting-order keys or signing private keys.
- Add duplicate, corrupt-signature and dropped-delivery cases, metrics, JSON scenarios, and a batch demo.
- Bind public contexts to public policy and a fresh session, excluding secret workload inputs.
- Pin vault member keys; reject unsafe virtual-time bounds and malformed seal inputs.
- Reject internally impossible negative-time or execution-before-opening traces.
- Add Chinese development and maintainer documentation with a reproducible validation summary.
- Remains a single-process model with ideal finality and key release, not threshold encryption or BFT consensus.

## v0.1

- Initial Go simulation with signed encrypted orders, promises, registration, service queue, fixed-price market, evidence verification and semantic replay.
