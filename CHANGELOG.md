# Changelog

## Unreleased — 2026-10-21

- Add a standard-library Python process harness with validated model tools, JSONL transport and a provider-neutral bounded agent loop.
- Support per-node lifecycle and fault restarts, structured measurement/audit results, action logs and owned-process cleanup.
- Add unit tests, an opt-in real five-node smoke test and a Chinese model integration guide.

## Unreleased — 2026-10-20

- Add optional median-receipts reference ordering from signed, durable local admission observations, with explicit sparse-evidence fallback and independent ordering audit.
- Add network measure and paired local normal/fault experiment orchestration with raw-metric aggregation and incomplete-work accounting.
- Select the freshest responsive committed snapshot for real-network audits before verifying replay and validator signatures.
- Add tests for signed sequences, persistence, deterministic median output, fallback, audit tampering and measurement denominators. The extension is not a full AOAB implementation.

## v0.3 — 2026-10-19

- Add a separate `network` mode with independent local node processes, loopback HTTP transport, durable admission journals, and per-node state.
- Integrate CometBFT v0.38.26 and ABCI++ for real validator consensus, finality, restart, and catch-up.
- Integrate Shutter shlib v0.1.19 BLS12-381 threshold encryption with ciphertext-bound identities and verifiable decryption shares; pin blst v0.3.16 for the installed Go toolchain.
- Implement consensus-backed admission rounds, signed complete lists, union registration, bounded queue admission, queue-prefix locks, authenticated share transactions, and deterministic execution.
- Persist promises before replying; bind consensus commands to their round, service number, queue head, or lock to prevent replay.
- Record verifiable promise/list omission evidence without treating insufficient funds or inventory as protocol violations.
- Add network initialization, node, ready, open, submit, wait, status, and audit commands; add `scripts/network-demo.sh` for normal, offline, omission, and share-withholding runs.
- Audit real signed consensus commits, replay committed blocks, verify threshold openings, and independently recompute market accounting.
- Pass an actual five-process integration test covering promise persistence across restart, progress with one validator offline, catch-up without duplicate effects, and omission evidence.
- Preserve the v0.2 simulator as a separate baseline. Local DKG provisioning still exposes the output shares to the initializer; independent authenticated DKG deployment, economic penalties, production isolation, and performance evaluation remain future work.

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
