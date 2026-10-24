# Changelog

## Symbolic protocol cost analysis — 2026-10-25

- Derive submission, complete receipt dissemination, full-list, share-batch, control and evidence costs from actual message formats.
- Separate the backend cost function and explicitly conditional closed-form bounds from the current CometBFT implementation.
- Account for all supplied decryption shares, repeated configuration verification, retries, candidate filtering and retained state costs.
- Keep symbolic analysis separate from the finite local measurement report; no protocol code or experiments changed.

## Local overhead measurement — 2026-10-25

- Add passive per-route HTTP body counters and a local metrics endpoint, keeping protocol and observer traffic separate.
- Measure CometBFT sent-packet counter deltas, node CPU/RSS and observed stages; preserve counter continuity checks, failures and raw samples.
- Add actual cryptographic/API timing samples after stopping validator processes; retain nested-validation costs and operation details.
- Record four audited six-order local samples at five/eight nodes, one validation pilot, and four pre-workload collection failures.
- Document repeated receipt gossip, observation overhead and the limits of finite-load/per-order normalization.

## Repository documentation — 2026-10-24

- Reorganize the English and Chinese homepages around the research question, protocol flow, quick start, experiment results, and code map.
- Separate inclusion, locked order, and fill outcomes; document the limits of current adversarial samples and the lack of economic incentives.
- Link the presentation report, methods, source data, and prior-mechanism attribution.
- Run Python harness unit tests alongside Go checks in GitHub Actions.

## Frozen-protocol binary-pair experiment — 2026-10-23

- Add a live-model node-ratio experiment and focused classification tests without changing the protocol or executable.
- Record inclusion separately from relative order and processing, distinguish model failures from deliberate deviations, and pair runs with honest waiting controls.
- Preserve the original failed 50% attempt alongside one bounded complete rerun and its control; verify protocol fingerprints and public receipts.

## Scope correction — 2026-10-23

- Remove the unsolicited ordering extension, signed sequence controls and dependent experiment entry points.
- Restore the base deterministic placeholder; list frequency does not grant or remove ordering eligibility.
- Withdraw dependent experiment conclusions and preserve their source/data in a local archive. Adapt node agents to admission, list and share decisions only.


## Live node-model pilot — 2026-10-23

- Call independent bounded models at actual admission, list-preparation, and service events, with opaque trader labels and per-node histories.
- Add validated list choices, bounded callback timeouts, and optional asynchronous list preparation; later admissions are included normally.
- Add an independent live Bob decision, recorded explanations and failures, and matched-wait honest controls. Keep these results separate from precompiled-policy runs.

## Independent role-agent experiments — 2026-10-23

- Add private per-node Unix-socket decisions for admission, complete lists, and decryption shares; preserve the core consensus state machine.
- Add isolated GPT policy planning and reference agents, bounded Bob strategies, an eight-node experiment matrix, exact receipt verification, protocol audits, and CPU/RSS sampling.
- Separate model latency from timed execution and label beyond-fault-bound stress cases explicitly.

## Direct ChatGPT connection verified — 2026-10-23

- Complete real user authorization, protected credential storage and account-specific model discovery.
- Verify one direct GPT-6.1-Sol request through the model adapter; record sanitized timing, token counts and returned action without executing node tools.


## ChatGPT connection recovery — 2026-10-23

- Apply the documented five-second JWT clock tolerance while retaining all identity checks.
- Preserve the issued registration ID across incomplete sign-ins, and reuse saved connections without opening another login.
- Show success only after verified credentials are durably saved; callback pages no longer report premature success or automatically retry.


## Direct ChatGPT connection — 2026-10-23

- Add an optional direct ChatGPT-plan OAuth adapter with PKCE, ID-token validation, protected per-account storage and serialized rotating refresh.
- Add account model discovery, bounded Responses streaming, validated JSON action replies and token/latency telemetry.
- Add a connection-only smoke command that cannot execute harness actions. Real authorization and inference remain dependent on the account completing the official flow.


## Project rename — 2026-10-23

- Rename the project and GitHub repository to `pinomarket`; update Go module imports, repository links and bilingual documentation.
- Retain Pinocchio as the node character name and preserve existing CLI paths, cryptographic domain identifiers and archived experiment records.

## Unreleased — 2026-10-21

- Add a standard-library Python process harness with validated model tools, JSONL transport and a provider-neutral bounded agent loop.
- Support per-node lifecycle and fault restarts, structured measurement/audit results, action logs and owned-process cleanup.
- Add unit tests, an opt-in real five-node smoke test and a Chinese model integration guide.

## Withdrawn scope expansion — 2026-10-20

The entries below describe a removed extension, not the current base protocol. Its experiment conclusions are withdrawn.

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
