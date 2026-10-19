# Pinocchio

**English** | [简体中文](README.zh-CN.md)

**Make promises checkable. Make markets replayable.**

Pinocchio is a market attack-and-defense research project in the design stage. We plan to build an interactive prediction-market environment where users can follow orders through propagation, admission promises, queuing, decryption, and execution, and check whether nodes violate their signed statements.

## Why Pinocchio?

Network delays can cause nodes to receive transactions in different orders. Different views alone are not evidence of lying. However, conflicting statements signed for the same round, or a complete published list that contradicts a node's admission promise, may provide verifiable evidence.

We want these contradictions to be visible, like Pinocchio's nose. Here, “lying” means a verifiable statement that violates an explicit rule; it does not mean guessing a node's motives.

## A scenario

Alice learns a match result at the venue and submits an order to buy YES shares. Meanwhile:

- Bots may observe public orders and submit competing orders.
- Sellers may cancel inventory that has not yet been traded.
- Nodes may receive messages in different orders.
- Limited admission and processing capacity may leave orders waiting.

The project aims to replay the same scenario under different visibility, admission, and processing rules, then compare order outcomes and system overhead.

## Planned components

| Component | Purpose |
|---|---|
| Market simulation engine | Process purchases, cancellations, balances, and inventory, recording deterministic state changes |
| Message and node model | Represent propagation delays, signed promises, and node failures |
| Protocol adapters | Compare public orders, encrypted orders, and candidate admission rules |
| Evidence checker | Check explicitly defined violations, such as conflicting statements and omitted promised orders |
| Interactive replay interface | Display order timelines, node views, and verifiable evidence |

## Current status

**v0.2 now includes a runnable Go protocol model.** It uses real signatures and AES-GCM, with simulated networking, ideal common finality, and an ideal key vault. **It does not implement threshold encryption or BFT consensus.**

New in v0.2: offline artifact auditing, independent market accounting, duplicate/corrupt/dropped-message cases, and metrics.

See the [prototype guide](docs/PROTOTYPE.md) or [中文运行说明](docs/PROTOTYPE.zh-CN.md).

- [x] Document the project scope and roadmap.
- [x] Define v0.2 messages, state transitions, and signed evidence formats.
- [x] Implement a minimal market and replayable event engine.
- [x] Implement promise/list consistency checks and attack scenarios.
- [ ] Add real multi-process nodes and cryptographic components.
- [ ] Add an interactive interface and reproducible comparisons.

Earlier ordering and AMM experiments remain in a separate research directory. They have not been imported here and do not implement the full proposed encrypted-admission protocol. There are no new performance results, formal security proofs, or established novelty claims at this stage.

## Development records

- [Development report (Chinese)](docs/DEVELOPMENT_REPORT.zh-CN.md)
- [Go learning and maintenance guide (Chinese)](docs/LEARNING.zh-CN.md)
- [v0.2 validation record](docs/validation-v02.json)

## Getting started

1. Read the [design scope (Chinese)](docs/SCOPE.md) to understand what each stage protects.
2. Read the [roadmap (Chinese)](ROADMAP.md) for the planned first version.
3. For help using GitHub, see the [beginner guide (Chinese)](docs/GITHUB_GUIDE.zh-CN.md).
4. Run the Go model (Go >=1.23; standard library only):

```sh
./scripts/go.sh test ./...
./scripts/go.sh run ./cmd/pinocchio run -scenario normal -out runs/normal-01
./scripts/go.sh run ./cmd/pinocchio run -scenario omission -out runs/omission-01
./scripts/go.sh run ./cmd/pinocchio verify -file runs/omission-01/evidence.json
```

Use a new output directory for each run. These are functional scenarios, not measured security or performance results.

## Research boundaries

- Encryption hides contents; it does not automatically guarantee fair admission or the first fill.
- Signatures establish what a node stated, not its actual message arrival time.
- A timeout or a different reception order alone is not evidence of lying.
- Withholding before a node produces its first record remains a research limitation.
- Idealized cryptographic operations in simulation will be distinguished from real implementations.

## Related work and reference projects

This project draws on encrypted transactions, inclusion guarantees, accountable systems, and market simulation. Existing mechanisms will be attributed to their sources.

- [Shutter + Primev public design](https://ethresear.ch/t/threshold-encrypted-mempools-with-mev-commit-preconfirmations/23588) and [primev-sequencer prototype](https://github.com/shutter-network/primev-sequencer): encrypted transactions and inclusion commitments.
- [Rolling Shutter](https://github.com/shutter-network/rolling-shutter): threshold-encryption infrastructure.
- [AOAB](https://gramoli.github.io/pubs/DSN24_AOAB_preprint.pdf): transaction ordering, common output, and inclusion guarantees.
- [PeerReview](https://www.sigops.org/s/conferences/sosp/2007/papers/sosp118-haeberlen.pdf): signed logs and distributed-system accountability.
- [ABIDES](https://github.com/abides-sim/abides): multi-agent market and message-delay simulation.

## License

An open-source license has not been selected yet. Before reusing third-party code, its license must be checked and attribution retained.
