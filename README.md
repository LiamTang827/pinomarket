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

**This repository currently contains documentation only. There is no runnable Pinocchio prototype yet.**

- [x] Document the project scope and roadmap.
- [ ] Define messages, state transitions, and evidence formats for one order.
- [ ] Implement a minimal market and replayable event engine.
- [ ] Implement promise/list consistency checks and attack scenarios.
- [ ] Add real multi-process nodes and cryptographic components.
- [ ] Add an interactive interface and reproducible comparisons.

Earlier ordering and AMM experiments remain in a separate research directory. They have not been imported here and do not implement the full proposed encrypted-admission protocol. There are no new performance results, formal security proofs, or established novelty claims at this stage.

## Getting started

1. Read the [design scope (Chinese)](docs/SCOPE.md) to understand what each stage protects.
2. Read the [roadmap (Chinese)](ROADMAP.md) for the planned first version.
3. For help using GitHub, see the [beginner guide (Chinese)](docs/GITHUB_GUIDE.zh-CN.md).
4. Verified installation, execution, and experiment commands will be added when code is available.

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
