# v0.2 runnable protocol model

[Detailed Chinese walkthrough](PROTOTYPE.zh-CN.md)

This is a single-process Go research model with a virtual network. It implements
real Ed25519 signatures and AES-GCM order encryption, signed admission promises,
complete local lists, an append-only cross-round queue, service-prefix locking,
conditional opening, buy/cancel execution, evidence verification and semantic replay.

**It does not implement threshold encryption or BFT consensus.** `IdealVault`
centrally stores complete AES keys and checks signed release approvals; these are
not decryption shares. Common registration and finality are ideal coordinator
operations. Every member publishes a final list; crash recovery is not implemented.

## Run

Requires Go >=1.23; standard library only. Run from the repository root:

```sh
./scripts/go.sh test ./...
./scripts/go.sh run ./cmd/pinocchio run -scenario normal -out runs/normal-01
./scripts/go.sh run ./cmd/pinocchio run -scenario omission -out runs/omission-01
./scripts/go.sh run ./cmd/pinocchio verify -file runs/omission-01/evidence.json
./scripts/go.sh run ./cmd/pinocchio replay -file runs/normal-01/report.json
```

Output directories must be new. Additional scenarios: `delay`, `refusal`,
`equivocation`, `late`, `capacity`, `funds`, `cancel`, `duplicate`, `corrupt`, `drop`. A `-config path.json` file
overrides the built-in configuration. See `scenarios/normal.json` for the schema.

Outputs: `report.json`, `events.jsonl`, and `evidence.json`. Reports include
plaintext scenario inputs for replay; they are not privacy-preserving production
logs. Private signing keys and keys of unserved orders are not exported. Keys of serviced orders are included in `openings` for independent AEAD verification.

Evidence verification checks signed contradictions against supplied scenario
public keys, not their real-world identity or evidence completeness. Replay
compares semantic events/results/state using fresh cryptographic randomness;
it does not authenticate every field of an old report.

Within-round sorting is a public owner/nonce/digest placeholder, not arrival
fairness. The queue has no total cap or bounded waiting guarantee. Admission and
service capacity are bounded. Funds are checked only during execution; unfunded
orders can consume processing capacity. There are no fees, bonds, slashing,
external-chain settlement, automated retries or production fault tolerance.

## v0.2 artifact audit

```sh
./scripts/go.sh run ./cmd/pinocchio audit -file runs/omission-01/report.json
./scripts/demo.sh runs/my-v02-suite
```

The offline auditor checks signatures, certificates, exact FIFO prefixes, released
keys and plaintext authorizations, then independently recomputes market outcomes
without running the simulator or execution engine. It relies on supplied scenario
keys, not an authenticated chain. Metrics count simulated events, not measured
network performance. Public contexts bind only public policy and a random session;
secret scenario inputs are not hashed into the public context.
