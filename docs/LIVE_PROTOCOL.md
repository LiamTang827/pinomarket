# Pinocchio v0.3: local multi-process protocol

Implementation record: 2026-10-19. See [the detailed Chinese protocol and operating guide](LIVE_PROTOCOL.zh-CN.md). `network` runs real processes; the existing `run` command retains the v0.2 simulator.

## Implemented path

Five independent OS processes run HTTP admission endpoints and CometBFT v0.38.26 validators. Each loads its own application signing key, validator identity, threshold secret share and durable state. Threshold encryption uses Shutter shlib v0.1.19, BLS12-381 identity-based encryption and pairing-verified shares. There is no ideal finality coordinator or ideal key vault in this path.

1. Initialize a public manifest, validator genesis, wallet keys and threshold configuration.
2. A user signs the order and header, encrypts them with a fresh AES-GCM key, threshold-encrypts that key under a label binding the header and encrypted body, and signs the complete envelope.
3. Admission nodes validate the public envelope and committed round/quota, persist a signed promise before replying, and gossip public signed receipts. Exact retries return the same promise.
4. At the committed closing height, members seal signed complete lists. CometBFT commits those lists. Registration selects the first `q` committed distinct-member lists, takes their union, removes duplicates/conflicting owner-nonce references, deterministically orders it, and appends it to the existing queue.
5. A committed lock fixes the exact next queue prefix. Only then does each node generate and submit its own authenticated decryption shares for that prefix.
6. Once each selected order has `t` distinct valid shares, every validator reconstructs the order-specific decryption capability, recovers the AES key, verifies the inner authorization, and executes the fixed sequence. Invalid encrypted payloads receive a deterministic failure result. Missing shares leave the service waiting.
7. Signed promises contradicted by a member's signed complete list can be submitted as omission evidence. No automatic economic penalty is implemented.
8. The audit client replays committed commands, verifies an actual signed CometBFT header authenticating the state hash, checks threshold openings, and independently reconciles market accounting. Replay shares the protocol transition code and is not an independent proof that the protocol rules are correct.

Default parameters: `n=5`, `f=1`, `q=4`, `t=3`, waiting capacity `Qmax=30`, service prefix `C=2`, admission window 30 committed blocks. At round opening each member receives `M=floor((Qmax-U)/n)` admissions, where `U` includes the active uncompleted prefix. Thus even disjoint member lists fit the reserved queue capacity. Historical storage remains unbounded.

Quorum promises suffice for inclusion under the stated assumptions: the promise signers and chosen list signers intersect in at least `2q-n-f > 0` honest members. The user must not submit conflicting envelopes with the same owner and nonce. Registration may also include orders present in a valid selected list without a full quorum receipt; quorum certification is sufficient, not an exclusive admission filter. Within-round `(owner,nonce,id)` sorting is a placeholder and does not provide arrival fairness.

## Run

Requires Go 1.23 or newer and a C compiler for `blst`; tested locally with Go 1.27.2. The first build downloads pinned dependencies.

```bash
./scripts/network-demo.sh runs/my-v03-test offline
```

The script builds, provisions five processes, stops one validator, submits three orders, audits results and cleans up its own child processes. Use a new output directory each time. Other modes are `normal`, `omission`, and `withhold`; their fault switches are described in the Chinese guide. Default P2P/RPC/API ports are `26656+10i`, `26657+10i` and `28000+i` for `i=0..4`. Run one default cluster at a time.

For manual operation, build `bin/pinocchio`, run `network init -dir runs/manual`, start one `network node -config runs/manual/nodeN.json` process for each `N=0..4`, then use `network ready`, `open`, `submit`, `wait`, `status`, and `audit`, each with `-dir runs/manual`. Preserve the same node directory and anti-double-sign state when restarting. Resend the original receipt with `submit -packet PATH` instead of re-encrypting an owner-nonce command. See the Chinese guide for complete copyable commands.

`audit.json` contains verified counts and market state. Receipt files contain public ciphertexts and signatures. The run directory also contains private wallet/validator/threshold keys: do not publish the entire directory. Generated keys, binaries and runs are Git-ignored.

## Verified behavior

The ordinary suite passed 37 top-level tests and 62 subtests, with three gated/helper tests skipped and no failures; `go vet ./...` passed. The gated real-process test was separately enabled and passed:

```bash
PINOCCHIO_LIVE_INTEGRATION=1 ./scripts/go.sh test ./internal/live -run '^TestLiveNetworkProcessesRestartAndOmission$' -count=1 -timeout=150s -v
```

It covers one stopped validator, a promise signer's restart before list closure, identical durable receipts after restart, three trades, a returning validator catching up without duplicate effects, and a second round with a signed omission and a normal `no_inventory` business result. The offline demo script was also run successfully. Both audits verify actual finality signatures, threshold openings and market accounting. These are functional checks, not performance benchmarks or formal security proofs. See [validation-v03.json](validation-v03.json).

## Deployment and research limits

`RunLocalDKG` uses genuine per-party DKG state machines, but relays all ceremony messages inside one initializer which can access all output shares. It is trusted local provisioning, not an independently administered authenticated distributed ceremony. The runtime does not reconstruct a long-term scalar secret; threshold shares yield an identity-specific decryption key. Processes on one machine under one OS user are not host-level security isolation.

The implementation binds to loopback and has no public service deployment, dynamic validator membership, externally settled assets, fee auction, fund reservation, slashing or globally fair arrival order. Public metadata remains visible. More than the assumed faulty participants may stop consensus; a threshold collusion may reveal contents early. Missing shares have no timeout bypass. `-delay-ms` affects admission only, not arbitrary P2P network latency. The market is a fixed-price, pre-funded seller inventory model, not a full prediction exchange or oracle.

The value of this version is an executable end-to-end research baseline. Novelty and comparative guarantees remain research questions. Shutter and CometBFT are credited in [third party notices](../THIRD_PARTY.md).
