# pinomarket

**English** · [简体中文](README.zh-CN.md) · [Protocol guide](docs/LIVE_PROTOCOL.md)

pinomarket is a Go research prototype for timing evidence and ordered execution of encrypted transactions. Independent local nodes agree on a service order before revealing the transaction contents. A simple market supplies the execution workload.

1. **Encrypt and submit.** A wallet signs and encrypts a transaction, then sends the ciphertext to an ingress node.
2. **Record and order.** Peers calibrate latency with signed challenges and check the ingress timestamp. The client submits the ciphertext and timing certificate to multiple validators for admission. Within each registered round, certificate time determines order.
3. **Lock and reveal.** CometBFT finalizes the selected transactions and their exact order. Nodes release verifiable decryption shares. The transactions are processed in the locked order once the threshold is reached.

The ingress and clock components are software stand-ins. Signatures let peers check who issued a record and what it covers. Hardware-backed TEE/TNIC ingress, trusted time, and remote attestation require a separate hardware integration.

## Run locally

Install Go and a C compiler. The first build downloads pinned dependencies.

```sh
bash scripts/network-demo.sh runs/first-demo
./scripts/go.sh test ./...
```

Use a fresh run directory each time. The run directory also contains private keys. Share individual public receipts or audit results as needed.

## Anvil MEV evaluation

The local experiment compares plaintext swaps with encrypted orders executed by a signature-verified EVM batch. See the [evaluation and reproduction guide (Chinese)](docs/ANVIL_EVALUATION.zh-CN.md) for commands, receipt checks, and performance metrics.

## Code map

| Location | Responsibility |
| --- | --- |
| [internal/live](internal/live) | Nodes, ingress records, timing evidence, consensus state, and execution audit |
| [threshold](threshold) | Threshold encryption and decryption shares using Shutter shlib |
| [scripts/network-demo.sh](scripts/network-demo.sh) | Start the local validators, submit ciphertexts, and audit execution |

[Roadmap](ROADMAP.md) · [Third-party software](THIRD_PARTY.md)
