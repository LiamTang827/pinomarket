# pinomarket protocol

[Project home](../README.md) · [中文](LIVE_PROTOCOL.zh-CN.md)

## Participants and trust boundary

Wallets sign and encrypt transactions. Validators issue admission and timing evidence, participate in consensus, and each hold a threshold decryption share. The five-node local configuration sets the fault parameter to `f = 1`, requires `q = 4` signatures for timing certificates and `q = 4` lists for registration, and requires `t = 3` valid shares to decrypt. Local key provisioning coordinates the participants' key generation and has access to their shares.

The ingress component signs admission records and round snapshots. The software implementation uses host-accessible signing keys and a host clock. A hardware implementation must bind its keys to attested code, establish trusted time, prevent rollback, and define how arrivals reach protected code.

## Transaction flow

1. **Encrypt.** The wallet encrypts the signed transaction with a fresh symmetric key, protects that key using the committee public key, and signs the public header and ciphertext envelope.
2. **Certify time.** The client obtains timing evidence through an ingress node. Signed nonce challenges calibrate estimated communication delay. Peers check the claimed time against the adjusted observation and configured tolerances. The certificate binds the network context, round, ingress node, ciphertext identifier, and endorsed time.
3. **Admit and register.** The client submits the ciphertext and certificate to multiple nodes. Each validates the public materials and admission quota, records its local acceptance, and signs a receipt. At round closure, validators seal the lists from their logs. Consensus selects the lists, verifies the attached evidence, and registers the deduplicated transactions.
4. **Order.** Registered rounds retain queue order. Transactions within a round sort by certified timestamp and then ciphertext identifier. For multiple valid certificates on one ciphertext in the selected lists, the earliest timestamp wins, with the certificate hash as a tie-breaker.
5. **Lock, reveal, and execute.** CometBFT finalizes the exact ordered prefix to serve. The lock identifier commits to its ordered ciphertext identifiers. Nodes then publish verifiable decryption shares for that lock. Once the required shares are present, validators recover the symmetric keys, verify authorization, and apply transactions in the locked order.

In this commit–reveal flow, consensus commits the ordered ciphertext prefix and the committee reveals it through threshold decryption. The client can retain the signed admission receipts without returning to reveal a key or upload the receipts.

## Timing and capacity

The timing flow draws on Aion's latency challenge and correction approach. A verifier estimates delay `d` by subtracting the signed challenge reply timestamp from its local response arrival time. The verifier endorses an origin's claim `s` only if its local receive time `r` satisfies `abs((r - d) - s) <= δ + ε`, where `δ` and `ε` are configured clock skew and delay variation tolerances. The proof contains the signed claim and the verifiers’ signed receive times and delay estimates. Verifiers check the challenge exchange locally. The origin records `s` after calibration. The client can hold a proof and submit it later within the same round. That wait does not affect the certified timestamp. That timestamp cannot establish when the client first sent the transaction. The original paper's guarantees do not carry over to this implementation. [Aion paper](https://gramoli.github.io/pubs/ESORICS23-Aion.pdf)

At the start of a round, each of the `n` nodes can accept up to `floor((Q - U) / n)` ciphertexts, where `Q` is queue capacity and `U` is occupied space. This reserves room even when the accepted lists are disjoint. Duplicate entries and unused quota can leave space unfilled.

A certificate carries `q` endorsements. Sending it to up to `n` validators replicates up to `n × q` endorsement signatures in the client admission step. An origin also requests calibration and votes from multiple validators. An origin–verifier pair can reuse its pinned delay estimate within the same round. Parallel requests share a wait, while signed lists, consensus, and decryption each add separate traffic.

A host can delay or discard transactions before the software admission boundary. A host with access to simulated signing keys can also forge records. When the network stalls or valid shares are unavailable, progress can stall. A successful admission, registration, lock, and market fill are separate outcomes.

The node endpoint `/metrics` counts requests and HTTP body bytes for the four timing routes. Consensus traffic and network framing require separate measurements.

## Run and inspect

```sh
bash scripts/network-demo.sh runs/first-demo
./scripts/go.sh test ./...
```

Use a new output directory. The demo launches local validators, submits encrypted orders, and writes receipts and `audit.json`. The audit replays the committed state and checks consensus signatures, threshold openings, and execution state. The directory also contains private keys and secret shares. Share individual public files as needed.

To configure nodes by hand, build `./cmd/pinocchio` and run `network init -dir runs/manual -ordering aion -ingress software`. Use `network init -h` for configuration options.

When `submit` receives an `-out` path, it saves the certified packet before asking nodes for admission. To retry the same packet and proof, pass the saved file to `submit -packet` and use a new `-out` path.
