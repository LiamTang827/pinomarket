# Threshold cryptography adapter

This package uses Shutter `shlib/puredkg` v0.1.19 for per-party distributed key generation and `shlib/shcrypto` for BLS12-381 identity based encryption, pairing verification of decryption shares, and interpolation. It does not construct a global private key. The adapter is experimental and has not been audited.

`DKGParty` is a transport-independent single participant state machine. Run it in a separate node process for a deployed ceremony. Transport must authenticate the sender, deliver commitments/complaints/apologies by consistent broadcast, and encrypt each private evaluation to its designated recipient. The eon must uniquely name the agreed participant list and threshold. Advance each phase only at an agreed round barrier or deadline. Agree on the resulting complete `PublicConfig.ID` before using the key. The state machine does not implement consensus or reliable broadcast.

`RunLocalDKG` drives the real per-party DKG state machines in one process for local setup and tests. That setup process temporarily sees every party's private state. It therefore models a trusted local provisioning ceremony and must not be described as a deployed distributed ceremony. Keep each resulting `SecretShare` only at its node and protect it as a private key. Go does not guarantee memory erasure.

`Encrypt` creates a fresh random identity nonce for each ciphertext. The Shutter identity is domain separated and binds the public config, application label, and nonce. `VerifyDecryptionShare` checks the BLS pairing against that identity and the party verification key. Each share envelope also includes the complete ciphertext digest. The digest is metadata, not a node signature: the application's signed release message must authenticate the whole share envelope and the release authorization. Shutter's ciphertext integrity check detects modifications to the encrypted body during `Decrypt`, including when an attacker rewrites unsigned digest metadata. Applications must check their expected label; a label can commit to a public header and an AES-GCM payload hash.

`ValidateCiphertext` checks format, canonical serialization, subgroup membership and configuration binding. It cannot prove the encrypted plaintext has a particular format or that a maliciously constructed ciphertext will decrypt. Such claims require an additional proof system or decryption-time validation.

Threshold interpolation never reconstructs the long-term scalar secret. It produces an identity-specific epoch key. Once a threshold releases shares for an identity, anyone can decrypt ciphertexts under that identity. Release policy and Byzantine fault tolerant sequencing belong to the application protocol.

Dependencies are pinned. Shutter v0.1.19 requests `blst` v0.3.11; this module explicitly uses the published `blst` v0.3.16 release for compatibility with the installed Go compiler.
