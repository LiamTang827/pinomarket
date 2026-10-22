# Third party software

The optional median-receipts experiment is original project code inspired by [AOAB (DSN 2024)](https://gramoli.github.io/pubs/DSN24_AOAB_preprint.pdf). Experiment organization also draws on the public [Isotaxis artifact](https://github.com/xrxrxrxrxr/Isotaxis-ArtifactEvaluation). No upstream Rust source or plotting data is bundled; these references do not imply that pinomarket implements either complete protocol or inherits its guarantees.

The v0.3 network path uses upstream implementations rather than custom implementations of consensus or threshold cryptography.

- **CometBFT v0.38.26**: consensus, validator signatures, peer networking, WAL and block storage. Apache-2.0; source notices are retained in [LICENSE](docs/licenses/CometBFT-LICENSE) and [NOTICE](docs/licenses/CometBFT-NOTICE). Upstream: https://github.com/cometbft/cometbft/tree/v0.38.26.
- **Shutter shlib v0.1.19**: `puredkg` and `shcrypto`. MIT. The threshold adapter and its crypto runtime dependencies are documented in [threshold/THIRD_PARTY.md](threshold/THIRD_PARTY.md), with license texts in `threshold/licenses/`.
- **blst v0.3.16**: BLS12-381 arithmetic and Go bindings. Apache-2.0. This explicit version overrides the older version requested by shlib for compiler compatibility.
- **Viper v1.19.0**: CometBFT configuration loading. MIT; see the downloaded module's `LICENSE`.

The complete selected Go module graph is recorded by `go.mod` and checksums by `go.sum`; the table above is not an exhaustive license inventory of CometBFT's transitive dependencies. Dependency license statements and distribution obligations should be reviewed before redistributing a product or binary. No claim is made here that a production distribution has fulfilled every obligation. The project has not yet selected a license for its own source code.
