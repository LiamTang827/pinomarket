# Third party notices

The adapter calls these upstream packages without modifying their source. Copies of upstream license texts are in `licenses/`.

| Module | Pinned version | Used component | Upstream license |
| --- | --- | --- | --- |
| github.com/shutter-network/shutter/shlib | v0.1.19 | puredkg, shcrypto | MIT, Copyright 2021 Brainbot Technologies AG, Germany |
| github.com/supranational/blst | v0.3.16 | Go bindings, BLS12-381 arithmetic | Apache License 2.0 |
| github.com/ethereum/go-ethereum | v1.13.4 | common/hexutil, indirectly through shcrypto encoding | GNU LGPL version 3 or later, Copyright 2016 The go-ethereum Authors |
| github.com/pkg/errors | v0.9.1 | puredkg error handling | BSD 2-Clause, Copyright 2015 Dave Cheney |
| golang.org/x/crypto | v0.33.0 | sha3 through shcrypto | BSD 3-Clause, Copyright The Go Authors |
| golang.org/x/sys | v0.30.0 | CPU feature detection used by x/crypto | BSD 3-Clause, Copyright The Go Authors |

Upstream sources:

- https://github.com/shutter-network/shutter/tree/shlib/v0.1.19/shlib
- https://github.com/supranational/blst/tree/v0.3.16
- https://github.com/ethereum/go-ethereum/tree/v1.13.4/common/hexutil
- https://github.com/pkg/errors/tree/v0.9.1
- https://go.googlesource.com/crypto/+/refs/tags/v0.33.0
- https://go.googlesource.com/sys/+/refs/tags/v0.30.0

The Go standard library and compiler toolchain are separately distributed under their own licenses. Additional dependencies used only by upstream tests are recorded in `go.sum` when present; the table lists the crypto adapter dependencies selected by the repository's combined go.mod. It is not an exhaustive inventory of the consensus adapter's transitive dependencies; see ../THIRD_PARTY.md.

This notice records the license statements found in the downloaded pinned source. It does not assert that a finished product has satisfied all distribution obligations.
