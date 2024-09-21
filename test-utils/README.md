# EigenSDK-RS Test Utilities

[![Validate PR](https://github.com/webb-tools/eigensdk-rs/actions/workflows/validate_pr.yml/badge.svg)](https://github.com/webb-tools/eigensdk-rs/actions/workflows/validate_pr.yml)
[![Rust Version](https://img.shields.io/badge/rust-1.74.0%2B-blue.svg)](https://www.rust-lang.org)
---

## Overview

Utilities designed to streamline and enhance the testing process of EigenSDK-RS and any projects that utilize it. 

## Getting Started

To use `test-utils` in your own workspace, add it as a dev-dependency. Using these tools in EigenSDK-RS work out-of-the-box:

```toml
[dev-dependencies]
test-utils = { path = "https://github.com/webb-tools/eigensdk-rs/tree/main/test-utils" }
```
## Features

---
### Scripts

To automatically set the Environment variables required for testing:
```bash
. ./scripts/env_setup.sh
```

If you are building your own AVS, you may be frequently rebuilding your Contracts. You can automatically clean and rebuild the contracts in `/contracts` with:
```bash
./scripts/rebuild_contracts.sh
```
To rebuild the contracts in the AVS directory:
```bash
./scripts/rebuild_contracts.sh
```

---

### Test Binaries

To run the included Testnet as a binary, build the project and then run the testnet:
```bash
cargo build -r
./target/release/incredible-squaring
```


---

### Cargo tests

To run the test for the included AVS (from the test-utils directory):

#### Incredible Squaring
```bash
# To run the testnet and test connecting an Operator to it
cargo test -p test-utils test_incredible_squaring_full
```
