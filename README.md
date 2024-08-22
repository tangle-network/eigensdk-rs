# EigenSDK-RS

[![Validate PR](https://github.com/webb-tools/eigensdk-rs/actions/workflows/validate_pr.yml/badge.svg)](https://github.com/webb-tools/eigensdk-rs/actions/workflows/validate_pr.yml)
[![Rust Version](https://img.shields.io/badge/rust-1.74.0%2B-blue.svg)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/Apache-2.0)

---

`eigensdk-rs` is a Rust SDK for interacting with Eigenlayer and building AVS tooling. Additionally, it incorporates features for interacting with Tangle and utilizing our [gadget](https://github.com/webb-tools/gadget), an augmented SDK for building task based AVS. Together, these two offer a comprehensive solution for building applications with both Eigenlayer and Tangle. This SDK is a high-performance, reliable, and efficient library that integrates seamlessly with Eigenlayer's ecosystem while leveraging the many advantages of Rust.

It should be noted that this SDK is still being actively developed and has not undergone a professional audit. Please use at your own risk in production.

---
## Table of Contents
- [**Features**](#features)
- [**Getting** Started](#getting-started)
    - [**Installation**](#installation)
- [**Building**](#building)
- [**Usage**](#usage)
  - [**Running an AVS**](#running-an-avs)
- [**Testing**](#testing)
    - [**Running the Included Tests**](#running-the-included-tests)
    - [**Testing Custom Implementations**](#testing-custom-implementations)
- [**Documentation**](#documentation)
- [**Contributing**](#contributing)
  - [**License**](#license)

---
## Features

- **Full Eigenlayer Integration**: Provides all the robust functionalities of eigensdk-go, now with the performance benefits of Rust.
- **Seamless Tangle Interoperability**: Easily integrates Tangle into Eigenlayer AVSs, allowing a Tangle Validator to live in an AVS.
- **Unlimited Customization**: Equipped with all the tools needed to build custom AVSs, including those that leverage our advanced Gadget capabilities.
- **High Performance**: Developed with Rust to deliver superior efficiency and speed, ensuring your applications run optimally.
- **Enhanced Type Safety**: Takes advantage of Rust's strong type system to create more reliable and maintainable code.
- **Advanced Concurrency**: Utilizes Rust's concurrency model to enable safe and efficient multi-threaded operations.
- **Go Implementation Compatibility**: Achieves full feature parity with the Go version, facilitating straightforward porting of applications from Go to Rust.
- **Comprehensive API Access**: Provides complete access to all Eigen network functionalities, empowering developers to fully exploit the platform's potential.

---
## Getting Started

### Installation

Clone the repository:

```bash
git clone https://github.com/webb-tools/eigensdk-rs/
cd eigensdk-rs
```

---
## Usage

### Building
```bash
cargo build --release
```
or to use EigenSDK-RS in your own Rust project, just add the following dependency to your `Cargo.toml`:
```toml
[dependencies]
eigensdk-rs = { git = "https://github.com/webb-tools/eigensdk-rs" }
```

### Running an AVS
To programmatically start an AVS operator:

1. Create a new operator, supplying the necessary inputs (dependent upon the AVS you are running). The following is a general example that a real implementation would closely follow. The config is dependent upon the AVS you are running.
```rust
let operator = Operator::new_from_config(
	config,
	http_provider,
	ws_provider,
	operator_info_service,
	signer,
)
.await?;
```
2. With the operator, simply run the start function:
```rust
operator.start().await?;
```
---
## Testing
This repository both contains tests for the included AVSs and provides the tools necessary to test custom AVSs you build with this SDK.

### Running the included tests
To run the tests from the command line, you can run the following commands in the root directory:

1. You can manually build all smart contracts, though there are build scripts to automatically build them.

```bash
./test-utils/scripts/build.sh
```

2. Set the environment variables for running the tests.

```bash
. ./test-utils/scripts/env_setup.sh
```

3. Run the test for the AVS you would like to test.

Tangle AVS
```bash
cargo test -p test-utils test_tangle_full
```
Incredible Squaring AVS
```bash
cargo test -p test-utils test_incredible_squaring_full
```

These full tests start a local Anvil testnet, deploy all the required contracts to it, and then start an operator.

### Running the Testnets as binaries

1. Build
```bash
cargo build --release
```

2. Run

Incredible Squaring AVS's Testnet
```bash
./target/release/incredible-squaring
```

Tangle AVS'sTestnet
```bash
./target/release/tangle
```

---
## Contributing

To contribute:

1. Fork the repository.
2. Create a new branch.
3. Make your changes and ensure tests pass.
4. Submit a pull request with a detailed description of your changes.

## License
Gadget is licensed under either of the following:
* Apache License, Version 2.0
  ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
* MIT license
  ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)
