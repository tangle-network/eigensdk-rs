# EigenSDK-RS

[![Validate PR](https://github.com/webb-tools/gadget/actions/workflows/validate_pr.yml/badge.svg)](https://github.com/webb-tools/gadget/actions/workflows/validate_pr.yml)
[![Rust Version](https://img.shields.io/badge/rust-1.74.0%2B-blue.svg)](https://www.rust-lang.org)
---

[//]: # ([![License]&#40;https://img.shields.io/badge/License-MIT-blue.svg&#41;]&#40;https://opensource.org/licenses/Apache-2.0&#41;)

[//]: # (---)

EigenSDK-RS is a Rust implementation of Layr-Lab's eigensdk-go. Additionally, it incorporates features for interacting with Tangle and utilizing Gadgets, offering a comprehensive solution for building applications with both Eigenlayer and Tangle. This SDK is a high-performance, reliable, and efficient library that integrates seamlessly with Eigen's ecosystem while leveraging the many advantages of Rust.

It should be noted that this SDK is still being actively developed.

---
## Table of Contents
- [**Features**](#features)
- [**Getting** Started](#getting-started)
    - [**Installation**](#installation)
    - [**Running an AVS**](#running-an-avs)
- [**Testing**](#testing)
    - [**Running the Included Tests**](#running-the-included-tests)
    - [**Testing Custom Implementations**](#testing-custom-implementations)
- [**Documentation**](#documentation)
- [**Contributing**](#contributing)

[//]: # (- [**License**]&#40;#license&#41;)

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

Build the project:

```bash
cargo build --release
```

To use EigenSDK-RS in your own Rust project, just add the following dependency to your `Cargo.toml`:
```toml
[dependencies]
eigensdk-rs = { git = "https://github.com/webb-tools/eigensdk-rs" }
```

### Running an AVS
To programmatically start an AVS operator:

1. Create a new operator, supplying the necessary inputs (dependent upon the AVS you are running). The following is a general example that a real implementation would closely follow:
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
To run the tests, use the following command inside the root directory of the AVS you would like to test:
```bash
RUST_LOG=info cargo test test_anvil
```
This test starts a local Anvil testnet, deploys all the required contracts to it, and then starts an operator.

### Testing custom implementations
We include testing utilities that make it easy to run tests for custom implementations. These tools are currently in development.

---
## Contributing

To contribute:

1. Fork the repository.
2. Create a new branch.
3. Make your changes and ensure tests pass.
4. Submit a pull request with a detailed description of your changes.

[//]: # (## License)

---
## Contact

If you have any questions or need further information, please contact the developers [here](https://webb.tools/)