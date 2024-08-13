use std::env;
use std::path::Path;
use std::process::Command;

fn main() {
    // List of directories containing Solidity contracts
    let contract_dirs = vec![
        "contracts",
        "contracts/lib/eigenlayer-middleware",
        "avs/incredible-squaring-avs/contracts",
    ];

    // Get the project root directory
    let root = env::var("CARGO_MANIFEST_DIR").unwrap();

    for dir in contract_dirs {
        let full_path = Path::new(&root).join(dir);

        if full_path.exists() {
            println!("cargo:rerun-if-changed={}", full_path.display());

            let status = Command::new("forge")
                .current_dir(&full_path)
                .arg("build")
                .status()
                .expect("Failed to execute Forge build");

            if !status.success() {
                panic!("Forge build failed for directory: {}", full_path.display());
            }
        } else {
            println!("Directory not found: {}", full_path.display());
        }
    }
}
