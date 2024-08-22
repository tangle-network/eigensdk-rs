use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    // List of directories containing Solidity contracts
    let contract_dirs = vec![
        // "./../../contracts/lib/eigenlayer-middleware/lib/eigenlayer-contracts",
        // "./../../contracts/lib/eigenlayer-middleware",
        // "./../../contracts/",
        "./contracts",
    ];

    // Get the project root directory
    let root = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());

    // Try to find the `forge` executable dynamically
    let forge_executable = match Command::new("which").arg("forge").output() {
        Ok(output) => {
            let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if path.is_empty() {
                panic!("Forge executable not found. Make sure Foundry is installed.");
            }
            path
        }
        Err(_) => panic!("Failed to locate `forge` executable. Make sure Foundry is installed."),
    };

    for dir in contract_dirs {
        let full_path = root.join(dir).canonicalize().unwrap_or_else(|_| {
            println!(
                "Directory not found or inaccessible: {}",
                root.join(dir).display()
            );
            root.join(dir)
        });

        if full_path.exists() {
            println!("cargo:rerun-if-changed={}", full_path.display());

            let status = Command::new(&forge_executable)
                .current_dir(&full_path)
                .arg("build")
                .status()
                .expect("Failed to execute Forge build");

            if !status.success() {
                panic!("Forge build failed for directory: {}", full_path.display());
            }
        } else {
            println!(
                "Directory not found or does not exist: {}",
                full_path.display()
            );
        }
    }
}
