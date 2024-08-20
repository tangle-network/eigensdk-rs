#![allow(dead_code)]
use alloy_provider::Provider;
use alloy_provider::ProviderBuilder;
use alloy_signer_local::PrivateKeySigner;
use alloy_transport_ws::WsConnect;
use k256::ecdsa::SigningKey;
use k256::elliptic_curve::SecretKey;
use tangle_avs::operator::*;
use test_utils::anvil::testnet::tangle::*;

#[tokio::main]
async fn main() {
    let _ = env_logger::try_init();
    run_full_tangle_test().await;
}

/// Sets up an Operator, given the [ContractAddresses] for the running Testnet you would like utilize
async fn operator_setup(contract_addresses: ContractAddresses) -> Operator<NodeConfig> {
    let http_endpoint = "http://127.0.0.1:8545";
    let ws_endpoint = "ws://127.0.0.1:8545";
    let node_config = NodeConfig {
        node_api_ip_port_address: "127.0.0.1:9808".to_string(),
        eth_rpc_url: http_endpoint.to_string(),
        eth_ws_url: ws_endpoint.to_string(),
        bls_private_key_store_path: "./keystore/bls".to_string(),
        ecdsa_private_key_store_path: "./keystore/ecdsa".to_string(),
        avs_registry_coordinator_address: contract_addresses.registry_coordinator.to_string(),
        eigen_metrics_ip_port_address: "127.0.0.1:9100".to_string(),
        tangle_validator_service_manager_address: contract_addresses.service_manager.to_string(),
        delegation_manager_address: contract_addresses.delegation_manager.to_string(),
        operator_address: contract_addresses.operator.to_string(),
        enable_metrics: false,
        enable_node_api: false,
        operator_state_retriever_address: contract_addresses.operator_state_retriever.to_string(),
        avs_directory_address: contract_addresses.avs_directory.to_string(),
    };

    let hex_key =
        hex::decode("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80").unwrap();
    let secret_key = SecretKey::from_slice(&hex_key).unwrap();
    let signing_key = SigningKey::from(secret_key.clone());
    let signer = EigenTangleSigner {
        signer: PrivateKeySigner::from_signing_key(signing_key),
    };

    println!("Creating HTTP Provider...");

    let http_provider = ProviderBuilder::new()
        .with_recommended_fillers()
        .on_http(http_endpoint.parse().unwrap())
        .root()
        .clone()
        .boxed();

    println!("Creating WS Provider...");

    let ws_provider = ProviderBuilder::new()
        .with_recommended_fillers()
        .on_ws(WsConnect::new(ws_endpoint))
        .await
        .unwrap()
        .root()
        .clone()
        .boxed();

    println!("Now setting up Operator!");

    Operator::<NodeConfig>::new_from_config(
        node_config.clone(),
        EigenTangleProvider {
            provider: http_provider,
        },
        EigenTangleProvider {
            provider: ws_provider,
        },
        signer,
    )
    .await
    .unwrap()
}

/// THIS FUNCTION IS FOR TESTING ONLY
///
/// Runs the Tangle Testnet and then creates an Operator that connects and registers.
async fn run_full_tangle_test() {
    let _ = env_logger::try_init();

    // Runs new Anvil Testnet - used for deploying programmatically in rust
    let contract_addresses = run_tangle_testnet().await;

    let operator = operator_setup(contract_addresses).await;

    operator.start().await.unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;
    use eigen_utils::crypto::bls::KeyPair;
    use k256::ecdsa::VerifyingKey;
    use k256::elliptic_curve::SecretKey;
    use std::env;

    #[tokio::test]
    async fn test_full_tangle() {
        if env::var("RUST_LOG").is_err() {
            env::set_var("RUST_LOG", "info");
        }
        env::set_var("BLS_PASSWORD", "BLS_PASSWORD");
        env::set_var("ECDSA_PASSWORD", "ECDSA_PASSWORD");
        env_logger::init();
        run_full_tangle_test().await;
    }

    #[tokio::test]
    async fn test_tangle_deployment() {
        if env::var("RUST_LOG").is_err() {
            env::set_var("RUST_LOG", "info");
        }
        env::set_var("BLS_PASSWORD", "BLS_PASSWORD");
        env::set_var("ECDSA_PASSWORD", "ECDSA_PASSWORD");
        let _ = env_logger::try_init();
        let _ = run_tangle_testnet().await;
    }

    // TODO: Get test for loading from state working
    // #[tokio::test]
    // async fn test_start_chain_from_state() {
    //     env_logger::init();
    //
    //     let chain = crate::anvil::local_chain::LocalEvmChain::new_with_chain_state(
    //         31337,
    //         String::from("eigen-testnet"),
    //         Path::new("../../eigen-utils/eigen-gadget-anvil-state.json"),
    //         Some(8545u16),
    //     );
    //     let chain_id = chain.chain_id();
    //     let chain_name = chain.name();
    //     println!("chain_id: {:?}", chain_id);
    //     println!("chain_name: {:?}", chain_name);
    //     let addresses = chain.addresses();
    //     println!("addresses: {:?}", addresses);
    //     tokio::time::sleep(Duration::from_secs(5)).await;
    //     println!("Now shutting down...");
    //     chain.shutdown();
    // }

    #[tokio::test]
    async fn test_generate_keys() {
        env_logger::init();

        // ---------------- BLS ----------------
        let bls_pair = KeyPair::gen_random().unwrap();
        bls_pair
            .save_to_file("./keystore/bls", BLS_PASSWORD)
            .unwrap();
        let bls_keys = KeyPair::read_private_key_from_file("./keystore/bls", BLS_PASSWORD).unwrap();
        assert_eq!(bls_pair.priv_key, bls_keys.priv_key);
        assert_eq!(bls_pair.pub_key, bls_keys.pub_key);

        //---------------- ECDSA ----------------
        // First Account
        let hex_key =
            hex::decode("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
                .unwrap();

        // Second Account
        // let hex_key =
        //     hex::decode("59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d")
        //         .unwrap();

        let secret_key = SecretKey::from_slice(&hex_key).unwrap();
        let signing_key = SigningKey::from(secret_key.clone());
        let public_key = secret_key.public_key();
        let verifying_key = VerifyingKey::from(public_key);
        eigen_utils::crypto::ecdsa::write_key("./keystore/ecdsa", &secret_key, ECDSA_PASSWORD)
            .unwrap();

        let read_ecdsa_secret_key =
            eigen_utils::crypto::ecdsa::read_key("./keystore/ecdsa", ECDSA_PASSWORD).unwrap();
        let read_ecdsa_public_key = read_ecdsa_secret_key.public_key();
        let read_ecdsa_signing_key = SigningKey::from(&read_ecdsa_secret_key);
        let read_ecdsa_verifying_key = VerifyingKey::from(&read_ecdsa_signing_key);

        assert_eq!(secret_key, read_ecdsa_secret_key);
        assert_eq!(public_key, read_ecdsa_public_key);
        assert_eq!(signing_key, read_ecdsa_signing_key);
        assert_eq!(verifying_key, read_ecdsa_verifying_key);
    }
}