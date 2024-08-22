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
    run_tangle_testnet().await;
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
        metadata_url:
            "https://github.com/webb-tools/eigensdk-rs/blob/main/test-utils/metadata.json"
                .to_string(),
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    fn env_init() {
        if env::var("RUST_LOG").is_err() {
            env::set_var("RUST_LOG", "info");
        }
        env::set_var("BLS_PASSWORD", "BLS_PASSWORD");
        env::set_var("ECDSA_PASSWORD", "ECDSA_PASSWORD");
        let _ = env_logger::try_init();
    }

    #[tokio::test]
    async fn test_tangle_testnet_deployment() {
        env_init();
        let _ = run_tangle_testnet().await;
    }

    #[tokio::test]
    async fn test_tangle_full() {
        env_init();

        // Runs new Anvil Testnet - used for deploying programmatically in rust
        let contract_addresses = run_tangle_testnet().await;

        // Sets up the Operator
        let operator = operator_setup(contract_addresses).await;

        // Check that the operator has registered successfully
        assert!(operator.is_registered().await.unwrap());

        log::info!("Operator Successfully Registered. The Tangle Validator would now start.");
    }
}
