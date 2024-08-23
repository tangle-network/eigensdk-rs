#![allow(dead_code)]

use alloy_primitives::ChainId;
use alloy_provider::Provider;
use alloy_provider::ProviderBuilder;
use alloy_signer::Signer;
use alloy_signer_local::PrivateKeySigner;
use alloy_transport_ws::WsConnect;
use eigen_utils::crypto::bls::KeyPair;
use eigen_utils::types::{operator_id_from_key_pair, OperatorInfo, OperatorPubkeys};
use incredible_squaring_avs::operator::*;
use k256::ecdsa::SigningKey;
use k256::elliptic_curve::SecretKey;
use test_utils::anvil::testnet::incredible_squaring::*;

#[tokio::main]
async fn main() {
    let _ = env_logger::try_init();
    run_incredible_squaring_testnet().await;
}

/// Sets up an Operator, given the [ContractAddresses] for the running Testnet you would like utilize
async fn operator_setup(
    contract_addresses: ContractAddresses,
) -> Result<Operator<NodeConfig, OperatorInfoService>, OperatorError> {
    let http_endpoint = "http://127.0.0.1:8545";
    let ws_endpoint = "ws://127.0.0.1:8545";
    let node_config = NodeConfig {
        node_api_ip_port_address: "127.0.0.1:9808".to_string(),
        eth_rpc_url: http_endpoint.to_string(),
        eth_ws_url: ws_endpoint.to_string(),
        bls_private_key_store_path: "./keystore/bls".to_string(),
        ecdsa_private_key_store_path: "./keystore/ecdsa".to_string(),
        incredible_squaring_service_manager_addr: contract_addresses.service_manager.to_string(),
        avs_registry_coordinator_addr: contract_addresses.registry_coordinator.to_string(),
        operator_state_retriever_addr: contract_addresses.operator_state_retriever.to_string(),
        eigen_metrics_ip_port_address: "127.0.0.1:9100".to_string(),
        delegation_manager_addr: contract_addresses.delegation_manager.to_string(),
        avs_directory_addr: contract_addresses.avs_directory.to_string(),
        operator_address: contract_addresses.operator.to_string(),
        enable_metrics: false,
        enable_node_api: false,
        server_ip_port_address: "127.0.0.1:8673".to_string(),
        metadata_url:
            "https://github.com/webb-tools/eigensdk-rs/blob/main/test-utils/metadata.json"
                .to_string(),
    };

    log::info!("Creating HTTP Provider...");

    let http_provider = ProviderBuilder::new()
        .with_recommended_fillers()
        .on_http(
            http_endpoint
                .parse::<url::Url>()
                .map_err(|e| OperatorError::HttpEthClientError(e.to_string()))?,
        )
        .root()
        .clone()
        .boxed();

    log::info!("Creating WS Provider...");

    let ws_provider = ProviderBuilder::new()
        .with_recommended_fillers()
        .on_ws(WsConnect::new(ws_endpoint))
        .await
        .map_err(|e| OperatorError::WsEthClientError(e.to_string()))?
        .root()
        .clone()
        .boxed();

    log::info!("Now setting up Operator!");

    let chain_id = http_provider
        .get_chain_id()
        .await
        .map_err(|e| OperatorError::HttpEthClientError(e.to_string()))?;

    let bls_key_password =
        std::env::var("OPERATOR_BLS_KEY_PASSWORD").unwrap_or_else(|_| "".to_string());
    let bls_keypair = KeyPair::read_private_key_from_file(
        &node_config.bls_private_key_store_path.clone(),
        &bls_key_password,
    )?;
    let operator_pubkeys = OperatorPubkeys {
        g1_pubkey: bls_keypair.get_pub_key_g1().to_ark_g1(),
        g2_pubkey: bls_keypair.get_pub_key_g2().to_ark_g2(),
    };

    let operator_id = operator_id_from_key_pair(&bls_keypair);

    let hex_key = hex::decode("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
        .map_err(|e| OperatorError::EcdsaPrivateKeyError(e.to_string()))?;
    let secret_key = SecretKey::from_slice(&hex_key)
        .map_err(|e| OperatorError::EcdsaPrivateKeyError(e.to_string()))?;
    let signing_key = SigningKey::from(secret_key.clone());
    let signer = EigenGadgetSigner::new(
        PrivateKeySigner::from_signing_key(signing_key),
        Some(ChainId::from(chain_id)),
    );

    let operator_info = OperatorInfo {
        socket: "0.0.0.0:0".to_string(),
        pubkeys: operator_pubkeys,
    };

    let operator_info_service = OperatorInfoService::new(
        operator_info,
        operator_id,
        signer.address(),
        node_config.clone(),
    );

    Operator::<NodeConfig, OperatorInfoService>::new_from_config(
        node_config.clone(),
        EigenGadgetProvider {
            provider: http_provider,
        },
        EigenGadgetProvider {
            provider: ws_provider,
        },
        operator_info_service,
        signer,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_rpc_types_eth::Log;
    use incredible_squaring_avs::avs::IncredibleSquaringTaskManager;
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
    async fn test_incredible_squaring_deployment() {
        env_init();
        let _ = run_incredible_squaring_testnet().await;
    }

    #[tokio::test]
    async fn test_incredible_squaring_full() {
        env_init();

        // Runs new Anvil Testnet - used for deploying programmatically in rust
        let contract_addresses = run_incredible_squaring_testnet().await;

        // Sets up the Operator
        let operator = operator_setup(contract_addresses).await.unwrap();

        // Check that the operator has registered successfully
        assert!(operator.is_registered().await.unwrap());

        let mut sub = operator.subscribe_to_new_tasks().await.unwrap();
        log::info!("Subscribed to new tasks: {:?}", sub);

        let server = operator.aggregator_server.clone();
        let aggregator_server = async move {
            server.start_server().await.unwrap();
        };
        tokio::spawn(aggregator_server);

        let new_task_created_log = sub.recv().await.unwrap();
        log::info!("Received new task: {:?}", new_task_created_log);

        let log: Log<IncredibleSquaringTaskManager::NewTaskCreated> =
            new_task_created_log.log_decode().unwrap();
        let task_response = operator.process_new_task_created_log(&log);
        log::info!("Generated Task Response: {:?}", task_response);
        if let Ok(signed_task_response) = operator.sign_task_response(&task_response) {
            log::info!(
                "Sending signed task response to aggregator: {:?}",
                signed_task_response
            );
            let agg_rpc_client = operator.aggregator_rpc_client.clone();
            tokio::spawn(async move {
                agg_rpc_client
                    .send_signed_task_response_to_aggregator(signed_task_response)
                    .await;
            });
        }
    }
}
