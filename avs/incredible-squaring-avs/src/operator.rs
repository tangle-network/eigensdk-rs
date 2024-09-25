#![allow(dead_code)]
use crate::aggregator::Aggregator;
use crate::avs::subscriber::IncredibleSquaringSubscriber;
use crate::avs::{
    IncredibleSquaringContractManager, IncredibleSquaringTaskManager, SetupConfig,
    SignedTaskResponse, TaskResponse,
};
use crate::get_task_response_digest;
use crate::rpc_client::AggregatorRpcClient;
use alloy_contract::private::Ethereum;
use alloy_primitives::{Address, Bytes, ChainId, FixedBytes, Signature, B256, U256};
use alloy_provider::{Provider, RootProvider};
use alloy_pubsub::Subscription;
use alloy_rpc_types::Log;
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::SolValue;
use alloy_transport::BoxTransport;
use async_trait::async_trait;
use eigen_utils::avs_registry::reader::AvsRegistryChainReaderTrait;
use eigen_utils::avs_registry::writer::AvsRegistryChainWriterTrait;
use eigen_utils::avs_registry::AvsRegistryContractManager;
use eigen_utils::crypto::bls::KeyPair;
use eigen_utils::crypto::ecdsa::ToAddress;
use eigen_utils::el_contracts::writer::ElWriter;
use eigen_utils::el_contracts::ElChainContractManager;
use eigen_utils::node_api::NodeApi;
use eigen_utils::services::operator_info::OperatorInfoServiceTrait;
use eigen_utils::types::{AvsError, OperatorId, OperatorInfo};
use eigen_utils::Config;
use k256::ecdsa::{SigningKey, VerifyingKey};
use log::error;
use prometheus::Registry;
use std::future::Future;
use std::pin::Pin;
use std::str::FromStr;
use thiserror::Error;

const AVS_NAME: &str = "incredible-squaring";
const SEM_VER: &str = "0.0.1";

/// Error type specific to the Operator for the Incredible Squaring AVS
#[derive(Debug, Error)]
pub enum OperatorError {
    #[error("Error in Address: {0}")]
    AddressError(String),
    #[error("Cannot create HTTP ethclient: {0}")]
    HttpEthClientError(String),
    #[error("Cannot create WS ethclient: {0}")]
    WsEthClientError(String),
    #[error("Cannot parse BLS private key: {0}")]
    BlsPrivateKeyError(String),
    #[error("Cannot parse ECDSA private key: {0}")]
    EcdsaPrivateKeyError(String),
    #[error("Cannot get chainId: {0}")]
    ChainIdError(String),
    #[error("Error using Contract Manager: {0}")]
    ContractManagerError(String),
    #[error("Error creating AvsWriter: {0}")]
    AvsWriterError(String),
    #[error("Error creating AvsReader: {0}")]
    AvsReaderError(String),
    #[error("Error creating AvsSubscriber: {0}")]
    AvsSubscriberError(String),
    #[error("Cannot create AggregatorRpcClient: {0}")]
    AggregatorRpcClientError(String),
    #[error("Cannot get operator id: {0}")]
    OperatorIdError(String),
    #[error(
        "Operator is not registered. Register using the operator-cli before starting operator."
    )]
    OperatorNotRegistered,
    #[error("Error in metrics server: {0}")]
    MetricsServerError(String),
    #[error("Error in websocket subscription: {0}")]
    WebsocketSubscriptionError(String),
    #[error("Error getting task response header hash: {0}")]
    TaskResponseHeaderHashError(String),
    #[error("Error in Task Handling Process: {0}")]
    TaskError(String),
    #[error("AVS SDK error")]
    AvsSdkError(#[from] AvsError),
    #[error("Wallet error")]
    WalletError(#[from] alloy_signer_local::LocalSignerError),
    #[error("Node API error: {0}")]
    NodeApiError(String),
}

/// Incredible Squaring AVS Operator Struct
#[derive(Clone)]
pub struct Operator<T: Config, I: OperatorInfoServiceTrait> {
    config: NodeConfig,
    node_api: NodeApi,
    avs_registry_contract_manager: AvsRegistryContractManager<T>,
    pub incredible_squaring_contract_manager: IncredibleSquaringContractManager<T>,
    eigenlayer_contract_manager: ElChainContractManager<T>,
    bls_keypair: KeyPair,
    operator_id: FixedBytes<32>,
    operator_addr: Address,
    aggregator_server_ip_port_addr: String,
    pub aggregator_server: Aggregator<T, I>,
    pub aggregator_rpc_client: AggregatorRpcClient,
}

#[derive(Clone)]
pub struct EigenGadgetProvider {
    pub provider: RootProvider<BoxTransport, Ethereum>,
}

impl Provider for EigenGadgetProvider {
    fn root(&self) -> &RootProvider<BoxTransport, Ethereum> {
        &self.provider
    }
}

#[derive(Clone)]
pub struct EigenGadgetSigner {
    signer: PrivateKeySigner,
    chain_id: Option<ChainId>,
}

impl EigenGadgetSigner {
    pub fn new(signer: PrivateKeySigner, chain_id: Option<ChainId>) -> Self {
        Self { signer, chain_id }
    }
}

impl alloy_signer::Signer for EigenGadgetSigner {
    fn sign_hash<'life0, 'life1, 'async_trait>(
        &'life0 self,
        hash: &'life1 B256,
    ) -> Pin<Box<dyn Future<Output = alloy_signer::Result<Signature>> + Send + 'async_trait>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: 'async_trait,
    {
        let signer = self.signer.clone();

        let signature_future = async move { signer.sign_hash(hash).await };

        Box::pin(signature_future)
    }

    fn address(&self) -> Address {
        self.signer.address()
    }

    fn chain_id(&self) -> Option<ChainId> {
        self.chain_id
    }

    fn set_chain_id(&mut self, chain_id: Option<ChainId>) {
        self.chain_id = chain_id;
    }
}

/// Incredible Squaring AVS Node Config Struct - Contains all the configurations relevant to the AVS' Target Chain
#[derive(Debug, Clone)]
pub struct NodeConfig {
    pub node_api_ip_port_address: String,
    pub enable_node_api: bool,
    pub eth_rpc_url: String,
    pub eth_ws_url: String,
    pub bls_private_key_store_path: String,
    pub ecdsa_private_key_store_path: String,
    pub incredible_squaring_service_manager_addr: String,
    pub avs_registry_coordinator_addr: String,
    pub operator_state_retriever_addr: String,
    pub delegation_manager_addr: String,
    pub avs_directory_addr: String,
    pub eigen_metrics_ip_port_address: String,
    pub server_ip_port_address: String,
    pub operator_address: String,
    pub enable_metrics: bool,
    pub metadata_url: String,
}

impl Config for NodeConfig {
    type TH = BoxTransport;
    type TW = BoxTransport;
    type PH = EigenGadgetProvider;
    type PW = EigenGadgetProvider;
    type S = EigenGadgetSigner;
}

#[derive(Debug, Clone)]
pub struct OperatorInfoService {
    operator_info: OperatorInfo,
    operator_id: OperatorId,
    operator_address: Address,
    config: NodeConfig,
}

impl OperatorInfoService {
    pub fn new(
        operator_info: OperatorInfo,
        operator_id: OperatorId,
        operator_address: Address,
        config: NodeConfig,
    ) -> Self {
        Self {
            operator_info,
            operator_id,
            operator_address,
            config,
        }
    }
}

#[async_trait]
impl OperatorInfoServiceTrait for OperatorInfoService {
    async fn get_operator_info(&self, _operator: Address) -> Result<Option<OperatorInfo>, String> {
        Ok(Some(self.operator_info.clone()))
    }
}

impl<T: Config, I: OperatorInfoServiceTrait> Operator<T, I> {
    /// Creates a new Operator from the given config, providers, and signer
    pub async fn new_from_config(
        config: NodeConfig,
        eth_client_http: T::PH,
        eth_client_ws: T::PW,
        operator_info_service: I,
        signer: T::S,
    ) -> Result<Self, OperatorError> {
        let _metrics_reg = Registry::new();
        let operator_address = Address::from_str(&config.operator_address)
            .map_err(|e| OperatorError::AddressError(e.to_string()))?;

        let node_api = NodeApi::new(AVS_NAME, SEM_VER, &config.node_api_ip_port_address);

        log::info!("Reading BLS key");
        let bls_key_password =
            std::env::var("OPERATOR_BLS_KEY_PASSWORD").unwrap_or_else(|_| "".to_string());
        let bls_keypair = KeyPair::read_private_key_from_file(
            &config.bls_private_key_store_path,
            &bls_key_password,
        )
        .map_err(OperatorError::from)?;

        log::info!("Reading ECDSA key");
        let ecdsa_key_password =
            std::env::var("OPERATOR_ECDSA_KEY_PASSWORD").unwrap_or_else(|_| "".to_string());
        let ecdsa_secret_key = eigen_utils::crypto::ecdsa::read_key(
            &config.ecdsa_private_key_store_path,
            &ecdsa_key_password,
        )
        .map_err(|e| OperatorError::EcdsaPrivateKeyError(e.to_string()))?;
        let ecdsa_signing_key = SigningKey::from(&ecdsa_secret_key);
        let verifying_key = VerifyingKey::from(&ecdsa_signing_key);
        let ecdsa_address = verifying_key.to_address();
        assert_eq!(
            operator_address, ecdsa_address,
            "Operator Address does not match the address found from the read ECDSA key"
        );

        let setup_config = SetupConfig::<T> {
            registry_coordinator_addr: Address::from_str(&config.avs_registry_coordinator_addr)
                .map_err(|e| OperatorError::AddressError(e.to_string()))?,
            operator_state_retriever_addr: Address::from_str(&config.operator_state_retriever_addr)
                .map_err(|e| OperatorError::AddressError(e.to_string()))?,
            delegate_manager_addr: Address::from_str(&config.delegation_manager_addr)
                .map_err(|e| OperatorError::AddressError(e.to_string()))?,
            avs_directory_addr: Address::from_str(&config.avs_directory_addr)
                .map_err(|e| OperatorError::AddressError(e.to_string()))?,
            eth_client_http: eth_client_http.clone(),
            eth_client_ws: eth_client_ws.clone(),
            signer: signer.clone(),
        };

        let incredible_squaring_contract_manager = IncredibleSquaringContractManager::build(
            setup_config.registry_coordinator_addr,
            setup_config.operator_state_retriever_addr,
            eth_client_http.clone(),
            eth_client_ws.clone(),
            signer.clone(),
        )
        .await
        .map_err(|e| OperatorError::ContractManagerError(e.to_string()))?;

        log::info!("Building AVS Registry Contract Manager");
        let avs_registry_contract_manager = AvsRegistryContractManager::build(
            Address::from_str(&config.incredible_squaring_service_manager_addr)
                .map_err(|e| OperatorError::AddressError(e.to_string()))?,
            setup_config.registry_coordinator_addr,
            setup_config.operator_state_retriever_addr,
            setup_config.delegate_manager_addr,
            setup_config.avs_directory_addr,
            eth_client_http.clone(),
            eth_client_ws.clone(),
            signer.clone(),
        )
        .await
        .map_err(|e| OperatorError::ContractManagerError(e.to_string()))?;

        log::info!("Building Aggregator Service...");
        let aggregator_service = Aggregator::build(
            &setup_config,
            operator_info_service,
            config.server_ip_port_address.clone(),
        )
        .await
        .map_err(|e| OperatorError::AggregatorRpcClientError(e.to_string()))?;

        log::info!("Building Aggregator RPC Client...");
        let aggregator_rpc_client = AggregatorRpcClient::new(config.server_ip_port_address.clone());

        log::info!("Building Eigenlayer Contract Manager...");
        let eigenlayer_contract_manager = ElChainContractManager::build(
            setup_config.delegate_manager_addr,
            setup_config.avs_directory_addr,
            eth_client_http.clone(),
            eth_client_ws.clone(),
            signer.clone(),
        )
        .await
        .map_err(|e| OperatorError::ContractManagerError(e.to_string()))?;

        let operator_id = avs_registry_contract_manager
            .get_operator_id(operator_address)
            .await?;

        // Register Operator with EigenLayer
        let register_operator = eigen_utils::types::Operator {
            address: operator_address,
            earnings_receiver_address: operator_address,
            delegation_approver_address: Address::from([0u8; 20]),
            staker_opt_out_window_blocks: 50400u32, // About 7 days in blocks on Ethereum
            metadata_url: config.metadata_url.clone(),
        };
        let eigenlayer_register_result = eigenlayer_contract_manager
            .register_as_operator(register_operator)
            .await
            .map_err(|e| OperatorError::ContractManagerError(e.to_string()))?
            .status();
        log::info!(
            "Eigenlayer Registration result: {:?}",
            eigenlayer_register_result
        );

        // Register Operator with AVS
        let quorum_nums = Bytes::from([0x00]);
        let register_result = avs_registry_contract_manager
            .register_operator(
                &ecdsa_signing_key,
                &bls_keypair,
                quorum_nums,
                config.eth_rpc_url.clone(),
            )
            .await;
        log::info!("AVS Registration result: {:?}", register_result);

        let answer = avs_registry_contract_manager
            .is_operator_registered(operator_address)
            .await
            .map_err(|e| OperatorError::ContractManagerError(e.to_string()))?;
        log::info!("Is operator registered: {:?}", answer);

        log::info!(
            "Operator info: operatorId={}, operatorAddr={}, operatorG1Pubkey={:?}, operatorG2Pubkey={:?}",
            hex::encode(operator_id),
            operator_address,
            bls_keypair.clone().get_pub_key_g1(),
            bls_keypair.clone().get_pub_key_g2(),
        );

        let operator = Operator {
            config: config.clone(),
            node_api,
            avs_registry_contract_manager: avs_registry_contract_manager.clone(),
            incredible_squaring_contract_manager,
            eigenlayer_contract_manager: eigenlayer_contract_manager.clone(),
            bls_keypair,
            operator_id,
            operator_addr: operator_address,
            aggregator_server_ip_port_addr: config.server_ip_port_address.clone(),
            aggregator_server: aggregator_service,
            aggregator_rpc_client,
        };

        Ok(operator)
    }

    pub async fn is_registered(&self) -> Result<bool, OperatorError> {
        let operator_is_registered = self
            .avs_registry_contract_manager
            .is_operator_registered(self.operator_addr)
            .await?;
        log::info!("Operator registration status: {:?}", operator_is_registered);
        Ok(operator_is_registered)
    }

    pub async fn start(self) -> Result<(), OperatorError> {
        log::info!("Starting operator.");
        let operator_is_registered = self
            .avs_registry_contract_manager
            .is_operator_registered(self.operator_addr)
            .await?;
        log::info!("Operator registration status: {:?}", operator_is_registered);

        if self.config.enable_node_api {
            if let Err(e) = self.node_api.start().await {
                return Err(OperatorError::NodeApiError(e.to_string()));
            }
        }
        let mut sub = self.subscribe_to_new_tasks().await?;

        let server = self.aggregator_server.clone();
        let aggregator_server = async move {
            server.start_server().await.unwrap();
        };
        tokio::spawn(aggregator_server);

        log::info!("Subscribed to new tasks: {:?}", sub);

        let value = sub
            .recv()
            .await
            .map_err(|e| OperatorError::TaskError(e.to_string()))?;
        log::info!("Received new task: {:?}", value);

        loop {
            log::info!("Waiting for new task submissions");
            tokio::select! {
                Ok(new_task_created_log) = sub.recv() => {
                    log::info!("Received new task: {:?}", new_task_created_log);
                    // self.metrics.inc_num_tasks_received();
                    let log: Log<IncredibleSquaringTaskManager::NewTaskCreated> = new_task_created_log.log_decode().map_err(|e| OperatorError::TaskError(e.to_string()))?;
                    let task_response = self.process_new_task_created_log(&log);
                    log::info!("Generated Task Response: {:?}", task_response);
                    if let Ok(signed_task_response) = self.sign_task_response(&task_response) {
                        log::info!("Sending signed task response to aggregator: {:?}", signed_task_response);
                        let agg_rpc_client = self.aggregator_rpc_client.clone();
                        tokio::spawn(async move {
                            agg_rpc_client.send_signed_task_response_to_aggregator(signed_task_response).await;
                        });
                    }
                },
            }
        }
    }

    pub fn config(&self) -> NodeConfig {
        self.config.clone()
    }

    pub fn process_new_task_created_log(
        &self,
        new_task_created_log: &Log<IncredibleSquaringTaskManager::NewTaskCreated>,
    ) -> TaskResponse {
        log::debug!("Received new task: {:?}", new_task_created_log);
        log::info!("Received new task: numberToBeSquared={}, taskIndex={}, taskCreatedBlock={}, quorumNumbers={}, QuorumThresholdPercentage={}",
            new_task_created_log.inner.task.numberToBeSquared,
            new_task_created_log.inner.taskIndex,
            new_task_created_log.inner.task.taskCreatedBlock,
            new_task_created_log.inner.task.quorumNumbers,
            new_task_created_log.inner.task.quorumThresholdPercentage
        );
        let number_squared = new_task_created_log
            .inner
            .task
            .numberToBeSquared
            .pow(U256::from(2));
        TaskResponse {
            referenceTaskIndex: new_task_created_log.inner.taskIndex,
            numberSquared: number_squared,
        }
    }

    pub fn sign_task_response(
        &self,
        task_response: &TaskResponse,
    ) -> Result<SignedTaskResponse, OperatorError> {
        let task_response_hash = get_task_response_digest(task_response);
        let bls_signature = self.bls_keypair.sign_message(&task_response_hash);
        let signed_task_response = SignedTaskResponse {
            task_response: task_response.abi_encode(),
            bls_signature,
            operator_id: self.operator_id,
        };
        log::debug!("Signed task response: {:?}", signed_task_response);
        Ok(signed_task_response)
    }

    pub async fn subscribe_to_new_tasks(&self) -> Result<Subscription<Log>, AvsError> {
        self.incredible_squaring_contract_manager
            .subscribe_to_new_tasks()
            .await
    }

    pub async fn start_aggregator_server(&self) -> Result<(), AvsError> {
        self.aggregator_server
            .clone()
            .start_server()
            .await
            .map_err(|e| AvsError::OperatorError(e.to_string()))
    }
}
