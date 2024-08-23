use alloy_contract::private::Ethereum;
use alloy_primitives::{Address, Bytes, ChainId, Signature, B256};
use alloy_provider::{Provider, RootProvider};
use alloy_signer_local::PrivateKeySigner;
use alloy_transport::BoxTransport;
use eigen_utils::avs_registry::reader::AvsRegistryChainReaderTrait;
use eigen_utils::avs_registry::writer::AvsRegistryChainWriterTrait;
use eigen_utils::avs_registry::AvsRegistryContractManager;
use eigen_utils::crypto::bls::KeyPair;
use eigen_utils::el_contracts::writer::ElWriter;
use eigen_utils::el_contracts::ElChainContractManager;
use eigen_utils::node_api::NodeApi;
use eigen_utils::types::AvsError;
use eigen_utils::Config;
use k256::ecdsa::SigningKey;
use log::error;
use std::future::Future;
use std::pin::Pin;
use std::str::FromStr;
use thiserror::Error;

const AVS_NAME: &str = "incredible-squaring";
const SEM_VER: &str = "0.0.1";

/// Error type specific to the Operator for the Tangle AVS
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
    #[error("Error in Operator Address: {0}")]
    OperatorAddressError(String),
    #[error("Error while Starting Operator: {0}")]
    OperatorStartError(String),
    #[error(
        "Operator is not registered. Register using the operator-cli before starting operator."
    )]
    OperatorNotRegistered,
    #[error("Error in metrics server: {0}")]
    MetricsServerError(String),
    #[error("Error in Service Manager Address: {0}")]
    ServiceManagerAddressError(String),
    #[error("Error in Task Handling Process: {0}")]
    TaskError(String),
    #[error("Error in websocket subscription: {0}")]
    WebsocketSubscriptionError(String),
    #[error("AVS SDK error")]
    AvsSdkError(#[from] AvsError),
    #[error("Wallet error")]
    WalletError(#[from] alloy_signer_local::LocalSignerError),
    #[error("Node API error: {0}")]
    NodeApiError(String),
}

/// Tangle AVS Operator Struct
#[allow(dead_code)]
pub struct Operator<T: Config> {
    config: NodeConfig,
    node_api: NodeApi,
    avs_registry_contract_manager: AvsRegistryContractManager<T>,
    operator_id: [u8; 32],
    operator_addr: Address,
    tangle_validator_service_manager_addr: Address,
}

/// Tangle AVS Node Config Struct - Contains all the configurations relevant to the AVS' Target Chain
#[derive(Debug, Clone)]
pub struct NodeConfig {
    pub node_api_ip_port_address: String,
    pub eth_rpc_url: String,
    pub eth_ws_url: String,
    pub bls_private_key_store_path: String,
    pub ecdsa_private_key_store_path: String,
    pub avs_registry_coordinator_address: String,
    pub operator_state_retriever_address: String,
    pub eigen_metrics_ip_port_address: String,
    pub tangle_validator_service_manager_address: String,
    pub delegation_manager_address: String,
    pub avs_directory_address: String,
    pub operator_address: String,
    pub enable_metrics: bool,
    pub enable_node_api: bool,
    pub metadata_url: String,
}

#[derive(Clone)]
pub struct EigenTangleProvider {
    pub provider: RootProvider<BoxTransport, Ethereum>,
}

impl Provider for EigenTangleProvider {
    fn root(&self) -> &RootProvider<BoxTransport, Ethereum> {
        &self.provider
    }
}

#[derive(Clone)]
pub struct EigenTangleSigner {
    signer: PrivateKeySigner,
    chain_id: Option<ChainId>,
}

impl EigenTangleSigner {
    pub fn new(signer: PrivateKeySigner, chain_id: Option<ChainId>) -> Self {
        Self { signer, chain_id }
    }
}

impl alloy_signer::Signer for EigenTangleSigner {
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

impl Config for NodeConfig {
    type TH = BoxTransport;
    type TW = BoxTransport;
    type PH = EigenTangleProvider;
    type PW = EigenTangleProvider;
    type S = EigenTangleSigner;
}

#[derive(Debug, Clone)]
pub struct SetupConfig<T: Config> {
    pub registry_coordinator_addr: Address,
    pub operator_state_retriever_addr: Address,
    pub delegate_manager_addr: Address,
    pub avs_directory_addr: Address,
    pub eth_client_http: T::PH,
    pub eth_client_ws: T::PW,
    pub signer: T::S,
}

impl<T: Config> Operator<T> {
    /// Creates a new Operator from the given config, providers, and signer
    pub async fn new_from_config(
        config: NodeConfig,
        eth_client_http: T::PH,
        eth_client_ws: T::PW,
        signer: T::S,
    ) -> Result<Self, OperatorError> {
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

        let setup_config = SetupConfig::<T> {
            registry_coordinator_addr: Address::from_str(&config.avs_registry_coordinator_address)
                .map_err(|e| OperatorError::AddressError(e.to_string()))?,
            operator_state_retriever_addr: Address::from_str(
                &config.operator_state_retriever_address,
            )
            .map_err(|e| OperatorError::AddressError(e.to_string()))?,
            delegate_manager_addr: Address::from_str(&config.delegation_manager_address)
                .map_err(|e| OperatorError::AddressError(e.to_string()))?,
            avs_directory_addr: Address::from_str(&config.avs_directory_address)
                .map_err(|e| OperatorError::AddressError(e.to_string()))?,
            eth_client_http: eth_client_http.clone(),
            eth_client_ws: eth_client_ws.clone(),
            signer: signer.clone(),
        };

        let avs_registry_contract_manager = AvsRegistryContractManager::build(
            Address::from_str(&config.tangle_validator_service_manager_address)
                .map_err(|e| OperatorError::AddressError(e.to_string()))?,
            setup_config.registry_coordinator_addr,
            setup_config.operator_state_retriever_addr,
            setup_config.delegate_manager_addr,
            setup_config.avs_directory_addr,
            eth_client_http.clone(),
            eth_client_ws.clone(),
            signer.clone(),
        )
        .await?;

        let operator_addr = Address::from_str(&config.operator_address)
            .map_err(|err| OperatorError::OperatorAddressError(err.to_string()))?;

        let operator_id = avs_registry_contract_manager
            .get_operator_id(operator_addr)
            .await?;

        let tangle_validator_service_manager_addr =
            Address::from_str(&config.tangle_validator_service_manager_address)
                .map_err(|err| OperatorError::ServiceManagerAddressError(err.to_string()))?;

        log::info!("Building Eigenlayer Contract Manager...");
        let eigenlayer_contract_manager: ElChainContractManager<T> = ElChainContractManager::build(
            setup_config.delegate_manager_addr,
            setup_config.avs_directory_addr,
            eth_client_http.clone(),
            eth_client_ws.clone(),
            signer.clone(),
        )
        .await
        .map_err(|e| OperatorError::ContractManagerError(e.to_string()))?;

        // Register Operator with EigenLayer
        let register_operator = eigen_utils::types::Operator {
            address: operator_addr,
            earnings_receiver_address: operator_addr,
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
            .is_operator_registered(operator_addr)
            .await
            .map_err(|e| OperatorError::ContractManagerError(e.to_string()))?;
        log::info!("Is operator registered: {:?}", answer);

        let operator = Operator {
            config: config.clone(),
            node_api,
            avs_registry_contract_manager,
            operator_id: [0u8; 32],
            operator_addr,
            tangle_validator_service_manager_addr,
        };

        log::info!(
            "Operator info: operatorId={}, operatorAddr={}, operatorG1Pubkey={:?}, operatorG2Pubkey={:?}",
            hex::encode(operator_id),
            config.operator_address,
            bls_keypair.get_pub_key_g1(),
            bls_keypair.get_pub_key_g2(),
        );

        Ok(operator)
    }

    /// Queries the Chain for the Operator's registration status on the AVS
    pub async fn is_registered(&self) -> Result<bool, OperatorError> {
        let operator_is_registered = self
            .avs_registry_contract_manager
            .is_operator_registered(self.operator_addr)
            .await?;
        log::info!("Operator registration status: {:?}", operator_is_registered);
        Ok(operator_is_registered)
    }

    /// Starts the operator, running the Tangle Validator and optionally the Node API
    pub async fn start(&self) -> Result<(), OperatorError> {
        log::info!("Starting operator.");
        self.is_registered().await?;

        if self.config.enable_node_api {
            if let Err(e) = self.node_api.start().await {
                return Err(OperatorError::NodeApiError(e.to_string()));
            }
        }

        log::info!("Starting Tangle Validator...");
        gadget_executor::run_tangle_validator()
            .await
            .map_err(|e| OperatorError::OperatorStartError(e.to_string()))?;

        Ok(())
    }
}
