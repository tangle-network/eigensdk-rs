#![allow(dead_code)]
use alloy_contract::private::Ethereum;
use alloy_primitives::{Address, Bytes, ChainId, FixedBytes, Signature, B256, U256, address};
use alloy_provider::{Provider, RootProvider};
use alloy_rpc_types::Log;
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::SolValue;
use alloy_transport::BoxTransport;
use async_trait::async_trait;
use eigen_utils::avs_registry::reader::AvsRegistryChainReaderTrait;
use eigen_utils::avs_registry::writer::AvsRegistryChainWriterTrait;
use eigen_utils::avs_registry::AvsRegistryContractManager;
use eigen_utils::crypto::bls::KeyPair;
use eigen_utils::el_contracts::ElChainContractManager;
use eigen_utils::node_api::NodeApi;
use eigen_utils::services::operator_info::OperatorInfoServiceTrait;
use eigen_utils::types::{AvsError, OperatorInfo};
use eigen_utils::Config;
use gadget_common::subxt_signer::bip39::rand;
use k256::ecdsa::{SigningKey, VerifyingKey};
use log::error;
use prometheus::Registry;
use rand::Rng;
use std::future::Future;
use std::pin::Pin;
use std::str::FromStr;
use thiserror::Error;
use eigen_utils::crypto::ecdsa::ToAddress;
use crate::aggregator::Aggregator;
use crate::avs::subscriber::IncredibleSquaringSubscriber;
use crate::avs::{
    IncredibleSquaringContractManager, IncredibleSquaringTaskManager, SetupConfig,
    SignedTaskResponse,
};
use crate::get_task_response_digest;
use crate::rpc_client::AggregatorRpcClient;

const AVS_NAME: &str = "incredible-squaring";
const SEM_VER: &str = "0.0.1";

#[derive(Debug, Error)]
pub enum OperatorError {
    #[error("Cannot create HTTP ethclient: {0}")]
    HttpEthClientError(String),
    #[error("Cannot create WS ethclient: {0}")]
    WsEthClientError(String),
    #[error("Cannot parse BLS private key: {0}")]
    BlsPrivateKeyError(String),
    #[error("Cannot get chainId: {0}")]
    ChainIdError(String),
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
    #[error("AVS SDK error")]
    AvsSdkError(#[from] AvsError),
    #[error("Wallet error")]
    WalletError(#[from] alloy_signer_local::LocalSignerError),
    #[error("Node API error: {0}")]
    NodeApiError(String),
}

pub struct Operator<T: Config, I: OperatorInfoServiceTrait> {
    config: NodeConfig,
    node_api: NodeApi,
    avs_registry_contract_manager: AvsRegistryContractManager<T>,
    incredible_squaring_contract_manager: IncredibleSquaringContractManager<T>,
    eigenlayer_contract_manager: ElChainContractManager<T>,
    bls_keypair: KeyPair,
    operator_id: FixedBytes<32>,
    operator_addr: Address,
    aggregator_server_ip_port_addr: String,
    aggregator_server: Aggregator<T, I>,
    aggregator_rpc_client: AggregatorRpcClient,
}

#[derive(Clone)]
pub struct EigenGadgetProvider {
    pub provider: RootProvider<BoxTransport, Ethereum>,
}

impl Provider for EigenGadgetProvider {
    fn root(&self) -> &RootProvider<BoxTransport, Ethereum> {
        println!("Provider Root TEST");
        &self.provider
    }
}

#[derive(Clone)]
pub struct EigenGadgetSigner {
    pub signer: PrivateKeySigner,
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
        println!("ADDRESS TEST");
        panic!("Signer functions for EigenGadgetSigner are not yet implemented")
    }

    fn chain_id(&self) -> Option<ChainId> {
        println!("CHAIN ID TEST");
        panic!("Signer functions for EigenGadgetSigner are not yet implemented")
    }

    fn set_chain_id(&mut self, _chain_id: Option<ChainId>) {
        println!("SET CHAIN ID TEST");
        panic!("Signer functions for EigenGadgetSigner are not yet implemented")
    }
}

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
}

impl Config for NodeConfig {
    type TH = BoxTransport;
    type TW = BoxTransport;
    type PH = EigenGadgetProvider;
    type PW = EigenGadgetProvider;
    type S = EigenGadgetSigner;
}

#[derive(Debug, Clone)]
pub struct OperatorInfoService {}

#[async_trait]
impl OperatorInfoServiceTrait for OperatorInfoService {
    async fn get_operator_info(&self, _operator: Address) -> Result<Option<OperatorInfo>, String> {
        todo!()
    }
}

impl<T: Config, I: OperatorInfoServiceTrait> Operator<T, I> {
    pub async fn new_from_config(
        config: NodeConfig,
        eth_client_http: T::PH,
        eth_client_ws: T::PW,
        operator_info_service: I,
        signer: T::S,
    ) -> Result<Self, OperatorError> {
        let _metrics_reg = Registry::new();
        let operator_address = Address::from_str(&config.operator_address).unwrap();

        let node_api = NodeApi::new(AVS_NAME, SEM_VER, &config.node_api_ip_port_address);

        log::info!("About to read BLS key");
        let bls_key_password =
            std::env::var("OPERATOR_BLS_KEY_PASSWORD").unwrap_or_else(|_| "".to_string());
        let bls_keypair = KeyPair::read_private_key_from_file(
            &config.bls_private_key_store_path,
            &bls_key_password,
        )
        .map_err(OperatorError::from)?;

        let _chain_id = eth_client_http
            .get_chain_id()
            .await
            .map_err(|e| OperatorError::ChainIdError(e.to_string()))?;
        // TODO: Chain id is not used

        log::info!("About to read ECDSA key");
        let ecdsa_key_password =
            std::env::var("OPERATOR_ECDSA_KEY_PASSWORD").unwrap_or_else(|_| "".to_string());
        let ecdsa_secret_key = eigen_utils::crypto::ecdsa::read_key(
            &config.ecdsa_private_key_store_path,
            &ecdsa_key_password,
        )
        .unwrap();
        let ecdsa_signing_key = SigningKey::from(&ecdsa_secret_key);
        let verifying_key = VerifyingKey::from(&ecdsa_signing_key);
        let ecdsa_address = verifying_key.to_address();
        assert_eq!(operator_address, ecdsa_address, "Operator Address does not match the address found from the read ECDSA key");

        let setup_config = SetupConfig::<T> {
            registry_coordinator_addr: Address::from_str(&config.avs_registry_coordinator_addr)
                .unwrap(),
            operator_state_retriever_addr: Address::from_str(&config.operator_state_retriever_addr)
                .unwrap(),
            delegate_manager_addr: Address::from_str(&config.delegation_manager_addr).unwrap(),
            avs_directory_addr: Address::from_str(&config.avs_directory_addr).unwrap(),
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
        .unwrap();

        log::info!("About to build AVS Registry Contract Manager");
        let avs_registry_contract_manager = AvsRegistryContractManager::build(
            Address::from_str(&config.incredible_squaring_service_manager_addr).unwrap(),
            setup_config.registry_coordinator_addr,
            setup_config.operator_state_retriever_addr,
            setup_config.delegate_manager_addr,
            setup_config.avs_directory_addr,
            eth_client_http.clone(),
            eth_client_ws.clone(),
            signer.clone(),
        )
        .await
        .unwrap();

        log::info!("About to build aggregator service");
        let aggregator_service = Aggregator::build(
            &setup_config,
            operator_info_service,
            config.server_ip_port_address.clone(),
        )
        .await
        .unwrap();

        log::info!("About to build aggregator RPC client");
        let aggregator_rpc_client = AggregatorRpcClient::new(config.server_ip_port_address.clone());

        log::info!("About to build eigenlayer contract manager");
        let eigenlayer_contract_manager = ElChainContractManager::build(
            setup_config.delegate_manager_addr,
            setup_config.avs_directory_addr,
            eth_client_http.clone(),
            eth_client_ws.clone(),
            signer.clone(),
        )
        .await
        .unwrap();

        // let mut salt = [0u8; 32];
        // rand::thread_rng().fill(&mut salt);
        // let sig_salt = FixedBytes::from_slice(&salt);
        // let current_block_number = eth_client_http.get_block_number().await.unwrap();
        // let expiry: U256 = U256::from(current_block_number + 20);
        // let quorum_nums = Bytes::from(vec![0]);
        // let register_result = avs_registry_contract_manager
        //     .register_operator_in_quorum_with_avs_registry_coordinator(
        //         &ecdsa_signing_key,
        //         sig_salt,
        //         expiry,
        //         &bls_keypair,
        //         quorum_nums,
        //         config.eth_rpc_url.clone(),
        //     )
        //     .await;
        let quorum_nums = Bytes::from(vec![0]);
        let register_result = avs_registry_contract_manager.register_operator(&ecdsa_signing_key, &bls_keypair, quorum_nums, config.eth_rpc_url.clone()).await;
        log::info!("Register result: {:?}", register_result);

        let answer = avs_registry_contract_manager
            .is_operator_registered(operator_address)
            .await
            .unwrap();
        log::info!("Is operator registered: {:?}", answer);

        let operator_id = avs_registry_contract_manager
            .get_operator_id(operator_address)
            .await?;

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
            avs_registry_contract_manager,
            incredible_squaring_contract_manager,
            eigenlayer_contract_manager,
            bls_keypair,
            operator_id,
            operator_addr: operator_address,
            aggregator_server_ip_port_addr: config.server_ip_port_address.clone(),
            aggregator_server: aggregator_service,
            aggregator_rpc_client,
        };

        // if config.register_operator_on_startup {
        //     operator.register_operator_on_startup(
        //         operator_ecdsa_private_key,
        //         config.token_strategy_addr.parse()?,
        //     );
        // }

        Ok(operator)
    }

    pub async fn start(self) -> Result<(), OperatorError> {
        log::info!("Starting operator.");
        let operator_is_registered = self
            .avs_registry_contract_manager
            .is_operator_registered(self.operator_addr)
            .await; //?;
                    // if !operator_is_registered {
                    //     return Err(OperatorError::OperatorNotRegistered);
                    // }
        log::info!("Operator registration status: {:?}", operator_is_registered);

        if self.config.enable_node_api {
            if let Err(e) = self.node_api.start().await {
                return Err(OperatorError::NodeApiError(e.to_string()));
            }
        }

        let mut sub = self
            .incredible_squaring_contract_manager
            .subscribe_to_new_tasks()
            .await
            .unwrap();

        log::info!("Subscribed to new tasks: {:?}", sub);
        log::info!("Raw Subscription: {:?}", sub.inner());

        let value = sub.recv().await.unwrap();
        log::info!("Received new task: {:?}", value);

        loop {
            log::info!("About to wait for a new task submissions");
            tokio::select! {
                Ok(new_task_created_log) = sub.recv() => {
                    log::info!("Received new task: {:?}", new_task_created_log);
                    // self.metrics.inc_num_tasks_received();
                    let log: Log<IncredibleSquaringTaskManager::NewTaskCreated> = new_task_created_log.log_decode().unwrap();
                    let task_response = self.process_new_task_created_log(&log);
                    if let Ok(signed_task_response) = self.sign_task_response(&task_response) {
                        let agg_rpc_client = self.aggregator_rpc_client.clone();
                        tokio::spawn(async move {
                            agg_rpc_client.send_signed_task_response_to_aggregator(signed_task_response).await;
                        });
                    }
                },
            }
        }
    }

    fn process_new_task_created_log(
        &self,
        new_task_created_log: &Log<IncredibleSquaringTaskManager::NewTaskCreated>,
    ) -> IncredibleSquaringTaskManager::TaskResponse {
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
        IncredibleSquaringTaskManager::TaskResponse {
            referenceTaskIndex: new_task_created_log.inner.taskIndex,
            numberSquared: number_squared,
        }
    }

    fn sign_task_response(
        &self,
        task_response: &IncredibleSquaringTaskManager::TaskResponse,
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{address, Address};
    use alloy_provider::Provider;
    use alloy_provider::ProviderBuilder;
    use alloy_signer_local::PrivateKeySigner;
    use alloy_transport_ws::WsConnect;
    use k256::ecdsa::VerifyingKey;
    use k256::elliptic_curve::SecretKey;
    use std::path::Path;
    use std::time::Duration;
    use std::vec;
    //, Bytes, U256};

    static BLS_PASSWORD: &str = "BLS_PASSWORD";
    static ECDSA_PASSWORD: &str = "ECDSA_PASSWORD";
    static TASK_RESPONSE_WINDOW_BLOCK: u32 = 10;
    static TASK_DURATION_BLOCKS: u32 = 0;
    // static QUORUM_THRESHOLD_PERCENTAGE: U256 = U256::from(100);
    static AGGREGATOR_ADDR: Address = address!("a0Ee7A142d267C1f36714E4a8F75612F20a79720");
    static TASK_GENERATOR_ADDR: Address = address!("a0Ee7A142d267C1f36714E4a8F75612F20a79720");

    use crate::avs;
    use alloy::signers::Signer;
    use alloy_provider::network::{TransactionBuilder, TxSigner};
    use alloy_rpc_types_eth::BlockId;
    use alloy_sol_types::private::SolTypeValue;
    use anvil::spawn;
    use ark_bn254::Fq as F;
    use ark_bn254::{Fr, G1Affine, G2Affine, G2Projective};
    use avs::IncredibleSquaringServiceManager;
    use eigen_contracts::RegistryCoordinator::{OperatorSetParam, StrategyParams};
    use eigen_contracts::*;
    use ethabi::ethereum_types::H160;
    use ethabi::{encode, Token};
    use gadget_common::subxt_signer::bip39::rand_core::OsRng;
    use url::Url;

    struct ContractAddresses {
        pub service_manager: Address,
        pub registry_coordinator: Address,
        pub operator_state_retriever: Address,
        pub delegation_manager: Address,
        pub avs_directory: Address,
        pub operator: Address,
    }

    // async fn run_anvil_testnet() -> ContractAddresses {
    //     // Initialize the logger
    //     let _ = env_logger::try_init();
    //
    //     let (api, mut handle) = spawn(anvil::NodeConfig::test().with_port(33125)).await;
    //     api.anvil_auto_impersonate_account(true).await.unwrap();
    //     // let http_provider = handle.http_provider();
    //     // let ws_provider = handle.ws_provider();
    //
    //     let _http_provider = ProviderBuilder::new()
    //         .on_http(Url::parse(&handle.http_endpoint()).unwrap())
    //         .root()
    //         .clone();
    //     // todo: http_provider is unused
    //
    //     // let provider = ProviderBuilder::new().on_ws(WsConnect::new(handle.ws_endpoint())).await.unwrap();
    //
    //     let provider = ProviderBuilder::new()
    //         .on_builtin(&handle.ws_endpoint())
    //         .await
    //         .unwrap();
    //
    //     let accounts = handle.dev_wallets().collect::<Vec<_>>();
    //     let from = accounts[0].address();
    //     let _to = accounts[1].address();
    //
    //     let _amount = handle
    //         .genesis_balance()
    //         .checked_div(U256::from(2u64))
    //         .unwrap();
    //
    //     let _gas_price = provider.get_gas_price().await.unwrap();
    //
    //     // Empty address for initial deployment of all contracts
    //     let empty_address = Address::default();
    //
    //     // let strategy_manager_addr = address!("Dc64a140Aa3E981100a9becA4E685f962f0cF6C9");
    //     // let delegation_manager_addr = address!("Cf7Ed3AccA5a467e9e704C703E8D87F634fB0Fc9");
    //     // let avs_directory_addr = address!("5FC8d32690cc91D4c39d9d3abcBD16989F875707");
    //     // let proxy_admin_addr = address!("5FbDB2315678afecb367f032d93F642f64180aa3");
    //     // let pauser_registry_addr = address!("e7f1725E7734CE288F8367e1Bb143E90bb3F0512");
    //     // let base_strategy_addr = address!("322813Fd9A801c5507c9de605d63CEA4f2CE6c44");
    //
    //     // Deploy Eigenlayer Contracts
    //     let strategy_manager_addr = address!("Dc64a140Aa3E981100a9becA4E685f962f0cF6C9");
    //     let delegation_manager_addr = address!("Cf7Ed3AccA5a467e9e704C703E8D87F634fB0Fc9");
    //     let avs_directory_addr = address!("5FC8d32690cc91D4c39d9d3abcBD16989F875707");
    //     let proxy_admin_addr = address!("5FbDB2315678afecb367f032d93F642f64180aa3");
    //     let pauser_registry_addr = address!("e7f1725E7734CE288F8367e1Bb143E90bb3F0512");
    //     let base_strategy_addr = address!("322813Fd9A801c5507c9de605d63CEA4f2CE6c44");
    //
    //     let istrategy_manager = IStrategyManager::new(strategy_manager_addr, provider.clone());
    //     let idelegation_manager =
    //         IDelegationManager::new(delegation_manager_addr, provider.clone());
    //     let iavs_directory = IAVSDirectory::new(avs_directory_addr, provider.clone());
    //     let proxy_admin = ProxyAdmin::new(proxy_admin_addr, provider.clone());
    //     let pauser_registry = PauserRegistry::new(pauser_registry_addr, provider.clone());
    //     let base_strategy = StrategyBaseTVLLimits::new(base_strategy_addr, provider.clone());
    //     // let istrategy_manager = IStrategyManager::deploy(provider.clone()).await.unwrap();
    //     // let &strategy_manager_addr = istrategy_manager.address();
    //     //
    //     // let idelegation_manager = IDelegationManager::deploy(provider.clone()).await.unwrap();
    //     // let &delegation_manager_addr = idelegation_manager.address();
    //     //
    //     // let iavs_directory = IAVSDirectory::deploy(provider.clone()).await.unwrap();
    //     // let &avs_directory_addr = iavs_directory.address();
    //     //
    //     // let proxy_admin = ProxyAdmin::deploy(provider.clone()).await.unwrap();
    //     // let &proxy_admin_addr = proxy_admin.address();
    //     //
    //     // let pauser_registry = PauserRegistry::deploy(provider.clone()).await.unwrap();
    //     // let &pauser_registry_addr = pauser_registry.address();
    //     //
    //     // let base_strategy = StrategyBaseTVLLimits::deploy(provider.clone(), Default::default())
    //     //     .await
    //     //     .unwrap();
    //     // let &base_strategy_addr = base_strategy.address();
    //
    //     let erc20_mock = ERC20Mock::deploy(provider.clone()).await.unwrap();
    //     let &erc20_mock_addr = erc20_mock.address();
    //
    //     let ierc20 = IERC20::new(erc20_mock_addr, provider.clone());
    //     let &ierc20_addr = ierc20.address();
    //
    //     let tokens = vec![
    //         Token::Uint(1.into()),
    //         Token::Uint(100.into()),
    //         Token::Address(H160::from_slice(ierc20_addr.as_slice())),
    //         Token::Address(H160::from_slice(pauser_registry_addr.as_slice())),
    //     ];
    //     let encoded_data = encode(&tokens);
    //     let strategy_proxy = TransparentUpgradeableProxy::deploy(
    //         provider.clone(),
    //         base_strategy_addr,
    //         proxy_admin_addr,
    //         alloy_primitives::Bytes::from(encoded_data),
    //     )
    //     .await
    //     .unwrap();
    //     let &strategy_proxy_addr = strategy_proxy.address();
    //
    //     let erc20_mock_strategy =
    //         StrategyBaseTVLLimits::deploy(provider.clone(), strategy_proxy_addr)
    //             .await
    //             .unwrap();
    //     let &erc20_mock_strategy_addr = erc20_mock_strategy.address();
    //
    //     let strategies = vec![erc20_mock_strategy_addr];
    //
    //     let add_strategies = istrategy_manager
    //         .addStrategiesToDepositWhitelist(strategies, vec![false])
    //         .send()
    //         .await
    //         .unwrap()
    //         .get_receipt()
    //         .await
    //         .unwrap();
    //     println!("Add Strategies Receipt: {:?}", add_strategies);
    //
    //     // Deploy Incredible Squaring Contracts
    //     let number_of_strategies = strategies.len();
    //
    //     let incredible_squaring_proxy_admin = ProxyAdmin::deploy(provider.clone()).await.unwrap();
    //     let &incredible_squaring_proxy_admin_addr = incredible_squaring_proxy_admin.address();
    //
    //     let pausers = vec![
    //         address!("f39Fd6e51aad88F6F4ce6aB8827279cffFb92266"),
    //         address!("f39Fd6e51aad88F6F4ce6aB8827279cffFb92266"),
    //     ];
    //
    //     let incredible_squaring_pauser_registry_addr =
    //         PauserRegistry::deploy_builder(provider.clone())
    //             .from(from)
    //             .send()
    //             .await
    //             .unwrap()
    //             .get_receipt()
    //             .await
    //             .unwrap()
    //             .contract_address
    //             .unwrap();
    //     let incredible_squaring_pauser_registry =
    //         PauserRegistry::new(incredible_squaring_pauser_registry_addr, provider.clone());
    //     let is_pauser = incredible_squaring_pauser_registry
    //         .isPauser(address!("f39Fd6e51aad88F6F4ce6aB8827279cffFb92266"))
    //         .call()
    //         .await
    //         .unwrap();
    //     println!("Is Dev Account 0 Pauser: {:?}", is_pauser._0);
    //
    //     let empty_contract = EmptyContract::deploy(provider.clone()).await.unwrap();
    //     let &empty_contract_addr = empty_contract.address();
    //
    //     let incredible_squaring_service_manager = IncredibleSquaringServiceManager::new(
    //         TransparentUpgradeableProxy::deploy(
    //             provider.clone(),
    //             empty_contract_addr,
    //             incredible_squaring_proxy_admin_addr,
    //             Bytes::from(""),
    //         )
    //         .await
    //         .unwrap(),
    //         provider.clone(),
    //     );
    //     let &incredible_squaring_service_manager_addr =
    //         incredible_squaring_service_manager.address();
    //
    //     let incredible_squaring_task_manager = IncredibleSquaringTaskManager::new(
    //         TransparentUpgradeableProxy::deploy(
    //             provider.clone(),
    //             empty_contract_addr,
    //             incredible_squaring_proxy_admin_addr,
    //             Bytes::from(""),
    //         )
    //         .await
    //         .unwrap(),
    //         provider.clone(),
    //     );
    //     let &incredible_squaring_task_manager_addr = incredible_squaring_task_manager.address();
    //
    //     let registry_coordinator = RegistryCoordinator::new(
    //         TransparentUpgradeableProxy::deploy(
    //             provider.clone(),
    //             empty_contract_addr,
    //             incredible_squaring_proxy_admin_addr,
    //             Bytes::from(""),
    //         )
    //         .await
    //         .unwrap(),
    //         provider.clone(),
    //     );
    //     let &registry_coordinator_addr = registry_coordinator.address();
    //
    //     let bls_apk_registry = BlsApkRegistry::new(
    //         TransparentUpgradeableProxy::deploy(
    //             provider.clone(),
    //             empty_contract_addr,
    //             incredible_squaring_proxy_admin_addr,
    //             Bytes::from(""),
    //         )
    //         .await
    //         .unwrap(),
    //         provider.clone(),
    //     );
    //     let &bls_apk_registry_addr = bls_apk_registry.address();
    //
    //     let bls_apk_registry = IBlsApkRegistry::new(
    //         TransparentUpgradeableProxy::deploy(
    //             provider.clone(),
    //             empty_contract_addr,
    //             incredible_squaring_proxy_admin_addr,
    //             Bytes::from(""),
    //         )
    //         .await
    //         .unwrap(),
    //         provider.clone(),
    //     );
    //     let &bls_apk_registry_addr = bls_apk_registry.address();
    //
    //     let index_registry = IIndexRegistry::new(
    //         TransparentUpgradeableProxy::deploy(
    //             provider.clone(),
    //             empty_contract_addr,
    //             incredible_squaring_proxy_admin_addr,
    //             Bytes::from(""),
    //         )
    //         .await
    //         .unwrap(),
    //         provider.clone(),
    //     );
    //     let &index_registry_addr = index_registry.address();
    //
    //     let stake_registry = IStakeRegistry::new(
    //         TransparentUpgradeableProxy::deploy(
    //             provider.clone(),
    //             empty_contract_addr,
    //             incredible_squaring_proxy_admin_addr,
    //             Bytes::from(""),
    //         )
    //         .await
    //         .unwrap(),
    //         provider.clone(),
    //     );
    //     let &stake_registry_addr = stake_registry.address();
    //
    //     let operator_state_retriever = OperatorStateRetriever::deploy(provider.clone())
    //         .await
    //         .unwrap();
    //     let &operator_state_retriever_addr = operator_state_retriever.address();
    //
    //     //Now, deploy the implementation contracts using the proxy contracts as inputs
    //     let stake_registry_implementation = StakeRegistry::deploy(
    //         provider.clone(),
    //         registry_coordinator_addr,
    //         delegation_manager_addr,
    //     )
    //     .await
    //     .unwrap();
    //     let &stake_registry_implementation_addr = stake_registry_implementation.address();
    //     let stake_registry_upgrade = incredible_squaring_proxy_admin
    //         .upgrade(stake_registry_addr, stake_registry_implementation_addr)
    //         .send()
    //         .await
    //         .unwrap()
    //         .get_receipt()
    //         .await
    //         .unwrap();
    //     log::info!(
    //         "Stake Registry Upgrade Receipt: {:?}",
    //         stake_registry_upgrade
    //     );
    //
    //     let bls_apk_registry_implementation =
    //         BlsApkRegistry::deploy(provider.clone(), registry_coordinator_addr)
    //             .await
    //             .unwrap();
    //     let &bls_apk_registry_implementation_addr = bls_apk_registry_implementation.address();
    //     let bls_apk_registry_upgrade = incredible_squaring_proxy_admin
    //         .upgrade(bls_apk_registry_addr, bls_apk_registry_implementation_addr)
    //         .send()
    //         .await
    //         .unwrap()
    //         .get_receipt()
    //         .await
    //         .unwrap();
    //     log::info!(
    //         "Bls Apk Registry Upgrade Receipt: {:?}",
    //         bls_apk_registry_upgrade
    //     );
    //
    //     let index_registry_implementation =
    //         IndexRegistry::deploy(provider.clone(), registry_coordinator_addr)
    //             .await
    //             .unwrap();
    //     let &index_registry_implementation_addr = index_registry_implementation.address();
    //     let index_registry_upgrade = incredible_squaring_proxy_admin
    //         .upgrade(index_registry_addr, index_registry_implementation_addr)
    //         .send()
    //         .await
    //         .unwrap()
    //         .get_receipt()
    //         .await
    //         .unwrap();
    //     log::info!(
    //         "Index Registry Upgrade Receipt: {:?}",
    //         index_registry_upgrade
    //     );
    //
    //     let registry_coordinator_implementation = RegistryCoordinator::deploy(
    //         provider.clone(),
    //         incredible_squaring_service_manager_addr,
    //         stake_registry_addr,
    //         bls_apk_registry_addr,
    //         index_registry_addr,
    //     )
    //     .await
    //     .unwrap();
    //     let &registry_coordinator_implementation_addr =
    //         registry_coordinator_implementation.address();
    //     // let registry_coordinator_upgrade = incredible_squaring_proxy_admin.upgrade(
    //     //     registry_coordinator_addr,
    //     //     registry_coordinator_implementation_addr,
    //     // ).send().await.unwrap().get_receipt().await.unwrap();
    //     // log::info!("Registry Coordinator Upgrade Receipt: {:?}", registry_coordinator_upgrade);
    //
    //     let number_of_quorums = 1;
    //     // For each quorum we want to set up, we must define QuorumOperatorSetParam, minimumStakeForQuorum, and strategyParams
    //     let mut quorum_operator_set_params = Vec::<OperatorSetParam>::new();
    //     for i in 0..number_of_quorums {
    //         log::info!("Deploying quorum {}", i);
    //         quorum_operator_set_params.push(OperatorSetParam {
    //             maxOperatorCount: 10000,
    //             kickBIPsOfOperatorStake: 15000,
    //             kickBIPsOfTotalStake: 100,
    //         });
    //     }
    //     // Set to 0 for each quorum
    //     let quorums_minimum_stake = Vec::<u128>::new();
    //     let mut quorums_strategy_params = Vec::<Vec<StrategyParams>>::new();
    //
    //     for j in 0..number_of_quorums {
    //         quorums_strategy_params.push(Vec::<StrategyParams>::new());
    //         for k in 0..number_of_strategies {
    //             quorums_strategy_params[j][k] = StrategyParams {
    //                 strategy: strategies[j],
    //                 multiplier: 1,
    //             }
    //         }
    //     }
    //
    //     let tokens = vec![
    //         Token::Address(H160::from_slice(pausers[0].as_slice())),
    //         Token::Address(H160::from_slice(pausers[0].as_slice())),
    //         Token::Address(H160::from_slice(pausers[0].as_slice())),
    //         Token::Address(H160::from_slice(pausers[1].as_slice())),
    //         Token::Uint(0.into()),
    //         Token::Array(quorum_operator_set_params),
    //         Token::Array(quorums_minimum_stake),
    //         Token::Array(quorums_strategy_params),
    //     ];
    //     let encoded_data = encode(&tokens);
    //     let registry_coordinator_upgrade = incredible_squaring_proxy_admin
    //         .upgradeAndCall(
    //             registry_coordinator_addr,
    //             registry_coordinator_implementation_addr,
    //             alloy_primitives::Bytes::from(encoded_data),
    //         )
    //         .send()
    //         .await
    //         .unwrap()
    //         .get_receipt()
    //         .await
    //         .unwrap();
    //     log::info!(
    //         "Registry Coordinator Upgrade Receipt: {:?}",
    //         registry_coordinator_upgrade
    //     );
    //
    //     let incredible_squaring_service_manager_implementation =
    //         IncredibleSquaringServiceManager::deploy(
    //             provider.clone(),
    //             avs_directory_addr,
    //             registry_coordinator_addr,
    //             stake_registry_addr,
    //             incredible_squaring_task_manager_addr,
    //         )
    //         .await
    //         .unwrap();
    //     let &incredible_squaring_service_manager_implementation_addr =
    //         incredible_squaring_service_manager_implementation.address();
    //     let incredible_squaring_service_manager_upgrade = incredible_squaring_proxy_admin
    //         .upgrade(
    //             incredible_squaring_service_manager_addr,
    //             incredible_squaring_service_manager_implementation_addr,
    //         )
    //         .send()
    //         .await
    //         .unwrap()
    //         .get_receipt()
    //         .await
    //         .unwrap();
    //     log::info!(
    //         "Incredible Squaring Service Manager Upgrade Receipt: {:?}",
    //         incredible_squaring_service_manager_upgrade
    //     );
    //
    //     let tokens = vec![
    //         Token::Address(H160::from_slice(pauser_registry_addr.as_slice())),
    //         Token::Address(H160::from_slice(pausers[0].as_slice())),
    //         Token::Address(H160::from_slice(AGGREGATOR_ADDR.as_slice())),
    //         Token::Address(H160::from_slice(TASK_GENERATOR_ADDR.as_slice())),
    //     ];
    //     let encoded_data = encode(&tokens);
    //     let incredible_squaring_task_manager_implementation =
    //         IncredibleSquaringTaskManager::deploy(
    //             provider.clone(),
    //             registry_coordinator_addr,
    //             TASK_RESPONSE_WINDOW_BLOCK,
    //         )
    //         .await
    //         .unwrap();
    //     let &incredible_squaring_task_manager_implementation_addr =
    //         incredible_squaring_task_manager_implementation.address();
    //     let incredible_squaring_task_manager_upgrade = incredible_squaring_proxy_admin
    //         .upgradeAndCall(
    //             incredible_squaring_task_manager_addr,
    //             incredible_squaring_service_manager_implementation_addr,
    //             alloy_primitives::Bytes::from(encoded_data),
    //         )
    //         .send()
    //         .await
    //         .unwrap()
    //         .get_receipt()
    //         .await
    //         .unwrap();
    //     log::info!(
    //         "Incredible Squaring Task Manager Upgrade Receipt: {:?}",
    //         incredible_squaring_task_manager_upgrade
    //     );
    //
    //     log::info!("ERC20MOCK ADDRESS: {:?}", erc20_mock_addr);
    //     log::info!("ERC20MOCK STRATEGY ADDRESS: {:?}", erc20_mock_strategy_addr);
    //     log::info!(
    //         "INCREDIBLE SQUARING TASK MANAGER ADDRESS: {:?}",
    //         incredible_squaring_task_manager_addr
    //     );
    //     log::info!(
    //         "INCREDIBLE SQUARING TASK MANAGER IMPLEMENTATION ADDRESS: {:?}",
    //         incredible_squaring_task_manager_implementation_addr
    //     );
    //     log::info!(
    //         "INCREDIBLE SQUARING SERVICE MANAGER ADDRESS: {:?}",
    //         incredible_squaring_service_manager_addr
    //     );
    //     log::info!(
    //         "INCREDIBLE SQUARING SERVICE MANAGER IMPLEMENTATION ADDRESS: {:?}",
    //         incredible_squaring_service_manager_implementation_addr
    //     );
    //     log::info!(
    //         "REGISTRY COORDINATOR ADDRESS: {:?}",
    //         registry_coordinator_addr
    //     );
    //     log::info!(
    //         "REGISTRY COORDINATOR IMPLEMENTATION ADDRESS: {:?}",
    //         registry_coordinator_implementation_addr
    //     );
    //     log::info!(
    //         "OPERATOR STATE RETRIEVER ADDRESS: {:?}",
    //         operator_state_retriever_addr
    //     );
    //
    //     // let _block = provider
    //     //     .get_block(BlockId::latest(), false.into())
    //     //     .await
    //     //     .unwrap()
    //     //     .unwrap();
    //     //
    //     // api.anvil_set_auto_mine(true).await.unwrap();
    //     // let run_testnet = async move {
    //     //     let serv = handle.servers.pop().unwrap();
    //     //     let res = serv.await.unwrap();
    //     //     res.unwrap();
    //     // };
    //     // let spawner_task_manager_address = task_manager_addr.clone();
    //     // // let spawner_provider = provider.clone();
    //     // let spawner_provider = provider;
    //     // let task_spawner = async move {
    //     //     let manager = IncredibleSquaringTaskManager::new(
    //     //         spawner_task_manager_address,
    //     //         spawner_provider.clone(),
    //     //     );
    //     //     loop {
    //     //         api.mine_one().await;
    //     //         log::info!("About to create new task");
    //     //         tokio::time::sleep(std::time::Duration::from_millis(5000)).await;
    //     //         let result = manager
    //     //             .createNewTask(U256::from(2), 100u32, Bytes::from("0"))
    //     //             .send()
    //     //             .await
    //     //             .unwrap()
    //     //             .watch()
    //     //             .await
    //     //             .unwrap();
    //     //         api.mine_one().await;
    //     //         log::info!("Created new task: {:?}", result);
    //     //         // let latest_task = manager.latestTaskNum().call().await.unwrap()._0;
    //     //         // log::info!("Latest task: {:?}", latest_task);
    //     //         // let task_hash = manager.allTaskHashes(latest_task).call().await.unwrap()._0;
    //     //         // log::info!("Task info: {:?}", task_hash);
    //     //     }
    //     // };
    //     // tokio::spawn(run_testnet);
    //     // tokio::spawn(task_spawner);
    //
    //     ContractAddresses {
    //         service_manager: incredible_squaring_service_manager_implementation_addr,
    //         registry_coordinator: registry_coordinator_implementation_addr,
    //         operator_state_retriever: operator_state_retriever_addr,
    //         delegation_manager: delegation_manager_addr,
    //         avs_directory: avs_directory_addr,
    //         operator: from,
    //     }
    // }

    #[tokio::test]
    async fn test_anvil() {
        env_logger::init();

        // // Runs new Anvil Testnet - used for deploying programmatically in rust
        // let contract_addresses = run_anvil_testnet().await;

        // // Runs saved Anvil Testnet - loads from saved chain state JSON file
        // let chain = eigen_utils::test_utils::local_chain::LocalEvmChain::new_with_chain_state(
        //     31337,
        //     String::from("eigen-testnet"),
        //     Path::new("../../eigen-utils/saved-anvil-state.json"),
        //     Some(8545u16),
        // );
        // let chain_id = chain.chain_id();
        // let chain_name = chain.name();
        // println!("chain_id: {:?}", chain_id);
        // println!("chain_name: {:?}", chain_name);

        let account_one = address!("f39Fd6e51aad88F6F4ce6aB8827279cffFb92266");
        let account_two = address!("70997970C51812dc3A010C7d01b50e0d17dc79C8");

        let contract_addresses = ContractAddresses {
            service_manager: address!("84eA74d481Ee0A5332c457a4d796187F6Ba67fEB"),
            registry_coordinator: address!("a82fF9aFd8f496c3d6ac40E2a0F282E47488CFc9"),
            operator_state_retriever: address!("95401dc811bb5740090279Ba06cfA8fcF6113778"),
            delegation_manager: address!("Cf7Ed3AccA5a467e9e704C703E8D87F634fB0Fc9"),
            avs_directory: address!("5FC8d32690cc91D4c39d9d3abcBD16989F875707"),
            operator: account_two,
        };

        // Implementation version of addresses
        // let contract_addresses = ContractAddresses {
        //     service_manager: address!("84eA74d481Ee0A5332c457a4d796187F6Ba67fEB"),
        //     registry_coordinator: address!("9d4454B023096f34B160D6B654540c56A1F81688"),
        //     operator_state_retriever: address!("95401dc811bb5740090279Ba06cfA8fcF6113778"),
        //     delegation_manager: address!("B7f8BC63BbcaD18155201308C8f3540b07f84F5e"),
        //     avs_directory: address!("0DCd1Bf9A1b36cE34237eEaFef220932846BCD82"),
        //     operator: address!("f39Fd6e51aad88F6F4ce6aB8827279cffFb92266"),
        // };

        let http_endpoint = "http://127.0.0.1:8545";
        let ws_endpoint = "ws://127.0.0.1:8545";
        let node_config = NodeConfig {
            node_api_ip_port_address: "127.0.0.1:9808".to_string(),
            eth_rpc_url: http_endpoint.to_string(),
            eth_ws_url: ws_endpoint.to_string(),
            bls_private_key_store_path: "./keystore/bls".to_string(),
            ecdsa_private_key_store_path: "./keystore/ecdsa".to_string(),
            incredible_squaring_service_manager_addr: contract_addresses
                .service_manager
                .to_string(),
            avs_registry_coordinator_addr: contract_addresses.registry_coordinator.to_string(),
            operator_state_retriever_addr: contract_addresses.operator_state_retriever.to_string(),
            eigen_metrics_ip_port_address: "127.0.0.1:9100".to_string(),
            delegation_manager_addr: contract_addresses.delegation_manager.to_string(),
            avs_directory_addr: contract_addresses.avs_directory.to_string(),
            operator_address: contract_addresses.operator.to_string(),
            enable_metrics: false,
            enable_node_api: false,
            server_ip_port_address: "".to_string(),
        };

        let operator_info_service = OperatorInfoService {};

        let hex_key =
            hex::decode("59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d")
                .unwrap();
        let secret_key = SecretKey::from_slice(&hex_key).unwrap();
        let signing_key = SigningKey::from(secret_key.clone());
        let signer = EigenGadgetSigner {
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

        let operator = Operator::<NodeConfig, OperatorInfoService>::new_from_config(
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
        .unwrap();

        operator.start().await.unwrap();
    }

    #[tokio::test]
    async fn test_start_chain_from_state() {
        env_logger::init();

        let chain = eigen_utils::test_utils::local_chain::LocalEvmChain::new_with_chain_state(
            31337,
            String::from("eigen-testnet"),
            Path::new("../../eigen-utils/eigen-gadget-anvil-state.json"),
            Some(8545u16),
        );
        let chain_id = chain.chain_id();
        let chain_name = chain.name();
        println!("chain_id: {:?}", chain_id);
        println!("chain_name: {:?}", chain_name);
        let addresses = chain.addresses();
        println!("addresses: {:?}", addresses);
        tokio::time::sleep(Duration::from_secs(5)).await;
        println!("Now shutting down...");
        chain.shutdown();
    }

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
        // let hex_key =
        //     hex::decode("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
        //         .unwrap();

        // Second Account
        let hex_key =
            hex::decode("59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d")
                .unwrap();

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
