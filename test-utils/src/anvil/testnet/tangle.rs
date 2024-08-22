#![allow(dead_code)]
use crate::encode_params;
use alloy_primitives::{address, Address, Bytes, Keccak256, U256};
use alloy_provider::ProviderBuilder;
use alloy_sol_types::{abi, SolValue};
use anvil::spawn;
use eigen_contracts::{
    RegistryCoordinator::{OperatorSetParam, StrategyParams},
    *,
};
use tangle_avs::{TangleValidatorServiceManager, TangleValidatorTaskManager};

pub static BLS_PASSWORD: &str = "BLS_PASSWORD";
pub static ECDSA_PASSWORD: &str = "ECDSA_PASSWORD";
pub static TASK_RESPONSE_WINDOW_BLOCK: u32 = 10;
pub static TASK_DURATION_BLOCKS: u32 = 0;
pub static AGGREGATOR_ADDR: Address = address!("a0Ee7A142d267C1f36714E4a8F75612F20a79720");
pub static TASK_GENERATOR_ADDR: Address = address!("a0Ee7A142d267C1f36714E4a8F75612F20a79720");

pub struct ContractAddresses {
    pub service_manager: Address,
    pub registry_coordinator: Address,
    pub operator_state_retriever: Address,
    pub delegation_manager: Address,
    pub avs_directory: Address,
    pub operator: Address,
}

/// Spawns and runs an Anvil node, deploying the Smart Contracts that are relevant to the Tangle AVS to it.
///
/// NOTE: This function will Panic upon contract deployment failure.
pub async fn run_tangle_testnet() -> ContractAddresses {
    // Initialize the logger
    let _ = env_logger::try_init();

    let (api, handle) = spawn(
        anvil::NodeConfig::test()
            .with_port(8545)
            .with_print_logs(true)
            .disable_block_gas_limit(true)
            .with_steps_tracing(true),
    )
    .await;
    api.anvil_auto_impersonate_account(true).await.unwrap();

    let provider = ProviderBuilder::new()
        .on_builtin(&handle.ws_endpoint())
        .await
        .unwrap();

    let accounts = handle.dev_wallets().collect::<Vec<_>>();
    let from = accounts[0].address();

    let dev_account = accounts[0].address();

    // Deploy initial contracts that don't depend on others

    let istrategy_manager = IStrategyManager::deploy(provider.clone()).await.unwrap();
    let &_strategy_manager_addr = istrategy_manager.address();

    let idelegation_manager = IDelegationManager::deploy(provider.clone()).await.unwrap();
    let &delegation_manager_addr = idelegation_manager.address();

    let iavs_directory = IAVSDirectory::deploy(provider.clone()).await.unwrap();
    let &_avs_directory_addr = iavs_directory.address();

    let proxy_admin = ProxyAdmin::deploy_builder(provider.clone())
        .from(dev_account)
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap()
        .contract_address
        .unwrap();
    let proxy_admin_addr = proxy_admin;

    let pauser_registry = PauserRegistry::deploy(provider.clone()).await.unwrap();
    let &pauser_registry_addr = pauser_registry.address();

    let base_strategy = StrategyBaseTVLLimits::deploy(provider.clone(), Default::default())
        .await
        .unwrap();
    let &base_strategy_addr = base_strategy.address();

    let erc20_mock = ERC20Mock::deploy(provider.clone()).await.unwrap();
    let &erc20_mock_addr = erc20_mock.address();

    let ierc20 = IERC20::new(erc20_mock_addr, provider.clone());
    let &ierc20_addr = ierc20.address();

    // Begin deploying with Proxies

    // Function with signature initialize(uint256,uint256,address,address) and selector 0x019e2729.
    let function_signature = "initialize(uint256,uint256,address,address)";

    let encoded_data = encode_params!(
        function_signature,
        1,
        100,
        ierc20_addr,
        pauser_registry_addr
    );

    let strategy_proxy = TransparentUpgradeableProxy::deploy(
        provider.clone(),
        base_strategy_addr,
        proxy_admin_addr,
        encoded_data,
    )
    .await
    .unwrap();
    let &strategy_proxy_addr = strategy_proxy.address();

    let erc20_mock_strategy = StrategyBaseTVLLimits::deploy(provider.clone(), strategy_proxy_addr)
        .await
        .unwrap();
    let &erc20_mock_strategy_addr = erc20_mock_strategy.address();

    let strategies = vec![erc20_mock_strategy_addr];

    let add_strategies = istrategy_manager
        .addStrategiesToDepositWhitelist(strategies.clone(), vec![false])
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();
    assert!(add_strategies.status());

    // Deploy Incredible Squaring Contracts
    let number_of_strategies = strategies.len();
    println!("Number of Strategies: {:?}", number_of_strategies);

    let tangle_validator_proxy_admin = ProxyAdmin::deploy_builder(provider.clone())
        .from(dev_account)
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();
    assert!(tangle_validator_proxy_admin.status());

    let tangle_validator_proxy_admin = tangle_validator_proxy_admin.contract_address.unwrap();
    let tangle_validator_proxy_admin_addr = tangle_validator_proxy_admin;
    let tangle_validator_proxy_admin =
        ProxyAdmin::new(tangle_validator_proxy_admin_addr, provider.clone());

    let pausers = [dev_account, dev_account];

    let tangle_validator_pauser_registry = PauserRegistry::deploy(provider.clone()).await.unwrap();
    let &_tangle_validator_pauser_registry_addr = tangle_validator_pauser_registry.address();

    let empty_contract = EmptyContract::deploy(provider.clone()).await.unwrap();
    let &empty_contract_addr = empty_contract.address();

    let tangle_validator_service_manager = TangleValidatorServiceManager::new(
        *TransparentUpgradeableProxy::deploy(
            provider.clone(),
            empty_contract_addr,
            tangle_validator_proxy_admin_addr,
            Bytes::from(""),
        )
        .await
        .unwrap()
        .address(),
        provider.clone(),
    );
    let &tangle_validator_service_manager_addr = tangle_validator_service_manager.address();

    let tangle_validator_task_manager = TangleValidatorTaskManager::new(
        *TransparentUpgradeableProxy::deploy(
            provider.clone(),
            empty_contract_addr,
            tangle_validator_proxy_admin_addr,
            Bytes::from(""),
        )
        .await
        .unwrap()
        .address(),
        provider.clone(),
    );
    let &tangle_validator_task_manager_addr = tangle_validator_task_manager.address();

    let registry_coordinator = RegistryCoordinator::new(
        *TransparentUpgradeableProxy::deploy(
            provider.clone(),
            empty_contract_addr,
            tangle_validator_proxy_admin_addr,
            Bytes::from(""),
        )
        .await
        .unwrap()
        .address(),
        provider.clone(),
    );
    let &registry_coordinator_addr = registry_coordinator.address();

    let bls_apk_registry = IBlsApkRegistry::new(
        *TransparentUpgradeableProxy::deploy(
            provider.clone(),
            empty_contract_addr,
            tangle_validator_proxy_admin_addr,
            Bytes::from(""),
        )
        .await
        .unwrap()
        .address(),
        provider.clone(),
    );
    let &bls_apk_registry_addr = bls_apk_registry.address();

    let index_registry = IIndexRegistry::new(
        *TransparentUpgradeableProxy::deploy(
            provider.clone(),
            empty_contract_addr,
            tangle_validator_proxy_admin_addr,
            Bytes::from(""),
        )
        .await
        .unwrap()
        .address(),
        provider.clone(),
    );
    let &index_registry_addr = index_registry.address();

    let stake_registry = IStakeRegistry::new(
        *TransparentUpgradeableProxy::deploy(
            provider.clone(),
            empty_contract_addr,
            tangle_validator_proxy_admin_addr,
            Bytes::from(""),
        )
        .await
        .unwrap()
        .address(),
        provider.clone(),
    );
    let &stake_registry_addr = stake_registry.address();

    let operator_state_retriever = OperatorStateRetriever::deploy(provider.clone())
        .await
        .unwrap();
    let &operator_state_retriever_addr = operator_state_retriever.address();

    let eth_pos = IETHPOSDeposit::deploy(provider.clone()).await.unwrap();
    let &eth_pos_addr = eth_pos.address();

    let eigen_pod_beacon = IBeacon::deploy(provider.clone()).await.unwrap();
    let &eigen_pod_beacon_addr = eigen_pod_beacon.address();

    let strategy_manager = StrategyManager::new(
        *TransparentUpgradeableProxy::deploy(
            provider.clone(),
            empty_contract_addr,
            tangle_validator_proxy_admin_addr,
            Bytes::from(""),
        )
        .await
        .unwrap()
        .address(),
        provider.clone(),
    );
    let &strategy_manager_addr = strategy_manager.address();

    let eigen_pod_manager = EigenPodManager::deploy(
        provider.clone(),
        eth_pos_addr,
        eigen_pod_beacon_addr,
        strategy_manager_addr,
        from,
        delegation_manager_addr,
    )
    .await
    .unwrap();
    let &eigen_pod_manager_addr = eigen_pod_manager.address();

    let slasher_addr = dev_account;
    let delegation_manager = DelegationManager::deploy(
        provider.clone(),
        strategy_manager_addr,
        slasher_addr,
        eigen_pod_manager_addr,
    )
    .await
    .unwrap();
    let &delegation_manager_addr = delegation_manager.address();

    let strategy_manager_implementation = StrategyManager::deploy(
        provider.clone(),
        delegation_manager_addr,
        eigen_pod_manager_addr,
        slasher_addr,
    )
    .await
    .unwrap();
    let &strategy_manager_implementation_addr = strategy_manager_implementation.address();
    let strategy_manager_upgrade = tangle_validator_proxy_admin
        .upgrade(strategy_manager_addr, strategy_manager_implementation_addr)
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();
    assert!(strategy_manager_upgrade.status());

    let strategy_manager_initialization = strategy_manager
        .initialize(pausers[0], pausers[0], pauser_registry_addr, U256::from(0))
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();
    assert!(strategy_manager_initialization.status());

    let avs_directory = AVSDirectory::deploy(provider.clone(), delegation_manager_addr)
        .await
        .unwrap();
    let &avs_directory_addr = avs_directory.address();

    // Now, deploy the implementation contracts using the proxy contracts as inputs
    let stake_registry_implementation = StakeRegistry::deploy(
        provider.clone(),
        registry_coordinator_addr,
        delegation_manager_addr,
    )
    .await
    .unwrap();
    let &stake_registry_implementation_addr = stake_registry_implementation.address();
    let stake_registry_upgrade = tangle_validator_proxy_admin
        .upgrade(stake_registry_addr, stake_registry_implementation_addr)
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();
    assert!(stake_registry_upgrade.status());

    let bls_apk_registry_implementation =
        BlsApkRegistry::deploy(provider.clone(), registry_coordinator_addr)
            .await
            .unwrap();
    let &bls_apk_registry_implementation_addr = bls_apk_registry_implementation.address();
    let bls_apk_registry_upgrade = tangle_validator_proxy_admin
        .upgrade(bls_apk_registry_addr, bls_apk_registry_implementation_addr)
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();
    assert!(bls_apk_registry_upgrade.status());

    let index_registry_implementation =
        IndexRegistry::deploy(provider.clone(), registry_coordinator_addr)
            .await
            .unwrap();
    let &index_registry_implementation_addr = index_registry_implementation.address();
    let index_registry_upgrade = tangle_validator_proxy_admin
        .upgrade(index_registry_addr, index_registry_implementation_addr)
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();
    assert!(index_registry_upgrade.status());

    let registry_coordinator_implementation = RegistryCoordinator::deploy(
        provider.clone(),
        tangle_validator_service_manager_addr,
        stake_registry_addr,
        bls_apk_registry_addr,
        index_registry_addr,
    )
    .await
    .unwrap();
    let &registry_coordinator_implementation_addr = registry_coordinator_implementation.address();

    let number_of_quorums = 1;
    // For each quorum we want to set up, we must define QuorumOperatorSetParam, minimumStakeForQuorum, and strategyParams
    let mut quorum_operator_set_params = Vec::<OperatorSetParam>::new();
    for i in 0..number_of_quorums {
        log::info!("Deploying quorum {}", i);
        quorum_operator_set_params.push(OperatorSetParam {
            maxOperatorCount: 10000,
            kickBIPsOfOperatorStake: 15000,
            kickBIPsOfTotalStake: 100,
        });
    }
    // Set to 0 for each quorum
    let mut quorums_minimum_stake = Vec::<u128>::new();
    let mut quorums_strategy_params = Vec::<Vec<StrategyParams>>::new();
    for j in 0..number_of_quorums {
        quorums_strategy_params.push(Vec::<StrategyParams>::new());
        quorums_minimum_stake.push(0);
        for _k in 0..number_of_strategies {
            quorums_strategy_params[j].push(StrategyParams {
                strategy: strategies[j],
                multiplier: 1,
            });
        }
    }

    // Function with signature initialize(address,address,address,address,uint256,(uint32,uint16,uint16)[],uint96[],(address,uint96)[][]) and selector 0xdd8283f3.
    let function_signature = "initialize(address,address,address,address,uint256,(uint32,uint16,uint16)[],uint96[],(address,uint96)[][])";
    let _encoded_data = encode_params!(
        function_signature,
        pausers[0],
        pausers[0],
        pausers[0],
        pausers[1],
        0,
        quorum_operator_set_params,
        quorums_minimum_stake,
        quorums_strategy_params
    );

    let registry_coordinator_upgrade = tangle_validator_proxy_admin
        .upgrade(
            registry_coordinator_addr,
            registry_coordinator_implementation_addr,
        )
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();
    assert!(registry_coordinator_upgrade.status());

    let registry_coordinator_initialization = registry_coordinator
        .initialize(
            pausers[0],
            pausers[0],
            pausers[0],
            pausers[1],
            U256::from(0),
            quorum_operator_set_params,
            quorums_minimum_stake,
            quorums_strategy_params,
        )
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();
    assert!(registry_coordinator_initialization.status());

    let tangle_validator_service_manager_implementation = TangleValidatorServiceManager::deploy(
        provider.clone(),
        avs_directory_addr,
        registry_coordinator_addr,
        stake_registry_addr,
        tangle_validator_task_manager_addr,
    )
    .await
    .unwrap();
    let &tangle_validator_service_manager_implementation_addr =
        tangle_validator_service_manager_implementation.address();
    let tangle_validator_service_manager_upgrade = tangle_validator_proxy_admin
        .upgrade(
            tangle_validator_service_manager_addr,
            tangle_validator_service_manager_implementation_addr,
        )
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();
    assert!(tangle_validator_service_manager_upgrade.status());

    // Function with signature initialize(address,address) and selector 0x485cc955
    let function_signature = "initialize(address,address)";
    let encoded_data = encode_params!(function_signature, pauser_registry_addr, pausers[0]);

    let tangle_validator_task_manager_implementation =
        TangleValidatorTaskManager::deploy_builder(provider.clone(), registry_coordinator_addr)
            .send()
            .await
            .unwrap()
            .get_receipt()
            .await
            .unwrap();
    assert!(tangle_validator_task_manager_implementation.status());

    let tangle_validator_task_manager_implementation_addr =
        tangle_validator_task_manager_implementation
            .contract_address
            .unwrap();

    let tangle_validator_task_manager_upgrade = tangle_validator_proxy_admin
        .upgradeAndCall(
            tangle_validator_task_manager_addr,
            tangle_validator_task_manager_implementation_addr,
            encoded_data,
        )
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();
    assert!(tangle_validator_task_manager_upgrade.status());

    log::info!("ERC20MOCK ADDRESS: {:?}", erc20_mock_addr);
    log::info!("ERC20MOCK STRATEGY ADDRESS: {:?}", erc20_mock_strategy_addr);
    log::info!(
        "TANGLE VALIDATOR TASK MANAGER ADDRESS: {:?}",
        tangle_validator_task_manager_addr
    );
    log::info!(
        "TANGLE VALIDATOR TASK MANAGER IMPLEMENTATION ADDRESS: {:?}",
        tangle_validator_task_manager_implementation_addr
    );
    log::info!(
        "TANGLE VALIDATOR SERVICE MANAGER ADDRESS: {:?}",
        tangle_validator_service_manager_addr
    );
    log::info!(
        "TANGLE VALIDATOR SERVICE MANAGER IMPLEMENTATION ADDRESS: {:?}",
        tangle_validator_service_manager_implementation_addr
    );
    log::info!(
        "REGISTRY COORDINATOR ADDRESS: {:?}",
        registry_coordinator_addr
    );
    log::info!(
        "REGISTRY COORDINATOR IMPLEMENTATION ADDRESS: {:?}",
        registry_coordinator_implementation_addr
    );
    log::info!(
        "OPERATOR STATE RETRIEVER ADDRESS: {:?}",
        operator_state_retriever_addr
    );
    log::info!("DELEGATION MANAGER ADDRESS: {:?}", delegation_manager_addr);

    ContractAddresses {
        service_manager: tangle_validator_service_manager_addr,
        registry_coordinator: registry_coordinator_addr,
        operator_state_retriever: operator_state_retriever_addr,
        delegation_manager: delegation_manager_addr,
        avs_directory: avs_directory_addr,
        operator: from,
    }
}
