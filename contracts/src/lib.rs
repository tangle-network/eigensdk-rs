pub use avs_directory::AVSDirectory;
pub use bls_apk_registry::BlsApkRegistry;
pub use delegation_manager::{DelegationManager, IDelegationManager::OperatorDetails};
pub use eigen_pod::EigenPod;
pub use eigen_pod_manager::EigenPodManager;
pub use eigen_strategy::EigenStrategy;
pub use eip1271_signature_utils::EIP1271SignatureUtils;
pub use empty_contract::EmptyContract;
pub use erc20_mock::ERC20Mock;
pub use i_avs_directory::IAVSDirectory;
pub use i_beacon::IBeacon;
pub use i_bls_apk_registry::IBlsApkRegistry;
pub use i_delegation_manager::IDelegationManager;
pub use i_index_registry::IIndexRegistry;
pub use i_registry_coordinator::IRegistryCoordinator;
pub use i_slasher::ISlasher;
pub use i_stake_registry::IStakeRegistry;
pub use i_strategy::IStrategy;
pub use i_strategy_manager::IStrategyManager;
pub use ierc20::IERC20;
pub use ieth_pos_deposit::IETHPOSDeposit;
pub use index_registry::IndexRegistry;
pub use operator_state_retriever::OperatorStateRetriever;
pub use pauser_registry::PauserRegistry;
pub use proxy_admin::ProxyAdmin;
pub use registry_coordinator::{
    IBLSApkRegistry::PubkeyRegistrationParams, IRegistryCoordinator::OperatorInfo,
    IRegistryCoordinator::OperatorSetParam, ISignatureUtils::SignatureWithSaltAndExpiry,
    IStakeRegistry::StrategyParams, RegistryCoordinator, BN254 as Bn254,
};
pub use service_manager_base::ServiceManagerBase;
pub use stake_registry::StakeRegistry;
pub use strategy_base_tvl_limits::StrategyBaseTVLLimits;
pub use strategy_manager::StrategyManager;
pub use transparent_upgradeable_proxy::TransparentUpgradeableProxy;

mod avs_directory {
    alloy_sol_types::sol!(
        #[allow(missing_docs)]
        #[sol(rpc)]
        AVSDirectory,
        "./out/AVSDirectory.sol/AVSDirectory.json"
    );
}

mod bls_apk_registry {
    alloy_sol_types::sol!(
        #[allow(missing_docs)]
        #[derive(Debug)]
        #[sol(rpc)]
        BlsApkRegistry,
        "./out/BLSApkRegistry.sol/BLSApkRegistry.json"
    );
}

mod delegation_manager {
    alloy_sol_types::sol!(
        #[allow(missing_docs)]
        #[sol(rpc)]
        DelegationManager,
        "./out/DelegationManager.sol/DelegationManager.json"
    );
}

mod eigen_pod {
    alloy_sol_types::sol!(
        #[allow(missing_docs)]
        #[sol(rpc)]
        EigenPod,
        "./lib/eigenlayer-middleware/out/EigenPod.sol/EigenPod.json"
    );
}

mod eigen_pod_manager {
    alloy_sol_types::sol!(
        #[allow(missing_docs)]
        #[sol(rpc)]
        EigenPodManager,
        "./out/EigenPodManager.sol/EigenPodManager.json"
    );
}

mod eigen_strategy {
    alloy_sol_types::sol!(
        #[allow(missing_docs)]
        #[sol(rpc)]
        EigenStrategy,
        "./lib/eigenlayer-middleware/lib/eigenlayer-contracts/out/EigenStrategy.sol/EigenStrategy.json"
    );
}

mod empty_contract {
    alloy_sol_types::sol!(
        #[allow(missing_docs)]
        #[sol(rpc)]
        EmptyContract,
        "./lib/eigenlayer-middleware/out/EmptyContract.sol/EmptyContract.json"
    );
}

mod erc20_mock {
    alloy_sol_types::sol!(
        #[allow(missing_docs)]
        #[sol(rpc)]
        ERC20Mock,
        "./lib/eigenlayer-middleware/lib/eigenlayer-contracts/out/ERC20Mock.sol/ERC20Mock.json"
    );
}

mod i_bls_apk_registry {
    alloy_sol_types::sol!(
        #[allow(missing_docs)]
        #[derive(Debug)]
        #[sol(rpc)]
        IBlsApkRegistry,
        "./out/IBLSApkRegistry.sol/IBLSApkRegistry.json"
    );
}

mod ierc20 {
    alloy_sol_types::sol!(
        #[allow(missing_docs)]
        #[sol(rpc)]
        IERC20,
        "./out/IERC20.sol/IERC20.json"
    );
}

mod index_registry {
    alloy_sol_types::sol!(
        #[allow(missing_docs)]
        #[sol(rpc)]
        IndexRegistry,
        "./lib/eigenlayer-middleware/out/IndexRegistry.sol/IndexRegistry.json"
    );
}

mod i_slasher {
    alloy_sol_types::sol!(
        #[allow(missing_docs)]
        #[sol(rpc)]
        ISlasher,
        "./out/ISlasher.sol/ISlasher.json"
    );
}

mod i_strategy {
    alloy_sol_types::sol!(
        #[allow(missing_docs)]
        #[sol(rpc)]
        IStrategy,
        "./out/IStrategy.sol/IStrategy.json"
    );
}

mod i_strategy_manager {
    alloy_sol_types::sol!(
        #[allow(missing_docs)]
        #[sol(rpc)]
        IStrategyManager,
        "./out/IStrategyManager.sol/IStrategyManager.json"
    );
}

mod operator_state_retriever {
    alloy_sol_types::sol!(
        #[allow(missing_docs)]
        #[sol(rpc)]
        OperatorStateRetriever,
        "./out/OperatorStateRetriever.sol/OperatorStateRetriever.json"
    );
}

mod pauser_registry {
    alloy_sol_types::sol!(
        #[allow(missing_docs)]
        #[sol(rpc)]
        PauserRegistry,
        "./lib/eigenlayer-middleware/out/IPauserRegistry.sol/IPauserRegistry.json"
    );
}

mod registry_coordinator {
    alloy_sol_types::sol!(
        #[allow(missing_docs, clippy::too_many_arguments)]
        #[sol(rpc)]
        RegistryCoordinator,
        "./out/RegistryCoordinator.sol/RegistryCoordinator.json"
    );
}

mod proxy_admin {
    alloy_sol_types::sol!(
        #[allow(missing_docs)]
        #[sol(rpc)]
        ProxyAdmin,
        "./lib/eigenlayer-middleware/out/ProxyAdmin.sol/ProxyAdmin.json"
    );
}

mod service_manager_base {
    alloy_sol_types::sol!(
        #[allow(missing_docs)]
        #[sol(rpc)]
        ServiceManagerBase,
        "./out/ServiceManagerBase.sol/ServiceManagerBase.json"
    );
}

mod stake_registry {
    alloy_sol_types::sol!(
        #[allow(missing_docs)]
        #[sol(rpc)]
        StakeRegistry,
        "./out/StakeRegistry.sol/StakeRegistry.json"
    );
}

mod strategy_base_tvl_limits {
    alloy_sol_types::sol!(
        #[allow(missing_docs)]
        #[sol(rpc)]
        StrategyBaseTVLLimits,
        "./lib/eigenlayer-middleware/lib/eigenlayer-contracts/out/StrategyBaseTVLLimits.sol/StrategyBaseTVLLimits.json"
    );
}

mod strategy_manager {
    alloy_sol_types::sol!(
        #[allow(missing_docs)]
        #[sol(rpc)]
        StrategyManager,
        "./out/StrategyManager.sol/StrategyManager.json"
    );
}

mod transparent_upgradeable_proxy {
    alloy_sol_types::sol!(
        #[allow(missing_docs)]
        #[sol(rpc)]
        TransparentUpgradeableProxy,
        "./lib/eigenlayer-middleware/out/TransparentUpgradeableProxy.sol/TransparentUpgradeableProxy.json"
    );
}

mod eip1271_signature_utils {
    alloy_sol_types::sol!(
        #[allow(missing_docs)]
        #[sol(rpc)]
        EIP1271SignatureUtils,
        "./out/EIP1271SignatureUtils.sol/EIP1271SignatureUtils.json"
    );
}

mod ieth_pos_deposit {
    alloy_sol_types::sol!(
        #[allow(missing_docs)]
        #[sol(rpc)]
        IETHPOSDeposit,
        "./out/IETHPOSDeposit.sol/IETHPOSDeposit.json"
    );
}

mod i_beacon {
    alloy_sol_types::sol!(
        #[allow(missing_docs)]
        #[sol(rpc)]
        IBeacon,
        "./out/IBeacon.sol/IBeacon.json"
    );
}

mod i_avs_directory {
    alloy_sol_types::sol!(
        #[allow(missing_docs)]
        #[sol(rpc)]
        IAVSDirectory,
        "./out/IAVSDirectory.sol/IAVSDirectory.json"
    );
}

mod i_delegation_manager {
    alloy_sol_types::sol!(
        #[allow(missing_docs)]
        #[sol(rpc)]
        IDelegationManager,
        "./out/IDelegationManager.sol/IDelegationManager.json"
    );
}

mod i_index_registry {
    alloy_sol_types::sol!(
        #[allow(missing_docs)]
        #[sol(rpc)]
        IIndexRegistry,
        "./out/IIndexRegistry.sol/IIndexRegistry.json"
    );
}

mod i_stake_registry {
    alloy_sol_types::sol!(
        #[allow(missing_docs)]
        #[sol(rpc)]
        IStakeRegistry,
        "./out/IStakeRegistry.sol/IStakeRegistry.json"
    );
}

mod i_registry_coordinator {
    alloy_sol_types::sol!(
        #[allow(missing_docs, clippy::too_many_arguments)]
        #[sol(rpc)]
        IRegistryCoordinator,
        "./out/IRegistryCoordinator.sol/IRegistryCoordinator.json"
    );
}
