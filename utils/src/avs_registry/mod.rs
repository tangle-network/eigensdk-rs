use alloy_primitives::Address;

use eigen_contracts::RegistryCoordinator;

use crate::{el_contracts::ElChainContractManager, types::AvsError, Config};

pub mod reader;
pub mod subscriber;
pub mod writer;

pub type AvsRegistryContractResult<T> = Result<T, AvsError>;

#[derive(Clone)]
pub struct AvsRegistryContractManager<T: Config> {
    service_manager_addr: Address,
    bls_apk_registry_addr: Address,
    registry_coordinator_addr: Address,
    operator_state_retriever_addr: Address,
    stake_registry_addr: Address,
    eth_client_http: T::PH,
    eth_client_ws: T::PW,
    el_contract_manager: ElChainContractManager<T>,
    signer: T::S,
}

impl<T: Config> AvsRegistryContractManager<T> {
    #[allow(clippy::too_many_arguments)]
    pub async fn build(
        service_manager_addr: Address,
        registry_coordinator_addr: Address,
        operator_state_retriever_addr: Address,
        delegation_manager_addr: Address,
        avs_directory_addr: Address,
        eth_client_http: T::PH,
        eth_client_ws: T::PW,
        signer: T::S,
    ) -> Result<Self, AvsError> {
        // let http_provider = ProviderBuilder::new()
        //     .on_http("http://127.0.0.1:33125".parse().unwrap());

        let registry_coordinator =
            RegistryCoordinator::new(registry_coordinator_addr, eth_client_http.clone());
        println!("AVS BUILD CHECKPOINT 1");
        println!("Registry Coordinator: {:?}", registry_coordinator_addr);

        println!("BLS APK REGISTRY BUILDER");
        let bls_apk_registry_addr = registry_coordinator.blsApkRegistry();

        println!("BLS APK REGISTRY REQUESTING CALL");
        let debug_one = bls_apk_registry_addr.call();

        println!("BLS APK REGISTRY AWAITING CALL");
        let debug_two = debug_one.await;

        println!("BLS APK REGISTRY ADDRESS");
        let debug_three = debug_two.map(|addr| addr._0);

        println!("BLS APK REGISTRY ADDRESS RESULT: {:?}", debug_three);
        let bls_apk_registry_addr = debug_three?;

        println!("AVS BUILD CHECKPOINT 2");

        let stake_registry_addr = registry_coordinator
            .stakeRegistry()
            .call()
            .await
            .map(|addr| addr._0)?;

        println!("AVS BUILD CHECKPOINT 3");

        let el_contract_manager = ElChainContractManager::build(
            delegation_manager_addr,
            avs_directory_addr,
            eth_client_http.clone(),
            eth_client_ws.clone(),
            signer.clone(),
        )
        .await?;

        println!("AVS BUILD CHECKPOINT 4");

        Ok(AvsRegistryContractManager {
            service_manager_addr,
            bls_apk_registry_addr,
            registry_coordinator_addr,
            operator_state_retriever_addr,
            stake_registry_addr,
            eth_client_http,
            eth_client_ws,
            el_contract_manager,
            signer,
        })
    }
}
