#![allow(async_fn_in_trait)]
use super::{AvsRegistryContractManager, AvsRegistryContractResult};
use crate::crypto::bls::{G1Point, KeyPair};
use crate::crypto::ecdsa::ToAddress;
use crate::el_contracts::reader::ElReader;
use crate::{types::*, Config};
use alloy_primitives::{Address, Bytes, FixedBytes, U256};
use alloy_provider::Provider;
use alloy_rpc_types::TransactionReceipt;
use alloy_signer::k256::ecdsa;
use alloy_signer::Signer as alloySigner;
use eigen_contracts::{
    Bn254, PubkeyRegistrationParams, RegistryCoordinator, SignatureWithSaltAndExpiry,
};
use k256::ecdsa::VerifyingKey;
use rand::Rng;

pub trait AvsRegistryChainWriterTrait {
    async fn register_operator(
        &self,
        operator_ecdsa_private_key: &ecdsa::SigningKey,
        bls_key_pair: &KeyPair,
        quorum_numbers: Bytes,
        socket: String,
    ) -> AvsRegistryContractResult<TransactionReceipt>;
    async fn register_operator_in_quorum_with_avs_registry_coordinator(
        &self,
        operator_ecdsa_private_key: &ecdsa::SigningKey,
        operator_to_avs_registration_sig_salt: FixedBytes<32>,
        operator_to_avs_registration_sig_expiry: U256,
        bls_key_pair: &KeyPair,
        quorum_numbers: Bytes,
        socket: String,
    ) -> AvsRegistryContractResult<TransactionReceipt>;

    async fn update_stakes_of_entire_operator_set_for_quorums(
        &self,
        operators_per_quorum: Vec<Vec<Address>>,
        quorum_numbers: Bytes,
    ) -> AvsRegistryContractResult<TransactionReceipt>;

    async fn update_stakes_of_operator_subset_for_all_quorums(
        &self,
        operators: Vec<Address>,
    ) -> AvsRegistryContractResult<TransactionReceipt>;

    async fn deregister_operator(
        &self,
        quorum_numbers: Bytes,
    ) -> AvsRegistryContractResult<TransactionReceipt>;
}

impl<T: Config> AvsRegistryChainWriterTrait for AvsRegistryContractManager<T> {
    async fn register_operator(
        &self,
        operator_ecdsa_private_key: &ecdsa::SigningKey,
        bls_key_pair: &KeyPair,
        quorum_numbers: Bytes,
        socket: String,
    ) -> AvsRegistryContractResult<TransactionReceipt> {
        let operator_addr = operator_ecdsa_private_key.verifying_key().to_address();
        log::info!("Operator address: {:?}", operator_addr);
        let registry_coordinator =
            RegistryCoordinator::new(self.registry_coordinator_addr, self.eth_client_http.clone());

        let g1_hashed_msg_to_sign = registry_coordinator
            .pubkeyRegistrationMessageHash(operator_addr)
            .from(operator_addr)
            .call()
            .await
            .map(|x| x._0)
            .map_err(AvsError::from)?;

        let g1_point = G1Point {
            x: g1_hashed_msg_to_sign.X,
            y: g1_hashed_msg_to_sign.Y,
        };

        let signed_msg = bls_key_pair
            .sign_hashed_to_curve_message(&g1_point)
            .g1_point;
        let g1_pubkey_bn254 = bls_key_pair.get_pub_key_g1();
        let g2_pubkey_bn254 = bls_key_pair.get_pub_key_g2();

        let pubkey_reg_params = PubkeyRegistrationParams {
            pubkeyRegistrationSignature: Bn254::G1Point {
                X: signed_msg.x,
                Y: signed_msg.y,
            },
            pubkeyG1: Bn254::G1Point {
                X: g1_pubkey_bn254.x,
                Y: g1_pubkey_bn254.y,
            },
            pubkeyG2: Bn254::G2Point {
                X: g2_pubkey_bn254.x,
                Y: g2_pubkey_bn254.y,
                //X: [g2_pubkey_bn254.x[1], g2_pubkey_bn254.x[0]],
                //Y: [g2_pubkey_bn254.y[1], g2_pubkey_bn254.y[0]],
            },
        };

        // Generate a random salt and 1 hour expiry for the signature
        let mut rng = rand::thread_rng();
        let mut operator_to_avs_registration_sig_salt = [0u8; 32];
        rng.fill(&mut operator_to_avs_registration_sig_salt);
        let operator_to_avs_registration_sig_salt =
            FixedBytes::from(operator_to_avs_registration_sig_salt);

        let cur_block_num = self.eth_client_http.get_block_number().await?;
        let cur_block = self
            .eth_client_http
            .get_block_by_number(cur_block_num.into(), false)
            .await?
            .unwrap();
        let sig_valid_for_seconds = 60 * 60; // 1 hour
        let operator_to_avs_registration_sig_expiry =
            U256::from(cur_block.header.timestamp + sig_valid_for_seconds);

        let msg_to_sign = self
            .el_contract_manager
            .calculate_operator_avs_registration_digest_hash(
                operator_addr,
                self.service_manager_addr,
                operator_to_avs_registration_sig_salt,
                operator_to_avs_registration_sig_expiry,
            )
            .await?;

        let operator_signature = self
            .signer
            .sign_hash(&msg_to_sign)
            .await
            .map_err(AvsError::from)?;
        let operator_signature_bytes = operator_signature.as_bytes();
        log::info!(
            "Operator Hash signature as bytes: {:?}",
            operator_signature_bytes
        );
        let operator_signature_bytes = Bytes::from(operator_signature_bytes);
        log::info!(
            "Operator Hash signature in Alloy Bytes: {:?}",
            operator_signature_bytes
        );

        let operator_signature_with_salt_and_expiry = SignatureWithSaltAndExpiry {
            signature: operator_signature_bytes,
            salt: operator_to_avs_registration_sig_salt,
            expiry: operator_to_avs_registration_sig_expiry,
        };

        let tx = registry_coordinator
            .registerOperator(
                quorum_numbers,
                socket,
                pubkey_reg_params,
                operator_signature_with_salt_and_expiry,
            )
            .from(operator_addr);

        let receipt = tx.send().await?.get_receipt().await.unwrap();

        Ok(receipt)
    }

    /// NOTICE: This function is considered to be deprecated in original Go implementation
    async fn register_operator_in_quorum_with_avs_registry_coordinator(
        &self,
        operator_ecdsa_private_key: &ecdsa::SigningKey,
        operator_to_avs_registration_sig_salt: FixedBytes<32>,
        operator_to_avs_registration_sig_expiry: U256,
        bls_key_pair: &KeyPair,
        quorum_numbers: Bytes,
        socket: String,
    ) -> AvsRegistryContractResult<TransactionReceipt> {
        let verifying_key = VerifyingKey::from(operator_ecdsa_private_key);
        let operator_addr = verifying_key.to_address();
        log::info!("Operator address: {:?}", operator_addr);

        let registry_coordinator =
            RegistryCoordinator::new(self.registry_coordinator_addr, self.eth_client_http.clone());

        let g1_hashed_msg_to_sign = registry_coordinator
            .pubkeyRegistrationMessageHash(operator_addr)
            .call()
            .await
            .map(|x| x._0)
            .map_err(AvsError::from)?;

        let g1_point = G1Point {
            x: g1_hashed_msg_to_sign.X,
            y: g1_hashed_msg_to_sign.Y,
        };

        let signed_msg = bls_key_pair.sign_hashed_to_curve_message(&g1_point);
        let g1_pubkey_bn254 = bls_key_pair.get_pub_key_g1();
        let g2_pubkey_bn254 = bls_key_pair.get_pub_key_g2();

        let pubkey_reg_params = PubkeyRegistrationParams {
            pubkeyRegistrationSignature: Bn254::G1Point {
                X: signed_msg.g1_point.x,
                Y: signed_msg.g1_point.y,
            },
            pubkeyG1: Bn254::G1Point {
                X: g1_pubkey_bn254.x,
                Y: g1_pubkey_bn254.y,
            },
            pubkeyG2: Bn254::G2Point {
                X: g2_pubkey_bn254.x,
                Y: g2_pubkey_bn254.y,
            },
        };
        log::info!(
            "Pubkey registration params: X1:{:?} Y1:{:?}, X2:{:?} Y2:{:?}",
            pubkey_reg_params.pubkeyG1.X,
            pubkey_reg_params.pubkeyG1.Y,
            pubkey_reg_params.pubkeyG2.X,
            pubkey_reg_params.pubkeyG2.Y
        );

        let msg_to_sign = self
            .el_contract_manager
            .calculate_operator_avs_registration_digest_hash(
                operator_addr,
                self.service_manager_addr,
                operator_to_avs_registration_sig_salt,
                operator_to_avs_registration_sig_expiry,
            )
            .await?;

        let operator_signature = self
            .signer
            .sign_message(msg_to_sign.as_ref())
            .await
            .map_err(AvsError::from)?;

        let mut signature = operator_signature.as_bytes();
        signature[64] += 27;

        let operator_signature_with_salt_and_expiry = SignatureWithSaltAndExpiry {
            signature: Bytes::from(signature),
            salt: operator_to_avs_registration_sig_salt,
            expiry: operator_to_avs_registration_sig_expiry,
        };

        let registry_coordinator =
            RegistryCoordinator::new(self.registry_coordinator_addr, self.eth_client_http.clone());
        let builder = registry_coordinator.registerOperator(
            quorum_numbers,
            socket,
            pubkey_reg_params,
            operator_signature_with_salt_and_expiry,
        );

        let tx = builder.send().await?;
        let watch = tx.watch().await?;
        let receipt = self
            .eth_client_http
            .get_transaction_receipt(watch)
            .await
            .unwrap()
            .unwrap();

        Ok(receipt)
    }

    async fn update_stakes_of_entire_operator_set_for_quorums(
        &self,
        operators_per_quorum: Vec<Vec<Address>>,
        quorum_numbers: Bytes,
    ) -> AvsRegistryContractResult<TransactionReceipt> {
        log::info!("Updating stakes for entire operator set");

        let registry_coordinator =
            RegistryCoordinator::new(self.registry_coordinator_addr, self.eth_client_http.clone());
        let receipt = registry_coordinator
            .updateOperatorsForQuorum(operators_per_quorum, quorum_numbers)
            .send()
            .await?
            .get_receipt()
            .await?;

        log::info!("Successfully updated stakes for entire operator set");

        Ok(receipt)
    }

    async fn update_stakes_of_operator_subset_for_all_quorums(
        &self,
        operators: Vec<Address>,
    ) -> AvsRegistryContractResult<TransactionReceipt> {
        log::info!("Updating stakes of operator subset for all quorums");

        let registry_coordinator =
            RegistryCoordinator::new(self.registry_coordinator_addr, self.eth_client_http.clone());
        let receipt = registry_coordinator
            .updateOperators(operators)
            .send()
            .await?
            .get_receipt()
            .await?;

        log::info!("Successfully updated stakes of operator subset for all quorums");

        Ok(receipt)
    }

    async fn deregister_operator(
        &self,
        quorum_numbers: Bytes,
    ) -> AvsRegistryContractResult<TransactionReceipt> {
        log::info!("Deregistering operator with the AVS's registry coordinator");

        let registry_coordinator =
            RegistryCoordinator::new(self.registry_coordinator_addr, self.eth_client_http.clone());
        let receipt = registry_coordinator
            .deregisterOperator(quorum_numbers)
            .send()
            .await?
            .get_receipt()
            .await?;

        log::info!("Successfully deregistered operator with the AVS's registry coordinator");

        Ok(receipt)
    }
}
