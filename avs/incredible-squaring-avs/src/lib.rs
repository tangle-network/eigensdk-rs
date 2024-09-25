use alloy_primitives::{keccak256, B256};
use alloy_sol_types::SolValue;
use avs::TaskResponse;

pub mod aggregator;
pub mod avs;
pub mod challenger;
pub mod operator;
pub mod rpc_client;

pub fn get_task_response_digest(task_response: &TaskResponse) -> B256 {
    let encoded = task_response.abi_encode_packed();
    keccak256(encoded)
}
