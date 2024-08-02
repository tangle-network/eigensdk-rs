use alloy_provider::Provider;
use alloy_pubsub::Subscription;
use alloy_rpc_types::{Filter, Log};
use alloy_sol_types::SolEvent;
use async_trait::async_trait;
use eigen_utils::{types::AvsError, Config};

use super::{IncredibleSquaringContractManager, IncredibleSquaringTaskManager};

#[async_trait]
pub trait IncredibleSquaringSubscriber: Send + Sync {
    async fn subscribe_to_new_tasks(&self) -> Result<Subscription<Log>, AvsError>;

    async fn subscribe_to_task_responses(&self) -> Result<Subscription<Log>, AvsError>;
}

#[async_trait]
impl<T: Config> IncredibleSquaringSubscriber for IncredibleSquaringContractManager<T> {
    async fn subscribe_to_new_tasks(&self) -> Result<Subscription<Log>, AvsError> {
        let subscription = self
            .eth_client_ws
            .subscribe_logs(
                &Filter::new().event(IncredibleSquaringTaskManager::NewTaskCreated::SIGNATURE),
            )
            .await?;

        Ok(subscription)
    }

    async fn subscribe_to_task_responses(&self) -> Result<Subscription<Log>, AvsError> {
        let subscription = self
            .eth_client_ws
            .subscribe_logs(
                &Filter::new().event(IncredibleSquaringTaskManager::TaskResponded::SIGNATURE),
            )
            .await?;

        Ok(subscription)
    }
}
