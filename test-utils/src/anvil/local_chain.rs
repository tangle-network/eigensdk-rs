use crate::anvil::anvil_node::{Anvil, AnvilInstance};
use crate::anvil::random_port;
use ethers::signers::Signer;
use std::sync::Arc;

type EthersClient = ethers::providers::Provider<ethers::providers::Http>;
type SignerEthersClient =
    ethers::middleware::SignerMiddleware<EthersClient, ethers::signers::LocalWallet>;

pub struct LocalEvmChain {
    chain_id: u32,
    name: String,
    client: Arc<SignerEthersClient>,
    anvil_node_handle: AnvilInstance,
}

impl LocalEvmChain {
    pub fn new(chain_id: u32, name: String, port: Option<u16>) -> Self {
        let anvil_node_handle = Self::spawn_anvil_node(chain_id, None, port);
        let secret_key = anvil_node_handle.keys()[0].clone();
        let signer = ethers::signers::LocalWallet::from(secret_key).with_chain_id(chain_id);
        let provider = ethers::providers::Provider::<ethers::providers::Http>::try_from(
            anvil_node_handle.endpoint(),
        )
        .unwrap();
        let client = SignerEthersClient::new(provider, signer);
        // start the node
        Self {
            chain_id,
            name,
            client: Arc::new(client),
            anvil_node_handle,
        }
    }

    pub fn new_with_chain_state(
        chain_id: u32,
        name: String,
        state_dir: &std::path::Path,
        port: Option<u16>,
    ) -> Self {
        let anvil_node_handle = Self::spawn_anvil_node(chain_id, Some(state_dir), port);
        let secret_key = anvil_node_handle.keys()[0].clone();
        let signer = ethers::signers::LocalWallet::from(secret_key).with_chain_id(chain_id);
        let provider = ethers::providers::Provider::<ethers::providers::Http>::try_from(
            anvil_node_handle.endpoint(),
        )
        .unwrap();
        let client = SignerEthersClient::new(provider, signer);
        Self {
            chain_id,
            name,
            client: Arc::new(client),
            anvil_node_handle,
        }
    }

    pub fn chain_id(&self) -> u32 {
        self.chain_id
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn keys(&self) -> &[ethers::core::k256::SecretKey] {
        self.anvil_node_handle.keys()
    }

    pub fn addresses(&self) -> &[ethers::types::Address] {
        self.anvil_node_handle.addresses()
    }

    pub fn client(&self) -> Arc<SignerEthersClient> {
        self.client.clone()
    }

    /// Returns the HTTP endpoint of this instance
    pub fn endpoint(&self) -> String {
        self.anvil_node_handle.endpoint()
    }

    /// Returns the Websocket endpoint of this instance
    pub fn ws_endpoint(&self) -> String {
        self.anvil_node_handle.ws_endpoint()
    }

    pub fn shutdown(self) {
        drop(self.anvil_node_handle);
    }

    fn spawn_anvil_node(
        chain_id: u32,
        state_dir: Option<&std::path::Path>,
        port: Option<u16>,
    ) -> AnvilInstance {
        let port = match port {
            None => random_port::random_port(),
            Some(port) => port,
        };
        let mut anvil = Anvil::new()
            .port(port)
            .chain_id(chain_id)
            .arg("--accounts")
            .arg("20");
        if let Some(p) = state_dir {
            anvil = anvil
                .arg("--dump-state")
                .arg(p.to_string_lossy())
                .arg("--state-interval")
                .arg("1");
            if p.join("state.json").exists() {
                anvil = anvil.arg("--load-state").arg(p.to_string_lossy());
            };
        };
        anvil.spawn()
    }
}
