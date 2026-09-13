use crate::*;
use warp::Filter;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    pub id: String,
    pub endpoint: String,
    pub public_key: Vec<u8>,
    pub capabilities: Vec<String>,
    pub last_seen: chrono::DateTime<chrono::Utc>,
}

pub struct DistributedNode {
    pub mesh_node: AgentMeshNode,
    pub orchestrator: Arc<Mutex<Orchestrator>>,
    pub known_peers: Arc<Mutex<BTreeMap<String, PeerInfo>>>,
}

impl DistributedNode {
    pub fn new(id: String, orchestrator: Orchestrator) -> Self {
        Self {
            mesh_node: AgentMeshNode::new(id),
            orchestrator: Arc::new(Mutex::new(orchestrator)),
            known_peers: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    pub async fn start_api(self: Arc<Self>, port: u16) {
        let node = self.clone();

        // GET /peers - List known peers
        let node_peers = self.clone();
        let get_peers = warp::get()
            .and(warp::path("peers"))
            .and_then(move || {
                let node = node_peers.clone();
                async move {
                    let peers = node.known_peers.lock().await;
                    Ok::<_, warp::Rejection>(warp::reply::json(&*peers))
                }
            });

        // POST /execute - Execute an action request
        let execute = warp::post()
            .and(warp::path("execute"))
            .and(warp::body::json())
            .and_then(move |req: ActionRequest| {
                let node = node.clone();
                async move {
                    let mut orch = node.orchestrator.lock().await;
                    match orch.run_task(req).await {
                        Ok(res) => Ok::<_, warp::Rejection>(warp::reply::json(&res)),
                        Err(e) => Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({"error": e}))),
                    }
                }
            });

        // POST /handshake - Peer-to-peer identity exchange
        let node = self.clone();
        let handshake = warp::post()
            .and(warp::path("handshake"))
            .and(warp::body::json())
            .and_then(move |req: HandshakeRequest| {
                let node = node.clone();
                async move {
                    match node.mesh_node.respond_to_handshake(&req) {
                        Ok((resp, _shared_secret)) => Ok::<_, warp::Rejection>(warp::reply::json(&resp)),
                        Err(e) => Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({"error": e}))),
                    }
                }
            });

        // POST /vote - Respond to a consensus proposal
        let node_vote = self.clone();
        let vote = warp::post()
            .and(warp::path("vote"))
            .and(warp::body::json())
            .and_then(move |proposal: RemoteProposal| {
                let node = node_vote.clone();
                async move {
                    let _orch = node.orchestrator.lock().await;
                    // Run the request through the local verifier
                    let verdict = IntentVerifier::verify(
                        &proposal.request,
                        &serde_json::Value::Null,
                        &IntentPolicy {
                            name: "Network Vote".into(),
                            capability: proposal.request.capability.clone(),
                            constraints: serde_json::Value::Object(serde_json::Map::new()),
                        }
                    );

                    let vote = RemoteVote {
                        proposal_id: proposal.id,
                        voter_id: node.mesh_node.id.clone(),
                        verdict,
                        signature: vec![], // TODO: Sign the vote using identity keys
                    };
                    Ok::<_, warp::Rejection>(warp::reply::json(&vote))
                }
            });

        let routes = execute.or(handshake).or(get_peers).or(vote);
        warp::serve(routes).run(([127, 0, 0, 1], port)).await;
    }

    pub async fn discover_peer(&self, endpoint: String) -> Result<(), String> {
        let (req, _secret) = self.mesh_node.initiate_handshake();
        let client = reqwest::Client::new();

        let resp = client.post(format!("{}/handshake", endpoint))
            .json(&req)
            .send()
            .await
            .map_err(|e| e.to_string())?;

        if resp.status().is_success() {
            let handshake_resp: HandshakeResponse = resp.json().await.map_err(|e| e.to_string())?;

            // In a real implementation, verify signature here
            let mut peers = self.known_peers.lock().await;
            peers.insert(handshake_resp.responder_id.clone(), PeerInfo {
                id: handshake_resp.responder_id,
                endpoint,
                public_key: handshake_resp.responder_public_key,
                capabilities: vec![], // Would be populated via a follow-up info request
                last_seen: chrono::Utc::now(),
            });
            Ok(())
        } else {
            Err("Handshake failed".into())
        }
    }
}

pub struct NetworkModule {
    pub endpoint: String,
    pub capability: String,
}

#[async_trait::async_trait]
impl Module for NetworkModule {
    fn name(&self) -> &str { &self.endpoint }
    fn capabilities(&self) -> Vec<String> { vec![self.capability.clone()] }
    async fn execute(&self, action: &str, input: serde_json::Value) -> Result<serde_json::Value, String> {
        let client = reqwest::Client::new();
        // In a real network, this request would be signed by the MeshNode
        let req = ActionRequest {
            id: rand::random::<u64>().to_string(),
            actor: "network_orchestrator".into(),
            capability: self.capability.clone(),
            action: action.into(),
            input,
            signature: None,
            pqc_signature: None,
            public_key: None,
            pqc_public_key: None,
            token: None,
            identity_claim: None,
        };

        let resp = client.post(format!("{}/execute", self.endpoint))
            .json(&req)
            .send()
            .await
            .map_err(|e| e.to_string())?;

        if resp.status().is_success() {
            resp.json().await.map_err(|e| e.to_string())
        } else {
            let err: serde_json::Value = resp.json().await.map_err(|e| e.to_string())?;
            Err(err["error"].as_str().unwrap_or("Unknown error").into())
        }
    }
}
