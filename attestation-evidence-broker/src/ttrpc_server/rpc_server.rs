use anyhow::anyhow;
use std::sync::Arc;
use ttrpc::asynchronous::server::*;
use ttrpc::error::Result;

use async_trait::async_trait;
use tokio::signal::unix::{signal, SignalKind};

use crate::aeb_modules::sev_aeb;
use crate::device_type::device::{self, DeviceType};
use crate::protocols::aeb::aeb::{
    RetrieveAttestationEvidenceRequest, RetrieveAttestationEvidenceResponse,
    RetrieveAttestationEvidenceSizeRequest, RetrieveAttestationEvidenceSizeResponse,
};
use crate::protocols::aeb::aeb_ttrpc::{create_aeb, Aeb};

struct AEBService {}

pub async fn start_service<S: Into<String>>(host: S, port: u16) -> Result<()> {
    let agent_service = Box::new(AEBService {}) as Box<dyn Aeb + Send + Sync>;
    let agent_worker = Arc::new(agent_service);
    let aservice = create_aeb(agent_worker);

    let addr: String = format!("{}:{}", host.into(), port.to_string());

    debug!("listening to socket addr: {}", addr);

    let mut server = Server::new()
        .bind(addr.as_str())?
        .register_service(aservice);

    let mut interrupt = signal(SignalKind::interrupt()).unwrap();
    server.start().await.unwrap();

    tokio::select! {
        _ = interrupt.recv() => {
            debug!("shutdown the server");
            server.shutdown().await.unwrap();
        }
    };

    Ok(())
}

#[async_trait]
impl Aeb for AEBService {
    async fn retrieve_attestation_evidence_size(
        &self,
        _ctx: &::ttrpc::r#async::TtrpcContext,
        _req: RetrieveAttestationEvidenceSizeRequest,
    ) -> ::ttrpc::Result<RetrieveAttestationEvidenceSizeResponse> {
        let mut cres = RetrieveAttestationEvidenceSizeResponse::new();
        let size;

        match device::get_device_type() {
            DeviceType::AmdMilan | DeviceType::AmdNaples | DeviceType::AmdRome => {
                size = std::mem::size_of::<sev_aeb::evidence::SevEvidence>() as u32;
            }
            _ => {
                return Err(::ttrpc::Error::Others(
                    anyhow!("device type is not supported").to_string(),
                ));
            }
        }

        cres.set_evidence_size(size);

        Ok(cres)
    }

    async fn retrieve_attestation_evidence(
        &self,
        _ctx: &::ttrpc::r#async::TtrpcContext,
        req: RetrieveAttestationEvidenceRequest,
    ) -> ::ttrpc::Result<RetrieveAttestationEvidenceResponse> {
        let guest_handle = req.get_guest_handle();
        let evidence_size = req.get_evidence_size();

        let mut cres = RetrieveAttestationEvidenceResponse::new();
        cres.set_evidence_size(evidence_size);

        let evidence;
        match device::get_device_type() {
            DeviceType::AmdMilan | DeviceType::AmdNaples | DeviceType::AmdRome => {
                evidence = sev_aeb::get_evidence::collect_evidence(guest_handle).await;
            }
            _ => {
                return Err(::ttrpc::Error::Others(
                    anyhow!("device type is not supported").to_string(),
                ));
            }
        }

        match evidence {
            Ok(evidence) => {
                cres.set_evidence(
                    serde_json::to_string(&evidence)
                        .unwrap()
                        .as_bytes()
                        .to_vec(),
                );
                Ok(cres)
            }
            Err(e) => Err(::ttrpc::Error::Others(
                anyhow!("failed to retrieve attestation evidence {}", e).to_string(),
            )),
        }
    }
}
