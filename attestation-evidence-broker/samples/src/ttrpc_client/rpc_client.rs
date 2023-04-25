use crate::sev_aeb::{aeb, aeb_ttrpc, sev_evidence::SevEvidence};
use anyhow::{anyhow, Result};
use ttrpc::client::Client;

extern crate libc;

extern "C" {
    fn do_hypercall(input: libc::c_int) -> libc::c_int;
}

const KVM_HC_VM_HANDLE: i32 = 13;

pub fn connect_service<S: Into<String>>(host: S, port: u16) -> Result<()> {
    let addr: String = format!("{}:{}", host.into(), port.to_string());

    debug!("connecting to socket addr: {}", addr);

    let c = Client::connect(&addr)?;

    let guest_handle = unsafe { do_hypercall(KVM_HC_VM_HANDLE) };
    info!("The guest handle is {}", guest_handle);
    if guest_handle < 1 {
        error!("failed to get guest handle");
    }

    let evidence_size = retrieve_attestation_evidence_size(
        guest_handle as u32,
        aeb_ttrpc::AebClient::new(c.clone()),
    );
    info!("The evidence size is {}", evidence_size);

    let _evidence = retrieve_attestation_evidence(
        guest_handle as u32,
        evidence_size,
        aeb_ttrpc::AebClient::new(c),
    );

    Ok(())
}

pub fn retrieve_attestation_evidence_size(
    guest_handle: u32,
    aeb_client: aeb_ttrpc::AebClient,
) -> u32 {
    let req = aeb::RetrieveAttestationEvidenceSizeRequest {
        guest_handle,
        unknown_fields: Default::default(),
        cached_size: Default::default(),
    };

    aeb_client
        .retrieve_attestation_evidence_size(default_ctx(), &req)
        .map_err(|e| {
            error!("failed to retrieve evidence size from aeb service {:?}", e);
        })
        .map(|response| response.evidence_size)
        .unwrap()
}

pub fn retrieve_attestation_evidence(
    guest_handle: u32,
    evidence_size: u32,
    aeb_client: aeb_ttrpc::AebClient,
) -> Result<SevEvidence> {
    let req = aeb::RetrieveAttestationEvidenceRequest {
        guest_handle,
        evidence_size,
        unknown_fields: Default::default(),
        cached_size: Default::default(),
    };

    let evidence = aeb_client
        .retrieve_attestation_evidence(default_ctx(), &req)
        .map_err(|e| {
            error!("failed to retrieve evidence size from aeb service {:?}", e);
        })
        .map(|response| String::from_utf8(response.get_evidence().to_vec()))
        .unwrap()
        .map(|evidence| serde_json::from_str::<SevEvidence>(&evidence[..]))
        .unwrap()
        .map_err(|e| {
            error!("failed to deserialize aeb respense to sev evidence {:?}", e);
        });

    match evidence {
        Ok(evidence) => {
            info!("retrieve attestation evidence successfully");
            Ok(evidence)
        }
        Err(e) => Err(anyhow!("failed to retrieve attestation evidence {:?}", e)),
    }
}

fn default_ctx() -> ttrpc::context::Context {
    ttrpc::context::with_timeout(0)
}
