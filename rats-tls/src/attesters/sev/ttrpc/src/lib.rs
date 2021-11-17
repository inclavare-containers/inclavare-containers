use anyhow::{Context, Result};
use log::{debug, error, info};
use protocols::sev::{aeb, aeb_ttrpc};
use sev_evidence::SevEvidence;
use ttrpc::client::Client;

mod protocols;
mod sev_evidence;

const SERVER_ADDR: &str = "vsock:///tmp/aeb.sock";
const SERVER_PORT: &str = "5577";

#[no_mangle]
pub extern "C" fn retrieve_attestation_evidence(
    guest_handle: u32,
    evidence_size: u32,
) -> Option<Box<SevEvidence>> {
    env_logger::builder()
        .filter(None, log::LevelFilter::Debug)
        .init();

    let req = aeb::RetrieveAttestationEvidenceRequest {
        guest_handle,
        evidence_size,
        unknown_fields: Default::default(),
        cached_size: Default::default(),
    };

    let evidence = connect()
        .map_err(|e| {
            error!("failed to create ttrpc client {:?}", e);
        })
        .and_then(|client| {
            client
                .retrieve_attestation_evidence(default_ctx(), &req)
                .map_err(|e| {
                    error!("failed to retrieve evidence size from aeb service {:?}", e);
                })
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
            info!("retrieve sev attestation evidence");
            Some(Box::new(evidence))
        }
        Err(e) => {
            error!("failed to deserialize aeb respense to sev evidence {:?}", e);
            None
        }
    }
}

#[no_mangle]
pub extern "C" fn retrieve_attestation_evidence_size(guest_handle: u32) -> u32 {
    let req = aeb::RetrieveAttestationEvidenceSizeRequest {
        guest_handle,
        unknown_fields: Default::default(),
        cached_size: Default::default(),
    };

    connect()
        .map_err(|e| {
            error!("failed to create ttrpc client {:?}", e);
        })
        .and_then(|agent_client| {
            agent_client
                .retrieve_attestation_evidence_size(default_ctx(), &req)
                .map_err(|e| {
                    error!("failed to retrieve evidence size from aeb service {:?}", e);
                })
        })
        .map(|response| response.evidence_size)
        .unwrap()
}

pub fn connect() -> Result<aeb_ttrpc::AebClient> {
    let addr = format!("{}:{}", SERVER_ADDR, SERVER_PORT);
    debug!("connect {}", addr);

    let c = Client::connect(&addr).context(format!("failed to connect {}", addr))?;

    Ok(aeb_ttrpc::AebClient::new(c))
}

fn default_ctx() -> ttrpc::context::Context {
    ttrpc::context::with_timeout(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sev::certs::Verifiable;

    #[test]
    fn test_retrieve_attestation_evidence_size() {
        let guest_handle = 1;
        let evidence_size = retrieve_attestation_evidence_size(guest_handle);

        assert_eq!(6460, evidence_size);
    }

    #[test]
    fn test_retrieve_attestation_evidence() {
        let guest_handle = 1;
        let evidence_size = 6460;

        let evidence = retrieve_attestation_evidence(guest_handle, evidence_size).unwrap();

        let cek = evidence.cek;
        let pek = evidence.pek;
        let oca = evidence.oca;

        (&cek, &pek).verify().unwrap();
        assert!((&cek, &pek).verify().is_ok());
        assert!((&pek, &cek).verify().is_err());

        (&oca, &pek).verify().unwrap();
        assert!((&oca, &pek).verify().is_ok());
        assert!((&pek, &oca).verify().is_err());

        // TODO: verfify report with pek
    }
}
