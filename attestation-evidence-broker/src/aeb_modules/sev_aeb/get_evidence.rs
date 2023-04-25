use anyhow::*;
use codicon::Decoder;
use rand::Rng;
use sev::{
    certs::sev::{Certificate, Chain, Usage},
    firmware::{AttestationReport, Firmware},
};
use std::time::Duration;

use crate::aeb_modules::sev_aeb::evidence::SevEvidence;

async fn download(url: &str, usage: Usage) -> Result<Certificate> {
    let mut rsp = reqwest::get(url).await;

    // The AMD KDS server only accepts requests every 10 seconds
    for attempt in 1..4 {
        match &rsp {
            // HTTP request has succeeded, ensure that the status code does not indicate an error.
            std::result::Result::Ok(found) => {
                if found.status().is_success() {
                    break;
                } else {
                    debug!(
                        "Attempt #{}, Error: Received HTTP response #{}",
                        attempt,
                        found.status()
                    );

                    if let Some(retry) = found.headers().get("retry-after") {
                        std::thread::sleep(Duration::from_secs(
                            retry.to_str()?.parse().unwrap_or(6),
                        ));
                    } else {
                        // For some reason, "retry-after" doesn't exist, waiting 6 seconds is a good default
                        std::thread::sleep(Duration::from_secs(6));
                    }

                    rsp = reqwest::get(url).await;
                }
            }
            // HTTP request has failed.
            Err(_) => break,
        }
    }

    let body = rsp
        .context(format!("Failed to complete request: {:?}", usage))?
        .bytes()
        .await?;

    let certificate = Certificate::decode(&mut &body[..], ())
        .map_err(|e| anyhow!("Failed to parse downloaded {:?}: {:?}", usage, e))?;

    Ok(certificate)
}

fn firmware() -> Result<Firmware> {
    Firmware::open().context("Failed to open /dev/sev")
}

async fn chain() -> Result<Chain> {
    const CEK_SVC: &str = "https://kdsintf.amd.com/cek/id";

    let mut chain = firmware()?
        .pdh_cert_export()
        .map_err(|e| anyhow!("Failed to export SEV certificates: {:?}", e))?;

    let id = firmware()?
        .get_identifier()
        .map_err(|e| anyhow!("Failed to fetch identifier: {:?}", e))?;
    let url = format!("{}/{}", CEK_SVC, id);

    chain.cek = download(&url, Usage::CEK)
        .await
        .map_err(|e| anyhow!("Failed to download CEK form AMD KDS server: {:?}", e))?;

    Ok(chain)
}

fn report(guest_handle: u32) -> Result<AttestationReport> {
    let mut monce = [0_u8; 16];
    rand::thread_rng().fill(&mut monce);

    let report = firmware()?
        .get_attestation_report(guest_handle, monce)
        .map_err(|e| anyhow!("Failed to get SEV guest attestation report: {:?}", e))?;

    Ok(report)
}

pub async fn collect_evidence(guest_handle: u32) -> Result<SevEvidence> {
    let cert_chain = chain()
        .await
        .map_err(|e| anyhow!("Failed to collect SEV certificate chain: {:?}", e))?;

    let attestation_report = report(guest_handle)
        .map_err(|e| anyhow!("Failed to collect SEV attestation report: {:?}", e))?;

    Ok(SevEvidence {
        report: attestation_report,
        cek: cert_chain.cek,
        pek: cert_chain.pek,
        oca: cert_chain.oca,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use sev::certs::Verifiable;

    #[tokio::test]
    async fn test_collect_and_verify_evidence() {
        // The guest handle usually increments from 1
        let guest_handle = 1;
        let evidence = collect_evidence(guest_handle).await.unwrap();
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
