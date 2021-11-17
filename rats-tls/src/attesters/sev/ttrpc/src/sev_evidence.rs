use serde::{Deserialize, Serialize};
use sev::certs::sev::Certificate;
use sev::firmware::AttestationReport;

#[derive(Serialize, Deserialize, Debug, Copy, Clone)]
#[repr(C, packed)]
pub struct SevEvidence {
    pub report: AttestationReport, // The attestation report
    pub cek: Certificate,          // The certificate for the CEK.
    pub pek: Certificate,          // The certificate for the PEK.
    pub oca: Certificate,          // The certificate for the OCA.
}
