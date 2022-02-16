use tonic::{Request, Response, Status};
use crate::client_api::api;
use crate::resources::gpg;
use std::io::Write;
use std::process::{Command, Stdio};

use api::clientApi::gpg_service_server::GpgService;
use api::clientApi::{ListGpgKeysRequest, ListGpgKeysResponse};
use api::clientApi::{ImportGpgKeyRequest, ImportGpgKeyResponse};
use api::clientApi::{DeleteGpgKeyRequest, DeleteGpgKeyResponse};
use api::clientApi::{ExportGpgKeyringRequest, ExportGpgKeyringResponse};

#[derive(Debug, Default)]
pub struct gpgService {}

#[tonic::async_trait]
impl GpgService for gpgService {
    async fn list_gpg_keys(
        &self,
        _request: Request<ListGpgKeysRequest>,
    ) -> Result<Response<ListGpgKeysResponse>, Status> {
        let output = 
            Command::new("gpg")
            .arg("--no-default-keyring")
            .arg("--keyring=".to_owned() + gpg::GPG_KEYRING)
            .arg("--list-keys")
            .output()
            .expect("Failed to list GPG keyring");

        println!("status: {}", output.status);

        let res = ListGpgKeysResponse {
            keys: output.stdout.to_vec()
        };

        Ok(Response::new(res))
    }

    async fn import_gpg_key(
        &self,
        request: Request<ImportGpgKeyRequest>,
    ) -> Result<Response<ImportGpgKeyResponse>, Status> {
        let request: ImportGpgKeyRequest = request.into_inner();
        let key = std::str::from_utf8(&request.key).unwrap().to_owned();

        let mut child = Command::new("gpg")
            .stdin(Stdio::piped())
            .stderr(Stdio::piped())
            .stdout(Stdio::piped())
            .arg("--no-default-keyring")
            .arg("--keyring=".to_owned() + gpg::GPG_KEYRING)
            .arg("--import")
            .spawn()
            .expect("Failed to spawn child process");
        
        let mut stdin = child.stdin.take().expect("Failed to open stdin");
        std::thread::spawn(move || {
            stdin.write_all(key.as_bytes()).expect("Failed to write to stdin");
        });
        
        let output = child.wait_with_output().expect("Failed to read stdout");
        //println!("status: {:?}", &output);

        let res = ImportGpgKeyResponse {
            status: output.stderr.to_vec()
        };

        Ok(Response::new(res))
    }

    async fn delete_gpg_key(
        &self,
        request: Request<DeleteGpgKeyRequest>,
    ) -> Result<Response<DeleteGpgKeyResponse>, Status> {
        let request: DeleteGpgKeyRequest = request.into_inner();
        let keyid = std::str::from_utf8(&request.keyid).unwrap();

        let output = 
            Command::new("gpg")
            .arg("--batch")
            .arg("--yes")
            .arg("--no-default-keyring")
            .arg("--keyring=".to_owned() + gpg::GPG_KEYRING)
            .arg("--delete-key")
            .arg(keyid)
            .output()
            .expect("Failed to import GPG key");

        println!("status: {}", output.status);

        let res = if output.status.success() {
            DeleteGpgKeyResponse {
                status: "Delete key successfully".as_bytes().to_vec()
            }
        } else {
            DeleteGpgKeyResponse {
                status: output.stderr.to_vec()
            }
        };

        Ok(Response::new(res))
    }

    async fn export_gpg_keyring(
        &self,
        _request: Request<ExportGpgKeyringRequest>,
    ) -> Result<Response<ExportGpgKeyringResponse>, Status> {
        let res = gpg::export_base64(gpg::GPG_KEYRING)
            .and_then(|content| {
                let res = ExportGpgKeyringResponse {
                    status: "OK".as_bytes().to_vec(),
                    content: content.into_bytes(),
                };
                Ok(res)
            })
            .unwrap_or_else(|e| {
                ExportGpgKeyringResponse {
                    status: e.into_bytes(),
                    content: "".as_bytes().to_vec(),
                }
            });   

        Ok(Response::new(res))
    }
}
