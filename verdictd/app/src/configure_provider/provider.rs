
use configureProvider::configure_provider_service_server::{ConfigureProviderService, ConfigureProviderServiceServer};

use configureProvider::{CreateKeyRequest, CreateKeyResponse};
use configureProvider::{GetKeyRequest, GetKeyResponse};
use configureProvider::{DeleteKeyRequest, DeleteKeyResponse};

use configureProvider::{SetPolicyRequest, SetPolicyResponse};
use configureProvider::{SetRawPolicyRequest, SetRawPolicyResponse};
use configureProvider::{ExportPolicyRequest, ExportPolicyResponse};

use crate::key_manager::directory_key_manager;
use crate::policyEngine;
use rand::*;
use tonic::{transport::Server, Request, Response, Status};
use uuid::Uuid;
use base64;

pub mod configureProvider {
    tonic::include_proto!("configureprovider");
}

#[derive(Debug, Default)]
pub struct configProviderService {}

#[tonic::async_trait]
impl ConfigureProviderService for configProviderService {
    async fn create_key(
        &self,
        _request: Request<CreateKeyRequest>,
    ) -> Result<Response<CreateKeyResponse>, Status> {
        let kid = Uuid::new_v4().to_string();
        // generate a new key file with a new random key
        let mut key: [u8; 32] = [0; 32];
        rand::rngs::OsRng.fill_bytes(&mut key);
        let res = directory_key_manager::set_key(&kid, &key)
            .and_then(|_| {
                let res = CreateKeyResponse {
                    status: "OK".as_bytes().to_vec(),
                    uuid: kid.into_bytes(),
                };
                Ok(res)
            })
            .unwrap_or_else(|_| {
                CreateKeyResponse {
                    status: "Greate key failed".as_bytes().to_vec(),
                    uuid: "".as_bytes().to_vec(),
                }
            });           

        Ok(Response::new(res))
    }

    async fn get_key(
        &self,
        request: Request<GetKeyRequest>,
    ) -> Result<Response<GetKeyResponse>, Status> {
        let kid = String::from_utf8(request.into_inner().uuid)
            .unwrap_or_else(|_| "00000000-0000-0000-0000-000000000000".to_string());
        println!("kid: {}", kid);

        let res = directory_key_manager::get_key(&kid)
            .and_then(|data| {
                let res = GetKeyResponse {
                    status: "OK".as_bytes().to_vec(),
                    key: base64::encode(data).into_bytes(),
                };
                Ok(res)
            })
            .unwrap_or_else(|_| {
                GetKeyResponse {
                    status: "key is not exist".as_bytes().to_vec(),
                    key: "".as_bytes().to_vec(),
                }
            });

        Ok(Response::new(res))   
    }  
    
    async fn delete_key(
        &self,
        request: Request<DeleteKeyRequest>,
    ) -> Result<Response<DeleteKeyResponse>, Status> {
        let res = DeleteKeyResponse {
            status: "Not implemented".as_bytes().to_vec(),
        };
        Ok(Response::new(res))   
    } 

    async fn set_policy(
        &self,
        request: Request<SetPolicyRequest>,
    ) -> Result<Response<SetPolicyResponse>, Status> {
        let empty = "".to_string();
        let request: SetPolicyRequest = request.into_inner();
        let policyname = std::str::from_utf8(&request.policyname)
            .unwrap_or_else(|_| {
                println!("parse policyname failed");
                &empty
            });
        let references = std::str::from_utf8(&request.references)
            .unwrap_or_else(|_| {
                println!("parse references failed");
                &empty
            });
            
        let res = policyEngine::opa::opaEngine::set_reference(policyname, references)
            .and_then(|_| {
                let res = SetPolicyResponse {
                    status: "OK".as_bytes().to_vec(),
                };
                Ok(res)
            })
            .unwrap_or_else(|e| {
                SetPolicyResponse {
                    status: e.into_bytes(),
                }
            });

        Ok(Response::new(res))
    }   
    
    async fn set_raw_policy(
        &self,
        request: Request<SetRawPolicyRequest>,
    ) -> Result<Response<SetRawPolicyResponse>, Status> {
        let empty = "".to_string();
        let request: SetRawPolicyRequest = request.into_inner();
        let policyname = std::str::from_utf8(&request.policyname)
            .unwrap_or_else(|_| {
                println!("parse policyname failed");
                &empty
            });
        let policycontent = std::str::from_utf8(&request.policycontent)
            .unwrap_or_else(|_| {
                println!("parse policycontent failed");
                &empty
            });

        let res = policyEngine::opa::opaEngine::set_raw_policy(policyname, policycontent)
            .and_then(|_| {
                let res = SetRawPolicyResponse {
                    status: "OK".as_bytes().to_vec(),
                };
                Ok(res)
            })
            .unwrap_or_else(|e| {
                SetRawPolicyResponse {
                    status: e.into_bytes(),
                }
            });            

        Ok(Response::new(res))
    }     

    async fn export_policy(
        &self,
        request: Request<ExportPolicyRequest>,
    ) -> Result<Response<ExportPolicyResponse>, Status> {
        let policyname = String::from_utf8(request.into_inner().policyname)
            .unwrap_or_else(|_| {
                println!("parse policyname failed");
                "".to_string()
            });

        let res = policyEngine::opa::opaEngine::export_policy(&policyname)
            .and_then(|content| {
                let res = ExportPolicyResponse {
                    status: "OK".as_bytes().to_vec(),
                    policycontent: content.into_bytes(),
                };
                Ok(res)
            })
            .unwrap_or_else(|e| {
                ExportPolicyResponse {
                    status: e.into_bytes(),
                    policycontent: "".as_bytes().to_vec(),
                }
            });   

        Ok(Response::new(res))
    }       
}

pub async fn server(addr: &str) -> Result<(), Box<dyn std::error::Error>> {
    let addr = addr.parse()?;
    let service = configProviderService::default();

    Server::builder()
        .add_service(ConfigureProviderServiceServer::new(service))
        .serve(addr)
        .await?;

    Ok(())
}
