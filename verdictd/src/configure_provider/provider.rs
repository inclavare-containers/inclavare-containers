
use configureProvider::configure_provider_service_server::{ConfigureProviderService, ConfigureProviderServiceServer};

use configureProvider::{CreateKeyRequest, CreateKeyResponse};
use configureProvider::{GetKeyRequest, GetKeyResponse};
use configureProvider::{DeleteKeyRequest, DeleteKeyResponse};

use configureProvider::{SetOpaPolicyRequest, SetOpaPolicyResponse};
use configureProvider::{ExportOpaPolicyRequest, ExportOpaPolicyResponse};
use configureProvider::{SetOpaReferenceRequest, SetOpaReferenceResponse};
use configureProvider::{ExportOpaReferenceRequest, ExportOpaReferenceResponse};
use configureProvider::{TestOpaRequest, TestOpaResponse};

use crate::key_manager::directory_key_manager;
use crate::policy_engine::opa;
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
        info!("kid: {}", kid);

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
        _request: Request<DeleteKeyRequest>,
    ) -> Result<Response<DeleteKeyResponse>, Status> {
        let res = DeleteKeyResponse {
            status: "Not implemented".as_bytes().to_vec(),
        };
        Ok(Response::new(res))   
    }   
    
    async fn set_opa_policy(
        &self,
        request: Request<SetOpaPolicyRequest>,
    ) -> Result<Response<SetOpaPolicyResponse>, Status> {
        let empty = "".to_string();
        let request: SetOpaPolicyRequest = request.into_inner();
        let name = std::str::from_utf8(&request.name)
            .unwrap_or_else(|_| {
                error!("parse policyname failed");
                &empty
            });
        let content = std::str::from_utf8(&request.content)
            .unwrap_or_else(|_| {
                error!("parse policycontent failed");
                &empty
            });

        let res = opa::opa_engine::set_raw_policy(name, content)
            .and_then(|_| {
                let res = SetOpaPolicyResponse {
                    status: "OK".as_bytes().to_vec(),
                };
                Ok(res)
            })
            .unwrap_or_else(|e| {
                SetOpaPolicyResponse {
                    status: e.into_bytes(),
                }
            });            

        Ok(Response::new(res))
    }     

    async fn export_opa_policy(
        &self,
        request: Request<ExportOpaPolicyRequest>,
    ) -> Result<Response<ExportOpaPolicyResponse>, Status> {
        let name = String::from_utf8(request.into_inner().name)
            .unwrap_or_else(|_| {
                error!("parse policyname failed");
                "".to_string()
            });

        let res = opa::opa_engine::export(&name)
            .and_then(|content| {
                let res = ExportOpaPolicyResponse {
                    status: "OK".as_bytes().to_vec(),
                    content: content.into_bytes(),
                };
                Ok(res)
            })
            .unwrap_or_else(|e| {
                ExportOpaPolicyResponse {
                    status: e.into_bytes(),
                    content: "".as_bytes().to_vec(),
                }
            });   

        Ok(Response::new(res))
    }

    async fn set_opa_reference(
        &self,
        request: Request<SetOpaReferenceRequest>,
    ) -> Result<Response<SetOpaReferenceResponse>, Status> {
        let empty = "".to_string();
        let request: SetOpaReferenceRequest = request.into_inner();
        let name = std::str::from_utf8(&request.name)
            .unwrap_or_else(|_| {
                error!("parse SetOpaReferenceRequest failed");
                &empty
            });
        let content = std::str::from_utf8(&request.content)
            .unwrap_or_else(|_| {
                error!("parse content failed");
                &empty
            });
        
        info!("content: {}", content);
            
        let res = opa::opa_engine::set_reference(name, content)
            .and_then(|_| {
                let res = SetOpaReferenceResponse {
                    status: "OK".as_bytes().to_vec(),
                };
                Ok(res)
            })
            .unwrap_or_else(|e| {
                SetOpaReferenceResponse {
                    status: e.into_bytes(),
                }
            });

        Ok(Response::new(res))
    } 

    async fn export_opa_reference(
        &self,
        request: Request<ExportOpaReferenceRequest>,
    ) -> Result<Response<ExportOpaReferenceResponse>, Status> {
        let name = String::from_utf8(request.into_inner().name)
            .unwrap_or_else(|_| {
                error!("parse ExportDataRequest failed");
                "".to_string()
            });

        let res = opa::opa_engine::export(&name)
            .and_then(|content| {
                let res = ExportOpaReferenceResponse {
                    status: "OK".as_bytes().to_vec(),
                    content: content.into_bytes(),
                };
                Ok(res)
            })
            .unwrap_or_else(|e| {
                ExportOpaReferenceResponse {
                    status: e.into_bytes(),
                    content: "".as_bytes().to_vec(),
                }
            });   

        Ok(Response::new(res))
    }

    async fn test_opa(
        &self,
        request: Request<TestOpaRequest>,
    ) -> Result<Response<TestOpaResponse>, Status> {
        let request: TestOpaRequest = request.into_inner();
        let mut policyname = "".to_string();
        let mut policycontent = "".to_string();
        let mut referencename = "".to_string();
        let mut referencecontent = "".to_string();

        if request.policylocal == true {
            policycontent = String::from_utf8(request.policycontent)
                .unwrap_or_else(|_| {
                    error!("parse policycontent failed");
                    "".to_string()
                });
            if policycontent == "".to_string() {
                let res = TestOpaResponse {
                    status: "parse policycontent failed".as_bytes().to_vec()
                };
                return Ok(Response::new(res))
            }
        } else {
            policyname = String::from_utf8(request.policyname)
            .unwrap_or_else(|_| {
                error!("parse policyname failed");
                "".to_string()
            });
            if policyname == "".to_string() {
                let res = TestOpaResponse {
                    status: "parse policyname failed".as_bytes().to_vec()
                };
                return Ok(Response::new(res))
            }
        }

        if request.referencelocal == true {
            referencecontent = String::from_utf8(request.referencecontent)
            .unwrap_or_else(|_| {
                error!("parse referencecontent failed");
                "".to_string()
            }); 
            if referencecontent == "".to_string() {
                let res = TestOpaResponse {
                    status: "parse referencecontent failed".as_bytes().to_vec()
                };
                return Ok(Response::new(res))
            }           
        } else {
            referencename = String::from_utf8(request.referencename)
            .unwrap_or_else(|_| {
                error!("parse referencename failed");
                "".to_string()
            });
            if referencename == "".to_string() {
                let res = TestOpaResponse {
                    status: "parse referencename failed".as_bytes().to_vec()
                };
                return Ok(Response::new(res))
            }  
        }

        let input = String::from_utf8(request.input)
            .unwrap_or_else(|_| {
                error!("parse input failed");
                "".to_string()
            });
        if input == "".to_string() {
            let res = TestOpaResponse {
                status: "parse input failed".as_bytes().to_vec()
            };
            return Ok(Response::new(res))
        }
    
        let msg = opa::opa_engine::make_decision_ext(
            &policyname, 
            &policycontent,
            request.policylocal,
            &referencename,
            &referencecontent,
            request.referencelocal,
            &input)
            .map_err(|e| format!("make_decision error: {}", e))
            .and_then(|res| {
                serde_json::from_str(&res).map_err(|_| res)
            })
            .and_then(|res: serde_json::Value| {
                Ok(res.to_string())
            });

        let msg = match msg {
                Ok(msg) => msg,
                Err(e) => e
            };
        
        let res = TestOpaResponse {
            status: msg.as_bytes().to_vec()
        };

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
