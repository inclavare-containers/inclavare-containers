use tonic::{Request, Response, Status};
use crate::client_api::api;
use crate::resources::image;

use api::clientApi::image_service_server::ImageService;
use api::clientApi::{ExportImageSigstoreRequest, ExportImageSigstoreResponse};
use api::clientApi::{SetImageSigstoreRequest, SetImageSigstoreResponse};
use api::clientApi::{ExportImagePolicyRequest, ExportImagePolicyResponse};
use api::clientApi::{SetImagePolicyRequest, SetImagePolicyResponse};

#[derive(Debug, Default)]
pub struct imageService {}

#[tonic::async_trait]
impl ImageService for imageService {
    async fn export_image_sigstore(
        &self,
        _request: Request<ExportImageSigstoreRequest>,
    ) -> Result<Response<ExportImageSigstoreResponse>, Status> {
        let res = image::export(image::SIGSTORE)
            .and_then(|content| {
                let res = ExportImageSigstoreResponse {
                    status: "OK".as_bytes().to_vec(),
                    content: content.into_bytes(),
                };
                Ok(res)
            })
            .unwrap_or_else(|e| {
                ExportImageSigstoreResponse {
                    status: e.into_bytes(),
                    content: "".as_bytes().to_vec(),
                }
            });   

        Ok(Response::new(res))
    }

    async fn set_image_sigstore(
        &self,
        request: Request<SetImageSigstoreRequest>,
    ) -> Result<Response<SetImageSigstoreResponse>, Status> {
        let empty = "".to_string();
        let request: SetImageSigstoreRequest = request.into_inner();
        let content = std::str::from_utf8(&request.content)
            .unwrap_or_else(|_| {
                error!("parse content failed");
                &empty
            });
        
        info!("content: {}", content);
            
        let res = image::set(image::SIGSTORE, content)
            .and_then(|_| {
                let res = SetImageSigstoreResponse {
                    status: "OK".as_bytes().to_vec(),
                };
                Ok(res)
            })
            .unwrap_or_else(|e| {
                SetImageSigstoreResponse {
                    status: e.into_bytes(),
                }
            });

        Ok(Response::new(res))
    }

    async fn export_image_policy(
        &self,
        _request: Request<ExportImagePolicyRequest>,
    ) -> Result<Response<ExportImagePolicyResponse>, Status> {
        info!("export image policy");
        let res = image::export(image::POLICY)
            .and_then(|content| {
                let res = ExportImagePolicyResponse {
                    status: "OK".as_bytes().to_vec(),
                    content: content.into_bytes(),
                };
                Ok(res)
            })
            .unwrap_or_else(|e| {
                ExportImagePolicyResponse {
                    status: e.into_bytes(),
                    content: "".as_bytes().to_vec(),
                }
            });   

        Ok(Response::new(res))
    }

    async fn set_image_policy(
        &self,
        request: Request<SetImagePolicyRequest>,
    ) -> Result<Response<SetImagePolicyResponse>, Status> {
        let empty = "".to_string();
        let request: SetImagePolicyRequest = request.into_inner();
        let content = std::str::from_utf8(&request.content)
            .unwrap_or_else(|_| {
                error!("parse content failed");
                &empty
            });
        
        info!("content: {}", content);
            
        let res = image::set(image::POLICY, content)
            .and_then(|_| {
                let res = SetImagePolicyResponse {
                    status: "OK".as_bytes().to_vec(),
                };
                Ok(res)
            })
            .unwrap_or_else(|e| {
                SetImagePolicyResponse {
                    status: e.into_bytes(),
                }
            });

        Ok(Response::new(res))
    }
}