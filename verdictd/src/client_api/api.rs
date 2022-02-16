use crate::client_api;
use tonic::transport::Server;

use clientApi::gpg_service_server::GpgServiceServer;
use clientApi::image_service_server::ImageServiceServer;
use clientApi::key_manager_service_server::KeyManagerServiceServer;
use clientApi::opa_service_server::OpaServiceServer;
use client_api::key_provider::keyProvider::key_provider_service_server::KeyProviderServiceServer;

pub mod clientApi {
    tonic::include_proto!("clientapi");
}

pub async fn server(addr: &str) -> Result<(), Box<dyn std::error::Error>> {
    let addr = addr.parse()?;
    let gpg_service = client_api::gpg::gpgService::default();
    let image_service = client_api::image::imageService::default();
    let key_manager_service = client_api::key_manager::keyManagerService::default();
    let key_provider_service = client_api::key_provider::keyProviderService::default();
    let opa_service = client_api::opa::opaService::default();

    Server::builder()
        .add_service(GpgServiceServer::new(gpg_service))
        .add_service(ImageServiceServer::new(image_service))
        .add_service(KeyManagerServiceServer::new(key_manager_service))
        .add_service(KeyProviderServiceServer::new(key_provider_service))
        .add_service(OpaServiceServer::new(opa_service))
        .serve(addr)
        .await?;

    Ok(())
}
