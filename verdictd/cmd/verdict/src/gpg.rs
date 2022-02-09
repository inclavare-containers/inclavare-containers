use std::fs;
use std::io::prelude::*;

use crate::client_api::gpg_service_client::GpgServiceClient;
use crate::client_api::{ListGpgKeysRequest, ListGpgKeysResponse};
use crate::client_api::{ImportGpgKeyRequest, ImportGpgKeyResponse};
use crate::client_api::{DeleteGpgKeyRequest, DeleteGpgKeyResponse};
use crate::client_api::{ExportGpgKeyringRequest, ExportGpgKeyringResponse};

pub async fn list_gpg_keys_cmd(addr: &str) {
    let request = ListGpgKeysRequest {};

    let mut client = GpgServiceClient::connect(format!("http://{}", addr))
    .await
    .unwrap();

    let response: ListGpgKeysResponse = client
        .list_gpg_keys(request)
        .await
        .unwrap()
        .into_inner();
    info!(
        "{}",
        String::from_utf8(response.keys).unwrap()
    );
}

pub async fn import_gpg_key_cmd(vals: Vec<&str>, addr: &str) {
    info!("import gpg key: {}", vals[0]);

    let mut key = String::new();
    fs::File::open(vals[0])
        .expect(&format!("Failed to open the key file {}.", vals[0]))
        .read_to_string(&mut key)
        .expect(&format!("Failed to read from the key file {}.", vals[0]));

    let request = ImportGpgKeyRequest {
        key: key.as_bytes().to_vec(),
    };

    let mut client = GpgServiceClient::connect(format!("http://{}", addr))
    .await
    .unwrap();

    let response: ImportGpgKeyResponse = client
        .import_gpg_key(request)
        .await
        .unwrap()
        .into_inner();
    info!(
        "{}",
        String::from_utf8(response.status).unwrap()
    );
}

pub async fn delete_gpg_key_cmd(vals: Vec<&str>, addr: &str) {
    info!("delete gpg key: {}", vals[0]);

    let request = DeleteGpgKeyRequest {
        keyid: vals[0].as_bytes().to_vec(),
    };

    let mut client = GpgServiceClient::connect(format!("http://{}", addr))
    .await
    .unwrap();

    let response: DeleteGpgKeyResponse = client
        .delete_gpg_key(request)
        .await
        .unwrap()
        .into_inner();
    info!(
        "{}",
        String::from_utf8(response.status).unwrap()
    );
}

pub async fn export_gpg_keyring_cmd(addr: &str) {
    let request = ExportGpgKeyringRequest {};

    let mut client = GpgServiceClient::connect(format!("http://{}", addr))
    .await
    .unwrap();

    let response: ExportGpgKeyringResponse = client
        .export_gpg_keyring(request)
        .await
        .unwrap()
        .into_inner();
    info!(
        "{}",
        String::from_utf8(response.content).unwrap()
    );
}
