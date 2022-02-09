use std::fs;
use std::io::prelude::*;

use crate::client_api::image_service_client::ImageServiceClient;
use crate::client_api::{ExportImageSigstoreRequest, ExportImageSigstoreResponse};
use crate::client_api::{SetImageSigstoreRequest, SetImageSigstoreResponse};
use crate::client_api::{ExportImagePolicyRequest, ExportImagePolicyResponse};
use crate::client_api::{SetImagePolicyRequest, SetImagePolicyResponse};

pub async fn export_image_sigstore_cmd(path: String, addr: &str) {
    let request = ExportImageSigstoreRequest {};

    let mut client = ImageServiceClient::connect(format!("http://{}", addr))
    .await
    .unwrap();

    let response: ExportImageSigstoreResponse = client
        .export_image_sigstore(request)
        .await
        .unwrap()
        .into_inner();
    let content = String::from_utf8(response.content).unwrap();

    info!(
        "export_image_sigstore status is: {:?}",
        String::from_utf8(response.status).unwrap()
    );
    info!("image sigstore:\n{}", content);

    let sigstore = path + "image_sigstore.ymal";
    fs::File::create(sigstore)
        .expect("Failed to create the file.")
        .write_all(content.as_bytes())
        .expect("Faied to write sigstore content into the file.");
}

pub async fn set_image_sigstore_cmd(vals: Vec<&str>, addr: &str) {
    let mut data = String::new();

    fs::File::open(&vals[0])
        .expect(&format!("Failed to open the file named {}.", &vals[0]))
        .read_to_string(&mut data)
        .expect(&format!("Failed to read from the file named {}.", &vals[0]));

    let request = SetImageSigstoreRequest {
        content: data.into_bytes(),
    };

    let mut client = ImageServiceClient::connect(format!("http://{}", addr))
    .await
    .unwrap();

    let response: SetImageSigstoreResponse = client
        .set_image_sigstore(request)
        .await
        .unwrap()
        .into_inner();
    info!(
        "set_image_sigstore status is: {:?}",
        String::from_utf8(response.status).unwrap()
    );
}

pub async fn export_image_policy_cmd(path: String, addr: &str) {
    let request = ExportImagePolicyRequest {};

    let mut client = ImageServiceClient::connect(format!("http://{}", addr))
    .await
    .unwrap();

    let response: ExportImagePolicyResponse = client
        .export_image_policy(request)
        .await
        .unwrap()
        .into_inner();
    let content = String::from_utf8(response.content).unwrap();

    info!(
        "export_image_policy status is: {:?}",
        String::from_utf8(response.status).unwrap()
    );
    info!("image policy.json:\n{}", content);

    let policy = path + "image_policy.json";
    fs::File::create(policy)
        .expect("Failed to create the file.")
        .write_all(content.as_bytes())
        .expect("Faied to write policy.json content into the file.");
}

pub async fn set_image_policy_cmd(vals: Vec<&str>, addr: &str) {
    let mut data = String::new();

    fs::File::open(&vals[0])
        .expect(&format!("Failed to open the file named {}.", &vals[0]))
        .read_to_string(&mut data)
        .expect(&format!("Failed to read from the file named {}.", &vals[0]));

    let request = SetImagePolicyRequest {
        content: data.into_bytes(),
    };

    let mut client = ImageServiceClient::connect(format!("http://{}", addr))
    .await
    .unwrap();

    let response: SetImagePolicyResponse = client
        .set_image_policy(request)
        .await
        .unwrap()
        .into_inner();
    info!(
        "set_image_policy status is: {:?}",
        String::from_utf8(response.status).unwrap()
    );
}
