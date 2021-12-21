use serde_json::Value;
use std::fs;
use std::io::prelude::*;

use crate::configure_provider::configure_provider_service_client::ConfigureProviderServiceClient;
use crate::configure_provider::{SetOpaPolicyRequest, SetOpaPolicyResponse};
use crate::configure_provider::{ExportOpaPolicyRequest, ExportOpaPolicyResponse};
use crate::configure_provider::{SetOpaReferenceRequest, SetOpaReferenceResponse};
use crate::configure_provider::{ExportOpaReferenceRequest, ExportOpaReferenceResponse};
use crate::configure_provider::{TestOpaRequest, TestOpaResponse};

pub async fn set_policy_cmd(vals: Vec<&str>, addr: &str) {
    let mut content = String::new();

    fs::File::open(vals[1])
        .expect(&format!("Failed to open the file named {}.", vals[1]))
        .read_to_string(&mut content)
        .expect(&format!("Failed to read from the file named {}.", vals[1]));

    let request = SetOpaPolicyRequest {
        name: vals[0].as_bytes().to_vec(),
        content: content.to_string().into_bytes(),
    };

    let mut client = ConfigureProviderServiceClient::connect(format!("http://{}", addr))
    .await
    .unwrap();

    let response: SetOpaPolicyResponse = client
        .set_opa_policy(request)
        .await
        .unwrap()
        .into_inner();
    info!(
        "set_opa_policy status is: {:?}",
        String::from_utf8(response.status).unwrap()
    );
}

pub async fn export_policy_cmd(name: &str, path: String, addr: &str) {
    let request = ExportOpaPolicyRequest {
        name: name.as_bytes().to_vec(),
    };

    let mut client = ConfigureProviderServiceClient::connect(format!("http://{}", addr))
    .await
    .unwrap();

    let response: ExportOpaPolicyResponse = client
        .export_opa_policy(request)
        .await
        .unwrap()
        .into_inner();
    let content = String::from_utf8(response.content).unwrap();

    info!(
        "export_opa_policy status is: {:?}",
        String::from_utf8(response.status).unwrap()
    );
    info!("policy: {} content is:\n{}", name, content);

    fs::File::create(path + name)
        .expect("Failed to create the file.")
        .write_all(content.as_bytes())
        .expect("Faied to write the policy content into the file.");
}

pub async fn set_reference_cmd(vals: Vec<&str>, addr: &str) {
    let mut data = String::new();

    fs::File::open(vals[1])
        .expect(&format!("Failed to open the file named {}.", vals[1]))
        .read_to_string(&mut data)
        .expect(&format!("Failed to read from the file named {}.", vals[1]));

    let _json: Value =
        serde_json::from_str(&data).expect("File content is not in json format.");

    let request = SetOpaReferenceRequest {
        name: vals[0].as_bytes().to_vec(),
        content: data.into_bytes(),
    };

    let mut client = ConfigureProviderServiceClient::connect(format!("http://{}", addr))
    .await
    .unwrap();

    let response: SetOpaReferenceResponse = client
        .set_opa_reference(request)
        .await
        .unwrap()
        .into_inner();
    info!(
        "set_opa_reference status is: {:?}",
        String::from_utf8(response.status).unwrap()
    );
}

pub async fn export_reference_cmd(name: &str, path: String, addr: &str) {
    let request = ExportOpaReferenceRequest {
        name: name.as_bytes().to_vec(),
    };

    let mut client = ConfigureProviderServiceClient::connect(format!("http://{}", addr))
    .await
    .unwrap();

    let response: ExportOpaReferenceResponse = client
        .export_opa_reference(request)
        .await
        .unwrap()
        .into_inner();
    let data = String::from_utf8(response.content).unwrap();

    info!(
        "export_opa_reference status is: {:?}",
        String::from_utf8(response.status).unwrap()
    );
    info!("data: {} content is:\n{}", name, data);

    fs::File::create(path + name)
        .expect("Failed to create the file.")
        .write_all(data.as_bytes())
        .expect("Faied to write the policy content into the file.");
}

pub async fn test_remote_cmd(vals: Vec<&str>, addr: &str) {
    info!("OPA Test remote: policy name: {}, reference name:{}, input file:{}", vals[0], vals[1], vals[2]);

    let mut input = String::new();
    fs::File::open(vals[2])
        .expect(&format!("Failed to open the file named {}.", vals[2]))
        .read_to_string(&mut input)
        .expect(&format!("Failed to read from the file named {}.", vals[2]));
    let _json: Value =
        serde_json::from_str(&input).expect("File content is not in json format.");
    
    let policycontent = "".to_string();
    let referencecontent = "".to_string();

    let request = TestOpaRequest {
        policyname: vals[0].as_bytes().to_vec(),
        policycontent: policycontent.as_bytes().to_vec(),
        policylocal: false,
        referencename: vals[1].as_bytes().to_vec(),
        referencecontent: referencecontent.as_bytes().to_vec(),
        referencelocal: false,
        input: input.to_string().into_bytes(),
    };

    let mut client = ConfigureProviderServiceClient::connect(format!("http://{}", addr))
    .await
    .unwrap();

    let response: TestOpaResponse = client
        .test_opa(request)
        .await
        .unwrap()
        .into_inner();
    info!(
        "TestOpa status is: {:?}",
        String::from_utf8(response.status).unwrap()
    );
}

pub async fn test_local_cmd(vals: Vec<&str>, addr: &str) {
    info!("OPA Test local: policy file: {}, reference file:{}, input file:{}", vals[0], vals[1], vals[2]);

    let mut policycontent = String::new();
    fs::File::open(vals[0])
        .expect(&format!("Failed to open the file named {}.", vals[0]))
        .read_to_string(&mut policycontent)
        .expect(&format!("Failed to read from the file named {}.", vals[0]));

    let mut referencecontent = String::new();
    fs::File::open(vals[1])
        .expect(&format!("Failed to open the file named {}.", vals[1]))
        .read_to_string(&mut referencecontent)
        .expect(&format!("Failed to read from the file named {}.", vals[1]));

    let mut input = String::new();
    fs::File::open(vals[2])
        .expect(&format!("Failed to open the file named {}.", vals[2]))
        .read_to_string(&mut input)
        .expect(&format!("Failed to read from the file named {}.", vals[2]));
    let _json: Value =
        serde_json::from_str(&input).expect("File content is not in json format.");

    let request = TestOpaRequest {
        policyname: vals[0].as_bytes().to_vec(),
        policycontent: policycontent.as_bytes().to_vec(),
        policylocal: true,
        referencename: vals[1].as_bytes().to_vec(),
        referencecontent: referencecontent.as_bytes().to_vec(),
        referencelocal: true,
        input: input.to_string().into_bytes(),
    };

    let mut client = ConfigureProviderServiceClient::connect(format!("http://{}", addr))
    .await
    .unwrap();

    let response: TestOpaResponse = client
        .test_opa(request)
        .await
        .unwrap()
        .into_inner();
    info!(
        "Opa execution result: {:?}",
        String::from_utf8(response.status).unwrap()
    );
}

pub async fn test_localpolicy_cmd(vals: Vec<&str>, addr: &str) {
    info!("OPA Test local policy: policy file: {}, reference name:{}, input file:{}", vals[0], vals[1], vals[2]);

    let mut policycontent = String::new();
    fs::File::open(vals[0])
        .expect(&format!("Failed to open the file named {}.", vals[0]))
        .read_to_string(&mut policycontent)
        .expect(&format!("Failed to read from the file named {}.", vals[0]));

    let mut input = String::new();
    fs::File::open(vals[2])
        .expect(&format!("Failed to open the file named {}.", vals[2]))
        .read_to_string(&mut input)
        .expect(&format!("Failed to read from the file named {}.", vals[2]));
    let _json: Value =
        serde_json::from_str(&input).expect("File content is not in json format.");
    let referencecontent = "".to_string();

    let request = TestOpaRequest {
        policyname: vals[0].as_bytes().to_vec(),
        policycontent: policycontent.as_bytes().to_vec(),
        policylocal: true,
        referencename: vals[1].as_bytes().to_vec(),
        referencecontent: referencecontent.as_bytes().to_vec(),
        referencelocal: false,
        input: input.to_string().into_bytes(),
    };

    let mut client = ConfigureProviderServiceClient::connect(format!("http://{}", addr))
    .await
    .unwrap();

    let response: TestOpaResponse = client
        .test_opa(request)
        .await
        .unwrap()
        .into_inner();
    info!(
        "TestOpa status is: {:?}",
        String::from_utf8(response.status).unwrap()
    );
}

pub async fn test_localreference_cmd(vals: Vec<&str>, addr: &str) {
    info!("OPA Test local reference: policy name: {}, reference file:{}, input file:{}", vals[0], vals[1], vals[2]);

    let mut referencecontent = String::new();
    fs::File::open(vals[1])
        .expect(&format!("Failed to open the file named {}.", vals[1]))
        .read_to_string(&mut referencecontent)
        .expect(&format!("Failed to read from the file named {}.", vals[1]));

    let mut input = String::new();
    fs::File::open(vals[2])
        .expect(&format!("Failed to open the file named {}.", vals[2]))
        .read_to_string(&mut input)
        .expect(&format!("Failed to read from the file named {}.", vals[2]));
    let _json: Value =
        serde_json::from_str(&input).expect("File content is not in json format.");

    let policycontent = "".to_string();

    let request = TestOpaRequest {
        policyname: vals[0].as_bytes().to_vec(),
        policycontent: policycontent.as_bytes().to_vec(),
        policylocal: false,
        referencename: vals[1].as_bytes().to_vec(),
        referencecontent: referencecontent.as_bytes().to_vec(),
        referencelocal: true,
        input: input.to_string().into_bytes(),
    };

    let mut client = ConfigureProviderServiceClient::connect(format!("http://{}", addr))
    .await
    .unwrap();

    let response: TestOpaResponse = client
        .test_opa(request)
        .await
        .unwrap()
        .into_inner();
    info!(
        "TestOpa status is: {:?}",
        String::from_utf8(response.status).unwrap()
    );
}
