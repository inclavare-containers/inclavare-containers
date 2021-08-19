use clap::{App, Arg};
use serde_json::Value;
use std::fs::File;
use std::io::prelude::*;

use configureProvider::configure_provider_service_client::ConfigureProviderServiceClient;
use configureProvider::{ExportPolicyRequest, ExportPolicyResponse};
use configureProvider::{SetPolicyRequest, SetPolicyResponse};
use configureProvider::{SetRawPolicyRequest, SetRawPolicyResponse};

pub mod configureProvider {
    tonic::include_proto!("configureprovider");
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let matches = App::new("verdict")
        .version("0.1")
        .author("Inclavare-Containers Team")
        .arg(
            Arg::with_name("set_policy")
                .short("s")
                .long("set_policy")
                .value_name("POLICY_NAME")
                .value_name("FILE_REFERENCE")
                .help("Generate a policy file named <POLICY_NAME>, according to the contents in <FILE_REFERENCE>.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("set_raw_policy")
                .short("r")
                .long("set_raw_policy")
                .value_name("POLICY_NAME")
                .value_name("FILE")
                .help("Write the contents of <FILE> into the policy file named <POLICY_NAME>.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("export_policy")
                .short("e")
                .long("export_policy")
                .value_name("POLICY_NAME")
                .help("Export the contents of the policy file named <POLICY_NAME>.")
                .takes_value(true),
        )
        .get_matches();

    let mut client = ConfigureProviderServiceClient::connect("http://[::1]:60000").await?;

    // set_policy
    if matches.is_present("set_policy") {
        let vals: Vec<&str> = matches.values_of("set_policy").unwrap().collect();

        let mut reference = String::new();

        File::open(vals[1])
            .expect(&format!("Failed to open the file named {}.", vals[1]))
            .read_to_string(&mut reference)
            .expect(&format!("Failed to read from the file named {}.", vals[1]));

        let reference: Value =
            serde_json::from_str(&reference).expect("File content is not in json format.");

        let request = SetPolicyRequest {
            policyname: vals[0].as_bytes().to_vec(),
            references: reference.to_string().into_bytes(),
        };

        let response: SetPolicyResponse = client.set_policy(request).await?.into_inner();
        println!(
            "SetPolicy status is: {:?}",
            String::from_utf8(response.status).unwrap()
        );
    }

    // set_raw_policy
    if matches.is_present("set_raw_policy") {
        let vals: Vec<&str> = matches.values_of("set_raw_policy").unwrap().collect();

        let mut policy = String::new();

        File::open(vals[1])
            .expect(&format!("Failed to open the file named {}.", vals[1]))
            .read_to_string(&mut policy)
            .expect(&format!("Failed to read from the file named {}.", vals[1]));

        let request = SetRawPolicyRequest {
            policyname: vals[0].as_bytes().to_vec(),
            policycontent: policy.to_string().into_bytes(),
        };

        let response: SetRawPolicyResponse = client.set_raw_policy(request).await?.into_inner();
        println!(
            "SetRawPolicy status is: {:?}",
            String::from_utf8(response.status).unwrap()
        );
    }

    // export_policy
    if matches.is_present("export_policy") {
        let policyname = matches.value_of("export_policy").unwrap();

        let request = ExportPolicyRequest {
            policyname: policyname.as_bytes().to_vec(),
        };

        let response: ExportPolicyResponse = client.export_policy(request).await?.into_inner();
        let policy = String::from_utf8(response.policycontent).unwrap();

        println!(
            "export_policy status is: {:?}",
            String::from_utf8(response.status).unwrap()
        );
        println!("policy: {} content is:\n{}", policyname, policy);

        File::create(policyname)
            .expect("Failed to create the file.")
            .write_all(policy.as_bytes())
            .expect("Faied to write the policy content into the file.");
    }

    Ok(())
}
