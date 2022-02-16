use clap::{App, Arg};

pub mod client_api {
    tonic::include_proto!("clientapi");
}

mod opa;
mod gpg;
mod image;

#[macro_use]
extern crate log;

#[tokio::main]
async fn main() {
    env_logger::builder().filter(None, log::LevelFilter::Info).init();

    let matches = App::new("verdict")
        .version("0.1")
        .author("Inclavare-Containers Team")
        .arg(
            Arg::with_name("set_opa_policy")
                .long("set-opa-policy")
                .value_name("POLICY_NAME")
                .value_name("POLICY_PATH")
                .help("Generate a policy file named <POLICY_NAME>, according to the contents in <POLICY_PATH>.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("export_opa_policy")
                .long("export-opa-policy")
                .value_name("POLICY_NAME")
                .help("Export the contents of the policy file named <POLICY_NAME>.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("path")
                .long("path")
                .short("p")
                .value_name("PATH")
                .help("Specify the path of the export file, must be used with '-e'.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("set_opa_reference")
                .long("set-opa-reference")
                .value_name("REFERENCE_NAME")
                .value_name("REFERENCE_PATH")
                .help("Generate a reference file named <REFERENCE_NAME>, according to the contents in <REFERENCE_PATH>.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("export_opa_reference")
                .long("export-opa-reference")
                .value_name("REFERENCE_NAME")
                .help("export OPA reference file named <REFERENCE_NAME>")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("client_api")
                .long("client-api")
                .short("c")
                .value_name("CLIENT_API_ADDRESS")
                .help("Specify the client API's connection address.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("test_opa_remote")
                .long("test-opa-remote")
                .value_name("POLICY_NAME")
                .value_name("REFERENCE_NAME")
                .value_name("INPUT_PATH")
                .help("test OPA's remote policy and remote reference")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("test_opa_local")
                .long("test-opa-local")
                .value_name("POLICY_PATH")
                .value_name("REFERENCE_PATH")
                .value_name("INPUT_PATH")
                .help("test OPA's local policy and local reference")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("test_opa_local_policy")
                .long("test-opa-local-policy")
                .value_name("POLICY_PATH")
                .value_name("REFERENCE_NAME")
                .value_name("INPUT_PATH")
                .help("test OPA's local policy and remote reference")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("test_opa_local_reference")
                .long("test-opa-local-reference")
                .value_name("POLICY_NAME")
                .value_name("REFERENCE_PATH")
                .value_name("INPUT_PATH")
                .help("test OPA's remote policy and local reference")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("list_gpg_keys")
                .long("list-gpg-keys")
                .help("list all gpg public keys")
        )
        .arg(
            Arg::with_name("import_gpg_key")
                .long("import-gpg-key")
                .value_name("KEY_FILE")
                .help("import a GPG public key")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("delete_gpg_key")
                .long("delete-gpg-key")
                .value_name("KEY_ID")
                .help("delete the keyid designated GPG public key")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("export_gpg_keyring")
                .long("export-gpg-keyring")
                .help("export GPG keyring with Base64 format")
        )
        .arg(
            Arg::with_name("export_image_sigstore")
                .long("export-image-sigstore")
                .help("export image sigstore file")
        )
        .arg(
            Arg::with_name("set_image_sigstore")
                .long("set-image-sigstore")
                .value_name("SIGSTORE_PATH")
                .help("set image sigstore according to the contents in <SIGSTORE_PATH>.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("export_image_policy")
                .long("export-image-policy")
                .help("export image policy file")
        )
        .arg(
            Arg::with_name("set_image_policy")
                .long("set-image-policy")
                .value_name("POLICY_PATH")
                .help("set image policy according to the contents in <POLICY_PATH>.")
                .takes_value(true),
        )
        .get_matches();

    let client_api = if matches.is_present("client_api") {
        matches.value_of("client_api").unwrap().to_string()
    } else {
        "[::1]:60000".to_string()
    };
    info!("Connect to Verdictd with addr: {}", client_api);

    // set_opa_policy
    if matches.is_present("set_opa_policy") {
        opa::set_policy_cmd(matches.values_of("set_opa_policy").unwrap().collect(), &client_api).await;
    }

    // export_opa_policy
    if matches.is_present("export_opa_policy") {
        let mut path: String = if matches.is_present("path") {
            matches.value_of("path").unwrap().to_string()
        } else {
            "./".to_string()
        };
        if !path.ends_with("/") {
            path = format!("{}/", path);
        }
        opa::export_policy_cmd(matches.value_of("export_opa_policy").unwrap(), path, &client_api).await;
    }

    // set data
    if matches.is_present("set_opa_reference") {
        opa::set_reference_cmd(matches.values_of("set_opa_reference").unwrap().collect(), &client_api).await;
    }

    // export Data
    if matches.is_present("export_opa_reference") {
        let mut path: String = if matches.is_present("path") {
            matches.value_of("path").unwrap().to_string()
        } else {
            "./".to_string()
        };
        if !path.ends_with("/") {
            path = format!("{}/", path);
        }
        opa::export_reference_cmd(matches.value_of("export_opa_reference").unwrap(), path, &client_api).await;
    }

    if matches.is_present("test_opa_remote") {
        opa::test_remote_cmd(matches.values_of("test_opa_remote").unwrap().collect(), &client_api).await;
    }

    if matches.is_present("test_opa_local") {
        opa::test_local_cmd(matches.values_of("test_opa_local").unwrap().collect(), &client_api).await;
    }

    if matches.is_present("test_opa_local_policy") {
        opa::test_localpolicy_cmd(matches.values_of("test_opa_local_policy").unwrap().collect(), &client_api).await;
    }

    if matches.is_present("test_opa_local_reference") {
        opa::test_localreference_cmd(matches.values_of("test_opa_local_reference").unwrap().collect(), &client_api).await;
    }

    if matches.is_present("list_gpg_keys") {
        gpg::list_gpg_keys_cmd(&client_api).await;
    }

    if matches.is_present("import_gpg_key") {
        gpg::import_gpg_key_cmd(matches.values_of("import_gpg_key").unwrap().collect(), &client_api).await;
    }

    if matches.is_present("export_gpg_keyring") {
        gpg::export_gpg_keyring_cmd(&client_api).await;
    }

    if matches.is_present("delete_gpg_key") {
        gpg::delete_gpg_key_cmd(matches.values_of("delete_gpg_key").unwrap().collect(), &client_api).await;
    }

    if matches.is_present("export_image_sigstore") {
        let mut path: String = if matches.is_present("path") {
            matches.value_of("path").unwrap().to_string()
        } else {
            "./".to_string()
        };
        if !path.ends_with("/") {
            path = format!("{}/", path);
        }
        image::export_image_sigstore_cmd(path, &client_api).await;
    }

    if matches.is_present("set_image_sigstore") {
        image::set_image_sigstore_cmd(matches.values_of("set_image_sigstore").unwrap().collect(), &client_api).await;
    }

    if matches.is_present("export_image_policy") {
        let mut path: String = if matches.is_present("path") {
            matches.value_of("path").unwrap().to_string()
        } else {
            "./".to_string()
        };
        if !path.ends_with("/") {
            path = format!("{}/", path);
        }
        image::export_image_policy_cmd(path, &client_api).await;
    }

    if matches.is_present("set_image_policy") {
        image::set_image_policy_cmd(matches.values_of("set_image_policy").unwrap().collect(), &client_api).await;
    }
}
