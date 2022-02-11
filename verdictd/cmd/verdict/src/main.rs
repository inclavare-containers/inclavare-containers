use clap::{App, Arg};

pub mod configure_provider {
    tonic::include_proto!("configureprovider");
}

mod opa;

#[macro_use]
extern crate log;

#[tokio::main]
async fn main() {
    env_logger::builder().filter(None, log::LevelFilter::Info).init();

    let matches = App::new("verdict")
        .version("0.1")
        .author("Inclavare-Containers Team")
        .arg(
            Arg::with_name("set_policy")
                .long("set_policy")
                .value_name("POLICY_NAME")
                .value_name("POLICY_PATH")
                .help("Generate a policy file named <POLICY_NAME>, according to the contents in <POLICY_PATH>.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("export_policy")
                .long("export_policy")
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
            Arg::with_name("set_reference")
                .long("set_reference")
                .value_name("REFERENCE_NAME")
                .value_name("REFERENCE_PATH")
                .help("Generate a reference file named <REFERENCE_NAME>, according to the contents in <REFERENCE_PATH>.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("export_reference")
                .long("export_reference")
                .value_name("REFERENCE_NAME")
                .help("export OPA reference file named <REFERENCE_NAME>")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("config")
                .long("config")
                .short("c")
                .value_name("CONFIG_ADDR")
                .help("Specify the config address.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("test_remote")
                .long("test_remote")
                .value_name("POLICY_NAME")
                .value_name("REFERENCE_NAME")
                .value_name("INPUT_PATH")
                .help("test OPA's remote policy and remote reference")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("test_local")
                .long("test_local")
                .value_name("POLICY_PATH")
                .value_name("REFERENCE_PATH")
                .value_name("INPUT_PATH")
                .help("test OPA's local policy and local reference")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("test_localpolicy")
                .long("test_localpolicy")
                .value_name("POLICY_PATH")
                .value_name("REFERENCE_NAME")
                .value_name("INPUT_PATH")
                .help("test OPA's local policy and remote reference")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("test_localreference")
                .long("test_localreference")
                .value_name("POLICY_NAME")
                .value_name("REFERENCE_PATH")
                .value_name("INPUT_PATH")
                .help("test OPA's remote policy and local reference")
                .takes_value(true),
        )
        .get_matches();

    let config_addr = if matches.is_present("config") {
        matches.value_of("config").unwrap().to_string()
    } else {
        "[::1]:60000".to_string()
    };
    info!("Connect to Verdictd with addr: {}", config_addr);

    // set_policy
    if matches.is_present("set_policy") {
        opa::set_policy_cmd(matches.values_of("set_policy").unwrap().collect(), &config_addr).await;
    }

    // export_policy
    if matches.is_present("export_policy") {
        let mut path: String = if matches.is_present("path") {
            matches.value_of("path").unwrap().to_string()
        } else {
            "./".to_string()
        };
        if !path.ends_with("/") {
            path = format!("{}/", path);
        }
        opa::export_policy_cmd(matches.value_of("export_policy").unwrap(), path, &config_addr).await;
    }

    // set data
    if matches.is_present("set_reference") {
        opa::set_reference_cmd(matches.values_of("set_reference").unwrap().collect(), &config_addr).await;
    }

    // export Data
    if matches.is_present("export_reference") {
        let mut path: String = if matches.is_present("path") {
            matches.value_of("path").unwrap().to_string()
        } else {
            "./".to_string()
        };
        if !path.ends_with("/") {
            path = format!("{}/", path);
        }
        opa::export_reference_cmd(matches.value_of("export_reference").unwrap(), path, &config_addr).await;
    }

    if matches.is_present("test_remote") {
        opa::test_remote_cmd(matches.values_of("test_remote").unwrap().collect(), &config_addr).await;
    }

    if matches.is_present("test_local") {
        opa::test_local_cmd(matches.values_of("test_local").unwrap().collect(), &config_addr).await;
    }

    if matches.is_present("test_localpolicy") {
        opa::test_localpolicy_cmd(matches.values_of("test_localpolicy").unwrap().collect(), &config_addr).await;
    }

    if matches.is_present("test_localreference") {
        opa::test_localreference_cmd(matches.values_of("test_localreference").unwrap().collect(), &config_addr).await;
    }
}
