
use tonic::{transport::Server, Request, Response, Status};
use crate::key_manager::directory_key_manager;
use crate::crypto::aes256_cbc;
use rand::*;
use uuid::Uuid;
use crate::key_provider::annotation;
use crate::key_provider::messages::*;
use keyProvider::key_provider_service_server::{KeyProviderService, KeyProviderServiceServer};
use keyProvider::{KeyProviderKeyWrapProtocolInput, KeyProviderKeyWrapProtocolOutput};

pub mod keyProvider {
    tonic::include_proto!("key_provider");
}

#[derive(Debug, Default)]
pub struct keyProviderSrv {}
 
#[tonic::async_trait]
impl KeyProviderService for keyProviderSrv {
    async fn wrap_key(
        &self,
        request: Request<KeyProviderKeyWrapProtocolInput>,
    ) -> Result<Response<KeyProviderKeyWrapProtocolOutput>, Status> {
        let wrap_command = 
            String::from_utf8(request.into_inner().key_provider_key_wrap_protocol_input)
            .and_then(|request|{
                Ok(serde_json::from_str::<KeyProviderInput>(&request[..]))
            })
            .unwrap();

        let wrap_command = match wrap_command {
            Ok(wrap_command) => wrap_command,
            Err(_) => {
                let reply = KeyProviderKeyWrapProtocolOutput {
                    key_provider_key_wrap_protocol_output: b"Parser failure".to_vec(),
                };
                return Ok(Response::new(reply));
            }
        };

        let mut kid = Uuid::new_v4().to_string();
        let ec = wrap_command.keywrapparams.ec.unwrap();
        let optsdata = wrap_command.keywrapparams.optsdata.unwrap();
        if ec.Parameters.contains_key("attestation-agent") {
            kid = ec.Parameters["attestation-agent"][0].to_string();
        } else {
            // generate a new key file with a new random key
            let mut key:[u8;32]=[0;32];
            rand::rngs::OsRng.fill_bytes(&mut key);
            directory_key_manager::set_key(&kid, &key)?;
        }
        let mut iv:[u8;16]=[0;16];
        rand::rngs::OsRng.fill_bytes(&mut iv);
        println!("iv: {:?}", iv);

        let encrypted_data = 
            directory_key_manager::get_key(&kid)
            .and_then(|key|{
                println!("key: {:?}", key);
                let encrypted_data = 
                    aes256_cbc::encrypt(optsdata.as_bytes(), key.as_slice(), &iv)
                        .unwrap_or_else(|_|vec![0]);
                Ok(encrypted_data)
            })
            .unwrap_or_else(|_|vec![0]);

        let annotation = annotation::AnnotationPacket {
            url: String::from("https://key-provider"),
            kid: kid.to_string(),
            wrapped_data: encrypted_data,
            iv: iv.to_vec(),
            wrap_type: String::from("AES256-CBC"),
        };
        
        let key_wrap_results = KeyWrapResults {
            annotation: serde_json::to_string(&annotation)
                .unwrap()
                .as_bytes()
                .to_vec(),
        };
 
        let reply = KeyProviderKeyWrapProtocolOutput {
            key_provider_key_wrap_protocol_output: serde_json::to_string(&key_wrap_results).unwrap().as_bytes().to_vec(),
        };
 
        Ok(Response::new(reply))
    }

    async fn un_wrap_key(
        &self,
        request: Request<KeyProviderKeyWrapProtocolInput>,
    ) -> Result<Response<KeyProviderKeyWrapProtocolOutput>, Status> {
        let annotation = 
            String::from_utf8(request.into_inner().key_provider_key_wrap_protocol_input)
            .and_then(|request|{
                Ok(serde_json::from_str::<KeyProviderInput>(&request[..]))
            })
            .unwrap()
            .and_then(|unwrap_command|{
                Ok(unwrap_command.keyunwrapparams.annotation)
            })
            .unwrap();

        let annotation = match annotation {
            Some(annotation) => annotation,
            None => {
                let reply = KeyProviderKeyWrapProtocolOutput {
                    key_provider_key_wrap_protocol_output: b"Parser failure".to_vec(),
                };
                return Ok(Response::new(reply));
            }
        };

        let decrypted_data =
            serde_json::from_str::<annotation::AnnotationPacket>(&annotation[..])
            .and_then(|annotation|{
                let decrypted_data = 
                directory_key_manager::get_key(&annotation.kid)
                .and_then(|key|{
                    let decrypted_data = 
                        aes256_cbc::decrypt(&annotation.wrapped_data[..], key.as_slice(), &annotation.iv[..])
                        .unwrap_or_else(|_| {vec![0]});
                    Ok(decrypted_data)
                });
                Ok(decrypted_data)
            })
            .unwrap()
            .unwrap();

        let key_unwrap_results= KeyUnwrapResults {
            optsdata: decrypted_data,
        };

        let reply = KeyProviderKeyWrapProtocolOutput {
            key_provider_key_wrap_protocol_output: serde_json::to_string(&key_unwrap_results).unwrap().as_bytes().to_vec(),
        };
 
        Ok(Response::new(reply))
    }     
}

pub async fn key_provider_server(addr:&str) -> Result<(), Box<dyn std::error::Error>> {
    let addr = addr.parse()?;
    let service = keyProviderSrv::default();
 
    Server::builder()
        .add_service(KeyProviderServiceServer::new(service))
        .serve(addr)
        .await?;
 
    Ok(())   
}