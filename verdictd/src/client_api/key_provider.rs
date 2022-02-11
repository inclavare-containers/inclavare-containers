use rand::*;
use tonic::{Request, Response, Status};
use uuid::Uuid;
use base64;
use crate::crypto::aes256_gcm;
use crate::resources::directory_key_manager;
use crate::client_api::annotation;
use crate::client_api::messages::*;

use keyProvider::key_provider_service_server::KeyProviderService;
use keyProvider::{KeyProviderKeyWrapProtocolInput, KeyProviderKeyWrapProtocolOutput};

pub mod keyProvider {
    tonic::include_proto!("keyprovider");
}

#[derive(Debug, Default)]
pub struct keyProviderService {}

const IV_LEN : usize = 12;
const KEY_LEN : usize = 32;

#[tonic::async_trait]
impl KeyProviderService for keyProviderService {
    async fn wrap_key(
        &self,
        request: Request<KeyProviderKeyWrapProtocolInput>,
    ) -> Result<Response<KeyProviderKeyWrapProtocolOutput>, Status> {
        let wrap_command =
            String::from_utf8(request.into_inner().key_provider_key_wrap_protocol_input)
                .and_then(|request| Ok(serde_json::from_str::<KeyProviderInput>(&request[..])))
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

        info!("wrap_command: {:?}", wrap_command);

        let mut kid = Uuid::new_v4().to_string();
        let ec = wrap_command.keywrapparams.ec.unwrap();
        let optsdata = wrap_command.keywrapparams.optsdata.unwrap();
        if !ec.Parameters.is_empty() {
            for key in ec.Parameters.keys() {
                kid = String::from_utf8(base64::decode(ec.Parameters[key][0].to_string()).unwrap()).unwrap();
                break;
            }
        } else {
            // generate a new key file with a new random key
            let mut key = [0; KEY_LEN];
            rand::rngs::OsRng.fill_bytes(&mut key);
            directory_key_manager::set_key(&kid, &key)?;
        }
        let mut iv = [0; IV_LEN];
        rand::rngs::OsRng.fill_bytes(&mut iv);

        let encrypted_data = directory_key_manager::get_key(&kid)
            .and_then(|key| {
                info!("key: {:?}", key);
                let encrypted_data = aes256_gcm::encrypt(&base64::decode(optsdata).unwrap(), key.as_slice(), &iv)
                    .unwrap_or_else(|e| {
                        error!("encrypt data failed with error:{:?}", e);
                        vec![0]
                    });
                Ok(encrypted_data)
            })
            .unwrap_or_else(|_| {
                error!("get encryption key faied");
                vec![0]
            });

        let annotation = annotation::AnnotationPacket {
            kid: kid.to_string(),
            wrapped_data: encrypted_data,
            iv: iv.to_vec(),
            algorithm: String::from("AES"),
            key_length: 256,
        };

        let key_wrap_output = KeyWrapOutput {
            keywrapresults: KeyWrapResults {
                annotation: serde_json::to_string(&annotation)
                    .unwrap()
                    .as_bytes()
                    .to_vec(),
            },
        };
        let reply = KeyProviderKeyWrapProtocolOutput {
            key_provider_key_wrap_protocol_output: serde_json::to_string(&key_wrap_output)
                .unwrap()
                .as_bytes()
                .to_vec(),
        };

        Ok(Response::new(reply))
    }

    async fn un_wrap_key(
        &self,
        request: Request<KeyProviderKeyWrapProtocolInput>,
    ) -> Result<Response<KeyProviderKeyWrapProtocolOutput>, Status> {
        let annotation =
            String::from_utf8(request.into_inner().key_provider_key_wrap_protocol_input)
                .and_then(|request| Ok(serde_json::from_str::<KeyProviderInput>(&request[..])))
                .unwrap()
                .and_then(|unwrap_command| Ok(unwrap_command.keyunwrapparams.annotation))
                .unwrap()
                .ok_or("annotation is empty".to_string())
                .and_then(|annotation| {
                    base64::decode(annotation)
                        .map_err(|_| "base64 decode annotation failed".to_string())
                })
                .and_then(|annotation| {
                    String::from_utf8(annotation)
                        .map_err(|_| "utf8 error".to_string())
                });
        
        let annotation = match annotation {
            Ok(annotation) => annotation,
            Err(e) => {
                let reply = KeyProviderKeyWrapProtocolOutput {
                    key_provider_key_wrap_protocol_output: e
                        .as_bytes()
                        .to_vec(),
                };
                return Ok(Response::new(reply));
            }
        };

        info!("unwrap's annotation: {:?}", &annotation);

        let decrypted_data = serde_json::from_str::<annotation::AnnotationPacket>(&annotation[..])
            .and_then(|annotation| {
                let decrypted_data =
                    directory_key_manager::get_key(&annotation.kid).and_then(|key| {
                        let a = aes256_gcm::decrypt(
                            &annotation.wrapped_data[..],
                            key.as_slice(),
                            &annotation.iv[..],
                        )
                        .unwrap_or_else(|e| {
                            error!("decrypt data failed with error:{:?}", e);
                            vec![0]
                        });
                        Ok(a)
                    })
                    .unwrap();
                Ok(decrypted_data)
            })
            .unwrap();

        let key_unwrap_output = KeyUnwrapOutput {
            keyunwrapresults: KeyUnwrapResults {
                optsdata: decrypted_data,
            },
        };        

        let reply = KeyProviderKeyWrapProtocolOutput {
            key_provider_key_wrap_protocol_output: serde_json::to_string(&key_unwrap_output)
                .unwrap()
                .as_bytes()
                .to_vec(),
        };

        Ok(Response::new(reply))
    }
}
