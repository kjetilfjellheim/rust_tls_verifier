#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::io::Read;
use std::env;
use std::fs::File;
use reqwest::{Identity, Proxy, blocking::ClientBuilder, Certificate};
use serde::{Deserialize, Serialize};
use tracing::Level;
use tracing_subscriber::FmtSubscriber;
use reqwest::blocking::Client;

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Log<'a> {
    logdata: &'a str
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all(deserialize = "snake_case", serialize = "camelCase"))]
struct Input<'a> {
    url: &'a str,
    proxy_url: Option<&'a str>,
    keystore_path: &'a str,
    keystore_password: &'a str,
    public_certificate_path: &'a str,
    check_hostname: bool,
    use_inbuilt_root_certs: bool,
    https_only: bool,
    use_tls_sni: bool
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ApplicationError {
    message: String,
}

impl ApplicationError {
    pub fn new(message: String) -> ApplicationError {
        ApplicationError {       
            message: message
        }
    }
}

fn read_file<'a,'b>(filename: &'a str) -> Result<Vec<u8>, ApplicationError> {
    let file = File::open(filename);
    let mut file: File = match file {
        Ok(file) => { file },
        Err(error) => {
            return Err(ApplicationError::new(String::from(error.to_string())))
        }
    };
    let mut buf = Vec::new();
    let read = file.read_to_end(&mut buf);
    match read {
        Ok(_size) => { Ok(buf) },
        Err(error) => {
            Err(ApplicationError::new(String::from(error.to_string())))
        }
    }
}

fn get_certificate<'a, 'b >(certificate_path: &'a str) -> Result<Certificate, ApplicationError> {
    let buffer = read_file(certificate_path)?;
    let certificate = reqwest::Certificate::from_pem(&buffer);
    match certificate {
        Ok(certificate) => { return Ok(certificate)  },
        Err(error) => { 
            Err(ApplicationError::new(String::from(error.to_string()))) 
        }
    }
}

fn get_clientbuilder() -> ClientBuilder {
    #[cfg(feature = "native-tls")]
    let client = reqwest::blocking::Client::builder().use_native_tls();
    #[cfg(feature = "rustls-tls")]
    let client = reqwest::blocking::Client::builder().use_rustls_tls();
    client
}

fn get_client<'a>(public_certificate_path: &str, keystore_path: &str, keystore_password: &str, proxy_url: Option<&str>, check_hostname: bool, use_inbuilt_root_certs: bool, use_tls_sni: bool, use_https_only: bool) -> Result<Client, ApplicationError> {
    let certificate = get_certificate(public_certificate_path)?;

    let identity = get_identity(keystore_path, keystore_password)?;

    let clientbuilder: ClientBuilder = get_clientbuilder()
        .tls_built_in_root_certs(use_inbuilt_root_certs)
        .add_root_certificate(certificate)
        .identity(identity)
        .https_only(use_https_only)     
        .connection_verbose(true)
        .tls_sni(use_tls_sni)
        .http1_only()
        .danger_accept_invalid_hostnames(!check_hostname);

    let clientbuilder: ClientBuilder = match proxy_url  {
        Some(proxy_url) => {
            let proxy = Proxy::all(proxy_url).expect("Failure setting proxy url");
            clientbuilder.proxy(proxy)
        },
        None => { clientbuilder },
    };

    let client = clientbuilder.build();
    match client {
        Ok(client) => { Ok(client) },
        Err(error) => { 
            Err(ApplicationError::new(String::from(error.to_string())))
        }
    }

}

#[cfg(feature = "native-tls")]
fn get_identity<'a,'b >(keystore_path: &'a str, keystore_password: &'a str) -> Result<Identity, ApplicationError> {
    let buffer = read_file(keystore_path)?;
    let identity = reqwest::Identity::from_pkcs12_der(&buffer, keystore_password);
    match identity {
        Ok(identity) => { return Ok(identity)  },
        Err(error) => { 
            Err(ApplicationError::new(String::from(error.to_string()))) 
        }
    }
}

#[cfg(feature = "rustls-tls")]
fn get_identity(keystore: &str, keystore_password: &str) -> Identity {
    let mut buf = Vec::new();
    File::open(keystore)
        .expect("Failure opening keystore file")
        .read_to_end(&mut buf)
        .expect("Failure reading keystore");
    reqwest::Identity::from_pem(&buf).expect("Failure parsing keystore")
}

#[tauri::command(rename_all(deserialize = "snake_case", serialize = "camelCase"))]
fn do_request<'a, 'b>(input : Input) -> Result<Log, ApplicationError> {
    let client = get_client(input.public_certificate_path, input.keystore_path, input.keystore_password, input.proxy_url, input.check_hostname, input.use_inbuilt_root_certs, input.https_only, input.use_tls_sni)?;
    let response = client.get(input.url).send();    
    match response {
        Ok(_) => { Ok(Log { logdata: "Success" }) },
        Err(error) => { 
            Err(ApplicationError::new(String::from(error.to_string())))
        }
    }
}

fn main() {
    let subscriber = FmtSubscriber::builder()
    .with_max_level(Level::TRACE)
    .finish();
    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");
    
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![do_request])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
