#![cfg_attr(not(debug_assertions), windows_subsystem = "linux")]

use reqwest::blocking::Client;
use reqwest::{blocking::ClientBuilder, Certificate, Identity, Proxy};
use serde::{Deserialize, Serialize};
use std::env;
use std::fs::File;
use std::io::Read;
use std::str;
use std::sync::Arc;
use std::sync::Mutex;
use tauri::State;

struct ApplicationState {
    logdata: Mutex<String>,
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
    use_https_only: bool,
    use_tls_sni: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all(deserialize = "snake_case", serialize = "camelCase"))]
struct Output {
    success: bool,
    logdata: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ApplicationError {
    error: String,
    logdata: Option<String>,
}

impl ApplicationError {
    pub fn new(error: String, logdata: Option<String>) -> ApplicationError {
        ApplicationError {
            error,
            logdata,
        }
    }
}
fn read_file<'a, 'b>(filename: &'a str) -> Result<Vec<u8>, ApplicationError> {
    let file = File::open(filename);
    let mut file: File = match file {
        Ok(file) => file,
        Err(error) => return Err(ApplicationError::new(String::from(error.to_string()), None)),
    };
    let mut buf = Vec::new();
    let read = file.read_to_end(&mut buf);
    match read {
        Ok(_size) => Ok(buf),
        Err(error) => Err(ApplicationError::new(String::from(error.to_string()), None)),
    }
}

fn get_certificate<'a, 'b>(certificate_path: &'a str) -> Result<Certificate, ApplicationError> {
    let buffer = read_file(certificate_path)?;
    let certificate = reqwest::Certificate::from_pem(&buffer);
    match certificate {
        Ok(certificate) => return Ok(certificate),
        Err(error) => Err(ApplicationError::new(String::from(error.to_string()), None)),
    }
}

fn get_clientbuilder() -> ClientBuilder {
    reqwest::blocking::Client::builder().use_native_tls()
}

fn get_client<'a>(
    public_certificate_path: &str,
    keystore_path: &str,
    keystore_password: &str,
    proxy_url: Option<&str>,
    check_hostname: bool,
    use_inbuilt_root_certs: bool,
    use_https_only: bool,
    use_tls_sni: bool,
) -> Result<Client, ApplicationError> {
    let certificate = get_certificate(public_certificate_path)?;

    let identity = get_identity(keystore_path, keystore_password)?;

    let clientbuilder: ClientBuilder = get_clientbuilder()
        .tls_built_in_root_certs(use_inbuilt_root_certs)
        .add_root_certificate(certificate)
        .identity(identity)
        .https_only(use_https_only)
        .connection_verbose(true)
        .tls_sni(use_tls_sni)
        .danger_accept_invalid_hostnames(!check_hostname);

    let clientbuilder: ClientBuilder = match proxy_url {
        Some(proxy_url) => {
            let proxy = Proxy::all(proxy_url).expect("Failure setting proxy url");
            clientbuilder.proxy(proxy)
        }
        None => clientbuilder,
    };

    let client = clientbuilder.build();
    match client {
        Ok(client) => Ok(client),
        Err(error) => Err(ApplicationError::new(String::from(error.to_string()), None)),
    }
}

fn get_identity<'a, 'b>(
    keystore_path: &'a str,
    keystore_password: &'a str,
) -> Result<Identity, ApplicationError> {
    let buffer = read_file(keystore_path)?;
    let identity = reqwest::Identity::from_pkcs12_der(&buffer, keystore_password);
    match identity {
        Ok(identity) => return Ok(identity),
        Err(error) => Err(ApplicationError::new(String::from(error.to_string()), None)),
    }
}

#[tauri::command]
fn do_request(
    input: Input,
    application_state: State<Arc<ApplicationState>>,
) -> Result<Output, ApplicationError> {
    let client = get_client(
        input.public_certificate_path,
        input.keystore_path,
        input.keystore_password,
        input.proxy_url,
        input.check_hostname,
        input.use_inbuilt_root_certs,
        input.use_https_only,
        input.use_tls_sni,
    )?;

    let response = client.get(input.url).send();
    match response {
        Ok(_) => Ok(Output {
            success: true,
            logdata: application_state.logdata.lock().unwrap().clone(),
        }),
        Err(error) => {
            let error = String::from(error.to_string());
            Err(ApplicationError::new(
                error,
                Some(application_state.logdata.lock().unwrap().clone()),
            ))
        }
    }
}

fn main() {
    let application_state = Arc::new(ApplicationState {
        logdata: Mutex::new(String::from("")),
    });

    tauri::Builder::default()
        .manage(application_state)
        .invoke_handler(tauri::generate_handler![do_request])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_client_success_noproxy() {
        let path = env::current_dir().unwrap();
        println!("The current directory is {}", path.display());

        let input = Input {
            url: "https://www.google.com",
            proxy_url: None,
            keystore_path: "test/resources/client.p12",
            keystore_password: "password",
            public_certificate_path: "test/resources/server.cer",
            check_hostname: false,
            use_inbuilt_root_certs: false,
            use_https_only: true,
            use_tls_sni: true,
        };
        let client = get_client(
            input.public_certificate_path,
            input.keystore_path,
            input.keystore_password,
            input.proxy_url,
            input.check_hostname,
            input.use_inbuilt_root_certs,
            input.use_https_only,
            input.use_tls_sni,
        );
        assert!(client.is_ok());
    }

    #[test]
    fn get_client_success_proxy() {
        let path = env::current_dir().unwrap();
        println!("The current directory is {}", path.display());

        let input = Input {
            url: "https://www.google.com",
            proxy_url: Some("localhost:8080"),
            keystore_path: "test/resources/client.p12",
            keystore_password: "password",
            public_certificate_path: "test/resources/server.cer",
            check_hostname: false,
            use_inbuilt_root_certs: false,
            use_https_only: true,
            use_tls_sni: true,
        };
        let client = get_client(
            input.public_certificate_path,
            input.keystore_path,
            input.keystore_password,
            input.proxy_url,
            input.check_hostname,
            input.use_inbuilt_root_certs,
            input.use_https_only,
            input.use_tls_sni,
        );
        assert!(client.is_ok());
    }
}
