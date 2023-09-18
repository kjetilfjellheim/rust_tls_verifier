//! Simple application backend using tauri used for checking TLS
//! connections.
//!
//! Currently only openssl is used through the native tls layer.
//! Rustls will be added latter.
//!
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

const APLICATION_STARTUP_ERROR: &str = "Error running application";

///
/// Application state. Will eventually be used to store logs so that they are
/// available to the frontend.
///   
struct ApplicationState {
    logdata: Mutex<String>,
}

///
/// Input from the frontend.
///
/// url: The url to connect to.
/// proxy_url: The proxy to use. If None then no proxy is used.
/// keystore_path: The path to the keystore containing the client certificate.
/// keystore_password: The password for the keystore.
/// public_certificate_path: The path to the public certificate of the server.
/// check_hostname: If true then the hostname of the server is checked against the certificate.
/// use_inbuilt_root_certs: If true then the inbuilt root certificates are used.
/// use_https_only: If true then only https is used.
/// use_tls_sni: If true then tls sni is used.
///  
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

///
/// Output to the frontend.
///
/// success: If true then the request was successful.
/// logdata: The logdata from the request.
///
#[derive(Serialize, Deserialize)]
#[serde(rename_all(deserialize = "snake_case", serialize = "camelCase"))]
struct Output {
    success: bool,
    logdata: String,
}

///
/// Application error.
///
/// error: The error message.
/// logdata: The logdata from the request.
///
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ApplicationError {
    error: String,
    logdata: Option<String>,
}

///
/// Implementation of the application error.
///
/// error: The error message.
/// logdata: The logdata from the request.
///
/// This is used to return errors to the frontend.
///
impl ApplicationError {
    pub fn new(error: String, logdata: Option<String>) -> ApplicationError {
        ApplicationError { error, logdata }
    }
}

///
/// Read a file into a buffer.
///
/// filename: The name of the file to read.
///
/// Returns a buffer containing the contents of the file.
///
fn read_file(filename: &str) -> Result<Vec<u8>, ApplicationError> {
    let file = File::open(filename);
    let mut file: File = match file {
        Ok(file) => file,
        Err(error) => return Err(ApplicationError::new(error.to_string(), None)),
    };
    let mut buf = Vec::new();
    let read = file.read_to_end(&mut buf);
    match read {
        Ok(_size) => Ok(buf),
        Err(error) => Err(ApplicationError::new(error.to_string(), None)),
    }
}

///
/// Get the certificate from the public certificate file.
///
/// certificate_path: The path to the public certificate file.
///
/// Returns the certificate.
///
fn get_certificate(certificate_path: &str) -> Result<Certificate, ApplicationError> {
    let buffer = read_file(certificate_path)?;
    let certificate = reqwest::Certificate::from_pem(&buffer);
    match certificate {
        Ok(certificate) => Ok(certificate),
        Err(error) => Err(ApplicationError::new(error.to_string(), None)),
    }
}

///
/// Get the client builder.
///
/// Returns the client builder.
///
fn get_clientbuilder() -> ClientBuilder {
    reqwest::blocking::Client::builder().use_native_tls()
}

///
/// Get the proxy.
///
/// proxy_url: The proxy to use.
///
/// Returns the proxy.
///
fn get_proxy(proxy_url: &str) -> Result<Proxy, ApplicationError> {
    let proxy = Proxy::all(proxy_url);
    match proxy {
        Ok(proxy) => Ok(proxy),
        Err(error) => Err(ApplicationError::new(error.to_string(), None)),
    }
}

///
/// Get the client.
///
/// public_certificate_path: The path to the public certificate file.
/// keystore_path: The path to the keystore containing the client certificate.
/// keystore_password: The password for the keystore.
/// proxy_url: The proxy to use. If None then no proxy is used.
/// check_hostname: If true then the hostname of the server is checked against the certificate.
/// use_inbuilt_root_certs: If true then the inbuilt root certificates are used.
/// use_https_only: If true then only https is used.
/// use_tls_sni: If true then tls sni is used.
///
/// TODO: Fix too many arguments.
///
/// Returns the client.
///
fn get_client(
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
            let proxy = get_proxy(proxy_url)?;
            clientbuilder.proxy(proxy)
        }
        None => clientbuilder,
    };

    let client = clientbuilder.build();
    match client {
        Ok(client) => Ok(client),
        Err(error) => Err(ApplicationError::new(error.to_string(), None)),
    }
}

///
/// Get the identity from the keystore.
///
/// keystore_path: The path to the keystore containing the client certificate.
/// keystore_password: The password for the keystore.
///
/// Returns the identity.
///
fn get_identity<'a>(
    keystore_path: &'a str,
    keystore_password: &'a str,
) -> Result<Identity, ApplicationError> {
    let buffer = read_file(keystore_path)?;
    let identity = reqwest::Identity::from_pkcs12_der(&buffer, keystore_password);
    match identity {
        Ok(identity) => Ok(identity),
        Err(error) => Err(ApplicationError::new(error.to_string(), None)),
    }
}

///
/// Get the logdata.
///
/// logdata: The logdata.
///
/// Returns the logdata.
///
fn get_logdata(logdata: &Mutex<String>) -> Result<String, ApplicationError> {
    let logdata = logdata.lock();
    match logdata {
        Ok(logdata) => Ok(logdata.clone()),
        Err(error) => Err(ApplicationError::new(error.to_string(), None)),
    }
}

///
/// Frontend request handler.
///
/// input: The input from the frontend.
/// application_state: The application state.
///
/// Returns the output to the frontend.
///
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
            logdata: get_logdata(&application_state.logdata)?,
        }),
        Err(error) => {
            let error = error.to_string();
            Err(ApplicationError::new(
                error,
                Some(get_logdata(&application_state.logdata)?),
            ))
        }
    }
}

///
/// Main function.
///
/// Starts the application.
///
fn main() {
    let application_state = Arc::new(ApplicationState {
        logdata: Mutex::new(String::from("")),
    });

    tauri::Builder::default()
        .manage(application_state)
        .invoke_handler(tauri::generate_handler![do_request])
        .run(tauri::generate_context!())
        .expect(APLICATION_STARTUP_ERROR);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_client_success_noproxy() {
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
