use clap::Parser;
use std::fs;
use libsodium_sys::crypto_sign_detached;
use serde_json::Value;
use actix_web::{get, web, App, HttpResponse, HttpServer, Responder};
use serde::Serialize;

#[derive(thiserror::Error, Debug)]
pub enum SignerError {
    #[error("failed to read: {0}")]
    FileReadFailed(String),
    #[error("failed to parse")]
    ParseFailed(#[from] serde_json::Error),
    #[error("invalid ACME: {0}")]
    ACMEError(String),
    #[error("failed to sign")]
    SignFailed,
    #[error("failed to initialize {0}")]
    InitFailed(String),
}

#[derive(Serialize)]
struct AppState {
    private_key: Vec<u8>,
    ca_info_path: String,
}

#[derive(Serialize)]
struct BinderResponse {
    sig: String,
    acme_id: String,
}

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Path to the enclave private key
    #[arg(short = 's', long, default_value = "/app/id.sec")]
    priv_key: String,

    /// ACME which issues the certificate
    #[arg(short, long, default_value = "acme-v02.api.letsencrypt.org-directory")]
    acme: String,

    /// Port to listen on
    #[arg(short, long, default_value = "1500")]
    port: u16,
}

fn get_ca_id(ca_info_path: &str) -> Result<String, SignerError> {
    let ca_info = match fs::read_to_string(ca_info_path) {
        Ok(ca_info) => ca_info,
        Err(_) => return Err(SignerError::FileReadFailed(ca_info_path.to_string())),
    };
    let ca_info: Value = match serde_json::from_str(&ca_info) {
        Ok(ca_info) => ca_info,
        Err(e) => return Err(SignerError::ParseFailed(e)),
    };
    let status = ca_info["status"].as_str().unwrap().to_string();
    let ca_id = ca_info["location"].as_str().unwrap().to_string();
    if status != "valid" {
        return Err(SignerError::ACMEError(ca_id));
    }
    Ok(ca_id)
}

fn get_sig(ca_id: String, private_key: Vec<u8>) -> Result<String, SignerError> {
    let mut sig = [0u8; 64];
    const SIG_PREFIX: &str = "signed-acme-id-for-secure-cert-generation-";
    let msg_to_sign = format!("{}{}", SIG_PREFIX.to_string(), ca_id);

    unsafe{
        let is_signed = crypto_sign_detached(
            sig.as_mut_ptr(), 
            std::ptr::null_mut(), 
            msg_to_sign.as_ptr(),
            msg_to_sign.len()  as u64,
            private_key.as_ptr()
        );
        if is_signed != 0 {
            return Err(SignerError::SignFailed);
        }
    }

    Ok(sig.iter().map(|x| format!("{:02x}", x)).collect::<String>())
}

#[get("/")]
async fn account(params: web::Data<AppState>) -> impl Responder {
    let acme_id = get_ca_id(&params.ca_info_path).unwrap();
    let sig = get_sig(acme_id.to_string(), params.private_key.clone()).unwrap();
    let data = BinderResponse {
        acme_id: acme_id,
        sig: sig,
    };
    // response is a json with the signature and the ca_id
    HttpResponse::Ok()
        .content_type("application/json")
        .json(data)
}

#[get("/{acme}")]
async fn account_by_acme(path: web::Path<String>, params: web::Data<AppState>) -> impl Responder {
    let acme = path.into_inner();
    let ca_info_path = format!("/var/lib/caddy/acme/{}/users/default/default.json", acme);
    let acme_id = get_ca_id(&ca_info_path).unwrap();
    let sig = get_sig(acme_id.to_string(), params.private_key.clone()).unwrap();
    let data = BinderResponse {
        acme_id: acme_id,
        sig: sig,
    };
    // response is a json with the signature and the ca_id
    HttpResponse::Ok()
        .content_type("application/json")
        .json(data)
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // initialize libsodium
    let res = unsafe { libsodium_sys::sodium_init() };
    if res != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            SignerError::InitFailed("libsodium".to_string()),
        ));
    }

    let cli = Cli::parse();

    let enclave_priv_key_path = cli.priv_key;
    let acme = cli.acme;
    let port: u16 = cli.port;

    let ca_info_path = format!("/var/lib/caddy/acme/{}/users/default/default.json", acme);

    let private_key = fs::read(enclave_priv_key_path)?;

    println!("starting HTTP server at http://127.0.0.1:{}", port);

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(AppState {
                private_key: private_key.clone(),
                ca_info_path: ca_info_path.clone(),
            }))
            .service(account)
            .service(account_by_acme)
    })
    .bind(("127.0.0.1", port))?
    .run()
    .await
}
