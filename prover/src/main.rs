use clap::Parser;
use oyster::{get_attestation_doc, verify};
use serde::{Deserialize, Serialize};
use std::error::Error;
use libsodium_sys::crypto_sign_verify_detached;
use std::net::Ipv4Addr;

#[derive(Serialize, Deserialize, Debug)]
struct AcmeAccountResponse {
    sig: String,
    acme_id: String,
}

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// IP address of the enclave
    #[clap(short = 't', long)]
    enclave_ip: Ipv4Addr,

    /// attestation server port used on enclave
    #[clap(short = 'b', long, default_value = "1300")]
    attestation_port: u16,

    /// CAA Binder port used on enclave
    #[clap(short = 'd', long, default_value = "1500")]
    caa_binder_port: u16,

    /// ACME directory
    #[clap(long, default_value="acme-v02.api.letsencrypt.org-directory")]
    ca: String,

    /// email specified in Caddyfile
    #[clap(short, long, default_value = "default")]
    email: String,

    /// expected pcr0
    #[arg(short = '0', long)]
    pcr0: String,

    /// expected pcr1
    #[arg(short = '1', long)]
    pcr1: String,

    /// expected pcr2
    #[arg(short = '2', long)]
    pcr2: String,

    /// minimum cpus
    #[arg(short = 'c', long)]
    min_cpus: usize,

    /// minimum memory in MB
    #[arg(short = 'm', long)]
    min_mem: usize,

    /// maximum age of attestation (in milliseconds)
    #[arg(short = 'a', long, default_value = "300000")]
    max_age: usize,
}

async fn verify_sig(message: String, sig: Vec<u8>, pub_key: [u8; 32]) -> Result<(), Box<dyn Error>> {
    const SIG_PREFIX: &str = "signed-acme-id-for-secure-cert-generation-";
    let msg_to_verify = format!("{}{}", SIG_PREFIX.to_string(), message);
    unsafe {
        let result = crypto_sign_verify_detached(
            sig.as_ptr(), 
            msg_to_verify.as_ptr(), 
            msg_to_verify.len().try_into().unwrap(), 
            pub_key.as_ptr()
        );
    
        if result == 0 {
            return Ok(());
        } else {
            println!("Signature is invalid");
            panic!("Signature is invalid");
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // initialize libsodium
    let res = unsafe { libsodium_sys::sodium_init() };
    if res != 0 {
        panic!("Unable to initialize libsodium");
    }

    let cli = Cli::parse();

    let pcrs = vec![cli.pcr0, cli.pcr1, cli.pcr2];
    let attestation_endpoint = format!("http://{}:{}", cli.enclave_ip, cli.attestation_port);
    let attestation_doc = get_attestation_doc(attestation_endpoint.parse()?).await?;

    let pub_key = verify(
        attestation_doc,
        pcrs,
        cli.min_cpus,
        cli.min_mem,
        cli.max_age,
    )?;

    println!("Public key verified from enclave attestation");
    
    let mut caa_binder_endpoint = format!("http://{}:{}", cli.enclave_ip, cli.caa_binder_port);

    if cli.ca != "acme-v02.api.letsencrypt.org-directory" {
        caa_binder_endpoint.push_str(&format!("/{}", cli.ca));
    }
    if cli.email != "default" {
        caa_binder_endpoint.push_str(&format!("/{}/{}", cli.email, cli.email.split("@").collect::<Vec<&str>>()[0]));
    }

    let response = reqwest::get(caa_binder_endpoint).await?;
    let ca_data: AcmeAccountResponse = response.json().await?;

    const SIG_PREFIX: &str = "signed-acme-id-for-secure-cert-generation-";
    let msg_to_verify = format!("{}{}", SIG_PREFIX.to_string(), ca_data.acme_id);

    let sig = hex::decode(ca_data.sig.clone()).unwrap();
    
    verify_sig(msg_to_verify, sig, pub_key).await?;

    println!("Signature on ACME accounturi verified");
    println!("Please set the following CAA record in your DNS");
    println!("IN CAA 0 issue \"letsencrypt.org; accounturi={}\"", ca_data.acme_id);

    Ok(())
}