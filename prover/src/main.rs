use clap::Parser;
use oyster::{get_attestation_doc, verify};
use serde::{Deserialize, Serialize};
use std::error::Error;
use libsodium_sys::crypto_sign_verify_detached;

#[derive(Serialize, Deserialize, Debug)]
struct AcmeAccountResponse {
    sig: String,
    acme_id: String,
}

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// endpoint of the attestation server (http://<ip:port>)
    #[clap(short = 't', long, value_parser)]
    attestation_endpoint: String,

    /// endpoint of the acme account server (http://<ip:port>)
    #[clap(short = 'd', long, value_parser)]
    acme_account_endpoint: String,

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

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // initialize libsodium
    let res = unsafe { libsodium_sys::sodium_init() };
    if res != 0 {
        panic!("Unable to initialize libsodium");
    }

    let cli = Cli::parse();

    let pcrs = vec![cli.pcr0, cli.pcr1, cli.pcr2];
    let attestation_doc = get_attestation_doc(cli.attestation_endpoint.parse()?).await?;

    let pub_key = verify(
        attestation_doc,
        pcrs,
        cli.min_cpus,
        cli.min_mem,
        cli.max_age,
    )?;
    
    println!("Public key verified from enclave attestation");
    
    let response = reqwest::get(cli.acme_account_endpoint).await?;
    let ca_data: AcmeAccountResponse = response.json().await?;

    const SIG_PREFIX: &str = "signed-acme-id-for-secure-cert-generation-";
    let msg_to_verify = format!("{}{}", SIG_PREFIX.to_string(), ca_data.acme_id);

    let sig = hex::decode(ca_data.sig.clone()).unwrap();
    
     unsafe {
        let result = crypto_sign_verify_detached(
            sig.as_ptr(), 
            msg_to_verify.as_ptr(), 
            msg_to_verify.len().try_into().unwrap(), 
            pub_key.as_ptr()
        );

        if result == 0 {
            println!("Signature from enclave verified, ACME account to use in CAA record is {}", ca_data.acme_id);
            return Ok(());
        } else {
            println!("Signature is invalid");
            panic!("Signature is invalid");
        }
    }
}