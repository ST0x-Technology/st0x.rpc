//! Live check against a real Alchemy app and KMS key:
//!
//! ```sh
//! GOOGLE_OAUTH_ACCESS_TOKEN=$(gcloud auth print-access-token) \
//! ALCHEMY_JWT_KMS_KEY_VERSION=projects/…/cryptoKeyVersions/1 \
//! ALCHEMY_JWT_KID=… \
//! cargo run --example alchemy_chain_id -- https://<network>.g.alchemy.com/v2
//! ```

use st0x_rpc::JwtEnv;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let url = std::env::args()
        .nth(1)
        .ok_or("usage: alchemy_chain_id https://<network>.g.alchemy.com/v2")?;
    let jwt = JwtEnv::from_env();
    if !matches!(jwt, JwtEnv::Both(_)) {
        return Err("set ALCHEMY_JWT_KMS_KEY_VERSION and ALCHEMY_JWT_KID".into());
    }
    if !st0x_rpc::uses_alchemy_jwt(&url) {
        return Err("expected a bare https://<network>.g.alchemy.com/v2 URL".into());
    }
    let client = st0x_rpc::connect_with(&url, jwt).await?;
    let chain_id: String = client.request_noparams("eth_chainId").await?;
    println!("eth_chainId via KMS-signed JWT: {chain_id}");
    Ok(())
}
