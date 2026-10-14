//! Shared alloy JSON-RPC client.
//!
//! A bare Alchemy endpoint (`https://<network>.g.alchemy.com/v2`) is
//! called with `Authorization: Bearer <JWT>`, the JWT signed by a Cloud KMS
//! P-256 key whose public half is registered with the Alchemy app. Any
//! other URL is called without one. Either way, errors never carry the
//! URL and redirects are not followed.
//!
//! ```no_run
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! let client = st0x_rpc::connect("https://base-mainnet.g.alchemy.com/v2").await?;
//! // alloy::providers::ProviderBuilder::new().connect_client(client)
//! # Ok(()) }
//! ```

mod config;
mod error;
mod jwt;
mod kms;
#[cfg(test)]
mod test_support;
mod transport;

use std::sync::Arc;
use std::time::Duration;

use alloy_rpc_client::{ClientBuilder, RpcClient};
use alloy_transport::utils::guess_local_url;
use reqwest::Url;
use tracing::{info, warn};

pub use config::{AlchemyJwtConfig, JwtEnv, KEY_VERSION_VAR, KID_VAR};
pub use error::Error;

use jwt::JwtMinter;
use kms::{AccessTokenSource, KmsSigner};
use transport::St0xHttp;

/// Budget for building the KMS signer and the first `eth_chainId` call.
const STARTUP_TIMEOUT: Duration = Duration::from_secs(10);

/// Builds a client for `url`, reading the JWT settings from
/// [`KEY_VERSION_VAR`] and [`KID_VAR`]. Pass the result to alloy's
/// `ProviderBuilder::connect_client`.
pub async fn connect(url: &str) -> Result<RpcClient, Error> {
    connect_with(url, JwtEnv::from_env()).await
}

/// Builds a client for `url` with the given JWT settings.
///
/// A bare Alchemy `/v2` URL requires both settings, and the client is
/// returned only after an `eth_chainId` call authenticated with a fresh JWT
/// succeeds, so a key Alchemy does not accept stops startup. Any other URL
/// gets a client without a bearer token and no startup call.
pub async fn connect_with(url: &str, jwt: JwtEnv) -> Result<RpcClient, Error> {
    connect_inner(url, jwt, Deps::production()).await
}

/// Whether `connect` calls `url` with a KMS-signed JWT: a bare
/// `https://<network>.g.alchemy.com/v2` URL.
pub fn uses_alchemy_jwt(url: &str) -> bool {
    url.parse()
        .is_ok_and(|url| config::is_alchemy_jwt_url(&url))
}

struct Deps {
    kms_base_url: String,
    token_source: AccessTokenSource,
    is_jwt_url: fn(&Url) -> bool,
    startup_timeout: Duration,
}

impl Deps {
    fn production() -> Self {
        Self {
            kms_base_url: kms::KMS_BASE_URL.to_string(),
            token_source: AccessTokenSource::Ambient,
            is_jwt_url: config::is_alchemy_jwt_url,
            startup_timeout: STARTUP_TIMEOUT,
        }
    }
}

async fn connect_inner(url: &str, jwt: JwtEnv, deps: Deps) -> Result<RpcClient, Error> {
    let url: Url = url.parse().map_err(|_| Error::InvalidUrl)?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(Error::UnsupportedScheme);
    }
    let is_local = guess_local_url(url.as_str());

    if !(deps.is_jwt_url)(&url) {
        if config::is_malformed_alchemy_jwt_url(&url) {
            return Err(Error::MalformedAlchemyUrl);
        }
        match jwt {
            JwtEnv::Both(_) => {
                warn!(
                    "Alchemy JWT settings are set, but the RPC URL is not a bare Alchemy /v2 URL"
                );
            }
            JwtEnv::Partial { missing } => {
                warn!(missing, "Alchemy JWT settings are incomplete and unused");
            }
            JwtEnv::Unset => {}
        }
        info!("RPC: plain HTTP");
        return Ok(ClientBuilder::default().transport(St0xHttp::new(url, None)?, is_local));
    }

    let JwtEnv::Both(AlchemyJwtConfig { key_version, kid }) = jwt else {
        return Err(Error::MissingJwtConfig {
            missing: jwt.missing().unwrap_or_default(),
        });
    };
    let startup = async {
        let signer =
            KmsSigner::new(key_version.clone(), deps.kms_base_url, deps.token_source).await?;
        let minter = Arc::new(JwtMinter::new(signer, kid.clone()));
        let client =
            ClientBuilder::default().transport(St0xHttp::new(url, Some(minter))?, is_local);
        let chain_id: String = client
            .request_noparams("eth_chainId")
            .await
            .map_err(Error::Rpc)?;
        Ok::<_, Error>((client, chain_id))
    };
    let (client, chain_id) = tokio::time::timeout(deps.startup_timeout, startup)
        .await
        .map_err(|_| Error::StartupTimeout)??;
    info!(%kid, %key_version, %chain_id, "Alchemy RPC: KMS-signed JWT");
    Ok(client)
}

#[cfg(test)]
mod tests {
    use httpmock::MockServer;

    use super::*;
    use crate::test_support::{
        mock_public_key, mock_rpc, mock_sign, mock_token, token_source, CHAIN_ID, KEY_VERSION,
    };

    /// Points KMS and the token endpoint at `server`, and treats its `/v2`
    /// path as the bare Alchemy URL.
    fn test_deps(server: &MockServer) -> Deps {
        Deps {
            kms_base_url: server.base_url(),
            token_source: token_source(server),
            is_jwt_url: |url| url.path() == "/v2",
            startup_timeout: STARTUP_TIMEOUT,
        }
    }

    fn both() -> JwtEnv {
        JwtEnv::Both(AlchemyJwtConfig {
            key_version: KEY_VERSION.to_string(),
            kid: "kid".to_string(),
        })
    }

    fn partial() -> JwtEnv {
        JwtEnv::Partial { missing: KID_VAR }
    }

    fn mock_kms(server: &MockServer) {
        mock_token(server);
        mock_public_key(server, "EC_SIGN_P256_SHA256");
        mock_sign(server);
    }

    #[tokio::test]
    async fn jwt_url_with_both_settings_sends_bearer() {
        let server = MockServer::start_async().await;
        mock_kms(&server);
        let (_rpc, seen) = mock_rpc(&server, "/v2");

        let client = connect_inner(&server.url("/v2"), both(), test_deps(&server))
            .await
            .unwrap();
        let chain_id: String = client.request_noparams("eth_chainId").await.unwrap();
        assert_eq!(chain_id, CHAIN_ID);

        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 2, "startup check plus one call");
        assert!(seen
            .iter()
            .all(|headers| headers.len() == 1 && headers[0].starts_with("Bearer ey")));
    }

    #[tokio::test]
    async fn jwt_url_without_both_settings_refuses() {
        let server = MockServer::start_async().await;
        for (jwt, expected) in [
            (partial(), KID_VAR),
            (
                JwtEnv::Unset,
                "ALCHEMY_JWT_KMS_KEY_VERSION or ALCHEMY_JWT_KID",
            ),
        ] {
            let err = connect_inner(&server.url("/v2"), jwt, test_deps(&server))
                .await
                .unwrap_err();
            assert!(
                matches!(err, Error::MissingJwtConfig { missing } if missing == expected),
                "{err:?}"
            );
        }
    }

    #[tokio::test]
    async fn other_urls_use_plain_http() {
        let server = MockServer::start_async().await;
        for path in ["/v2/secret-api-key", "/rpc"] {
            for jwt in [both(), partial(), JwtEnv::Unset] {
                let (mut rpc, seen) = mock_rpc(&server, path);
                let client = connect_inner(&server.url(path), jwt, test_deps(&server))
                    .await
                    .unwrap();
                rpc.assert_calls(0);
                let _: String = client.request_noparams("eth_chainId").await.unwrap();
                assert_eq!(*seen.lock().unwrap(), vec![Vec::<String>::new()]);
                rpc.delete();
            }
        }
    }

    #[tokio::test]
    async fn invalid_url_error_omits_input() {
        let err = connect_with("not a url secret-api-key", JwtEnv::Unset)
            .await
            .unwrap_err();
        assert!(matches!(err, Error::InvalidUrl));
        assert!(!format!("{err} {err:?}").contains("secret-api-key"));
    }

    #[tokio::test]
    async fn non_http_scheme_is_refused() {
        for url in [
            "wss://base-mainnet.g.alchemy.com/v2",
            "ws://127.0.0.1:8545",
            "file:///v2",
        ] {
            let err = connect_with(url, both()).await.unwrap_err();
            assert!(matches!(err, Error::UnsupportedScheme), "{url}: {err:?}");
        }
    }

    #[tokio::test]
    async fn malformed_alchemy_url_is_refused() {
        for url in [
            "http://base-mainnet.g.alchemy.com/v2",
            "https://base-mainnet.g.alchemy.com./v2",
        ] {
            let err = connect_with(url, both()).await.unwrap_err();
            assert!(matches!(err, Error::MalformedAlchemyUrl), "{url}: {err:?}");
            assert!(!format!("{err} {err:?}").contains("base-mainnet"));
        }
    }

    #[tokio::test]
    async fn rejected_startup_call_fails_connect() {
        let server = MockServer::start_async().await;
        mock_kms(&server);
        server.mock(|when, then| {
            when.method("POST").path("/v2");
            then.status(401).body("unauthorized");
        });

        let err = connect_inner(&server.url("/v2"), both(), test_deps(&server))
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Rpc(_)), "{err:?}");
    }

    #[tokio::test]
    async fn hanging_kms_hits_startup_timeout() {
        let server = MockServer::start_async().await;
        mock_token(&server);
        server.mock(|when, then| {
            when.method("GET").path(format!("/{KEY_VERSION}/publicKey"));
            then.status(200).delay(Duration::from_secs(5));
        });

        let deps = Deps {
            startup_timeout: Duration::from_millis(200),
            ..test_deps(&server)
        };
        let err = connect_inner(&server.url("/v2"), both(), deps)
            .await
            .unwrap_err();
        assert!(matches!(err, Error::StartupTimeout), "{err:?}");
    }
}
