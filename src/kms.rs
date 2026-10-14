//! ES256 signatures from a Cloud KMS `EC_SIGN_P256_SHA256` key, through
//! the KMS REST API with the instance's metadata-server access token.
//!
//! Every signature KMS returns is verified against the key's public half
//! before use, so a confused or substituted KMS response cannot produce a
//! token Alchemy would reject at every call.

use std::future::Future;
use std::time::Duration;

use base64::prelude::BASE64_STANDARD;
use base64::Engine as _;
use p256::ecdsa::signature::Verifier as _;
use p256::ecdsa::{Signature, VerifyingKey};
use p256::pkcs8::DecodePublicKey as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::Error;

pub(crate) const KMS_BASE_URL: &str = "https://cloudkms.googleapis.com/v1";
const METADATA_TOKEN_URL: &str =
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token";
const REQUIRED_ALGORITHM: &str = "EC_SIGN_P256_SHA256";

const KMS_TIMEOUT: Duration = Duration::from_secs(10);
const METADATA_TIMEOUT: Duration = Duration::from_secs(3);

/// Produces the raw ES256 signature over a JWS signing input.
pub(crate) trait JwsSigner: Send + Sync + 'static {
    fn sign(&self, message: &[u8]) -> impl Future<Output = Result<Signature, Error>> + Send;
}

#[derive(Debug, Clone)]
pub(crate) enum AccessTokenSource {
    /// `GOOGLE_OAUTH_ACCESS_TOKEN` when set and non-empty (local runs),
    /// otherwise the GCE metadata server.
    Ambient,
    #[cfg(test)]
    Endpoint(String),
    #[cfg(test)]
    EnvToken(String),
}

#[derive(Debug, PartialEq, Eq)]
enum SelectedToken<'a> {
    Env(String),
    Fetch(&'a str),
}

/// An empty `GOOGLE_OAUTH_ACCESS_TOKEN` counts as unset, so a leftover
/// `KEY=` line falls back to the metadata server.
fn select_token(source: &AccessTokenSource, env_token: Option<String>) -> SelectedToken<'_> {
    match source {
        AccessTokenSource::Ambient => env_token
            .filter(|token| !token.is_empty())
            .map_or(SelectedToken::Fetch(METADATA_TOKEN_URL), SelectedToken::Env),
        #[cfg(test)]
        AccessTokenSource::Endpoint(url) => SelectedToken::Fetch(url),
        #[cfg(test)]
        AccessTokenSource::EnvToken(token) => SelectedToken::Env(token.clone()),
    }
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
}

#[derive(Deserialize)]
struct PublicKeyResponse {
    pem: String,
    algorithm: String,
}

#[derive(Serialize)]
struct AsymmetricSignRequest<'a> {
    digest: DigestBody<'a>,
}

#[derive(Serialize)]
struct DigestBody<'a> {
    sha256: &'a str,
}

#[derive(Deserialize)]
struct AsymmetricSignResponse {
    signature: String,
}

/// Signs about every eight minutes, so each call fetches a fresh access
/// token from the link-local metadata server instead of caching one.
pub(crate) struct KmsSigner {
    http: reqwest::Client,
    kms_base_url: String,
    token_source: AccessTokenSource,
    key_version: String,
    verifying_key: VerifyingKey,
}

impl std::fmt::Debug for KmsSigner {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("KmsSigner")
            .field("key_version", &self.key_version)
            .finish_non_exhaustive()
    }
}

impl KmsSigner {
    /// Fetches the key's public half and checks its algorithm, so a wrong
    /// key fails at startup instead of on the first RPC call.
    pub(crate) async fn new(
        key_version: String,
        kms_base_url: String,
        token_source: AccessTokenSource,
    ) -> Result<Self, Error> {
        let http = reqwest::Client::builder()
            .timeout(KMS_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .user_agent("st0x-rpc")
            .build()?;
        let token = access_token(&http, &token_source).await?;

        let response = http
            .get(format!("{kms_base_url}/{key_version}/publicKey"))
            .bearer_auth(&token)
            .send()
            .await?;
        let PublicKeyResponse { pem, algorithm } = kms_success(response).await?.json().await?;
        if algorithm != REQUIRED_ALGORITHM {
            return Err(Error::WrongAlgorithm {
                key_version,
                algorithm,
            });
        }
        let verifying_key = VerifyingKey::from_public_key_pem(&pem)?;

        Ok(Self {
            http,
            kms_base_url,
            token_source,
            key_version,
            verifying_key,
        })
    }
}

impl JwsSigner for KmsSigner {
    async fn sign(&self, message: &[u8]) -> Result<Signature, Error> {
        let token = access_token(&self.http, &self.token_source).await?;
        let digest = BASE64_STANDARD.encode(Sha256::digest(message));
        let response = self
            .http
            .post(format!(
                "{}/{}:asymmetricSign",
                self.kms_base_url, self.key_version
            ))
            .bearer_auth(&token)
            .json(&AsymmetricSignRequest {
                digest: DigestBody { sha256: &digest },
            })
            .send()
            .await?;
        let AsymmetricSignResponse { signature } = kms_success(response).await?.json().await?;
        let signature = Signature::from_der(&BASE64_STANDARD.decode(signature)?)?;

        // KMS does not normalize S; JWS ES256 verifiers accept high-S.
        self.verifying_key
            .verify(message, &signature)
            .map_err(|_| Error::SignatureVerification)?;
        Ok(signature)
    }
}

async fn kms_success(response: reqwest::Response) -> Result<reqwest::Response, Error> {
    let status = response.status();
    if status.is_success() {
        return Ok(response);
    }
    Err(Error::KmsStatus {
        status: status.as_u16(),
        body: response.text().await.unwrap_or_default(),
    })
}

async fn access_token(http: &reqwest::Client, source: &AccessTokenSource) -> Result<String, Error> {
    let url = match select_token(source, std::env::var("GOOGLE_OAUTH_ACCESS_TOKEN").ok()) {
        SelectedToken::Env(token) => return Ok(token),
        SelectedToken::Fetch(url) => url,
    };
    let response = http
        .get(url)
        .header("Metadata-Flavor", "Google")
        .timeout(METADATA_TIMEOUT)
        .send()
        .await?;
    let status = response.status();
    if !status.is_success() {
        return Err(Error::TokenStatus {
            status: status.as_u16(),
        });
    }
    // Parsed by hand: a serde error can quote the body, which holds the token.
    let body = response.bytes().await?;
    let TokenResponse { access_token } =
        serde_json::from_slice(&body).map_err(|_| Error::TokenResponse)?;
    Ok(access_token)
}

#[cfg(test)]
mod tests {
    use httpmock::{HttpMockResponse, MockServer};
    use p256::ecdsa::SigningKey;

    use super::*;
    use crate::test_support::{
        kms_signature_response, kms_signer, mock_public_key, mock_sign, mock_token,
        sign_requested_digest, sign_response, signing_key, token_source, ACCESS_TOKEN, KEY_VERSION,
    };

    const MESSAGE: &[u8] = b"header.claims";

    fn mock_sign_with(
        server: &MockServer,
        respond: impl Fn(&httpmock::HttpMockRequest) -> HttpMockResponse + Send + Sync + 'static,
    ) -> httpmock::Mock<'_> {
        server.mock(|when, then| {
            when.method("POST")
                .path(format!("/{KEY_VERSION}:asymmetricSign"));
            then.respond_with(respond);
        })
    }

    fn json_response(status: u16, body: &str) -> HttpMockResponse {
        HttpMockResponse::builder()
            .status(status)
            .header("content-type", "application/json")
            .body(body.to_string())
            .build()
    }

    #[test]
    fn env_token_wins_unless_empty() {
        let source = AccessTokenSource::Ambient;
        assert_eq!(
            select_token(&source, Some("env-token".to_string())),
            SelectedToken::Env("env-token".to_string())
        );
        assert_eq!(
            select_token(&source, Some(String::new())),
            SelectedToken::Fetch(METADATA_TOKEN_URL)
        );
        assert_eq!(
            select_token(&source, None),
            SelectedToken::Fetch(METADATA_TOKEN_URL)
        );
    }

    #[tokio::test]
    async fn signs_with_metadata_token_and_verifies() {
        let server = MockServer::start_async().await;
        let token = mock_token(&server);
        mock_public_key(&server, REQUIRED_ALGORITHM);
        let sign = mock_sign(&server);

        let signer = kms_signer(&server).await;
        let signature = signer.sign(MESSAGE).await.unwrap();
        signing_key()
            .verifying_key()
            .verify(MESSAGE, &signature)
            .unwrap();
        signer.sign(MESSAGE).await.unwrap();

        token.assert_calls(3);
        sign.assert_calls(2);
    }

    #[tokio::test]
    async fn accepts_high_s_signature() {
        let server = MockServer::start_async().await;
        mock_token(&server);
        mock_public_key(&server, REQUIRED_ALGORITHM);
        mock_sign_with(&server, |request| {
            let signature = sign_requested_digest(request, &signing_key());
            let low = signature.normalize_s().unwrap_or(signature);
            let high = Signature::from_scalars(low.r(), -*low.s()).unwrap();
            assert!(high.normalize_s().is_some());
            kms_signature_response(&high)
        });

        let signer = kms_signer(&server).await;
        let signature = signer.sign(MESSAGE).await.unwrap();
        assert!(signature.normalize_s().is_some());
    }

    #[tokio::test]
    async fn refuses_signature_from_another_key() {
        let server = MockServer::start_async().await;
        mock_token(&server);
        mock_public_key(&server, REQUIRED_ALGORITHM);
        mock_sign_with(&server, |request| {
            sign_response(request, &SigningKey::from_slice(&[9; 32]).unwrap())
        });

        let signer = kms_signer(&server).await;
        assert!(matches!(
            signer.sign(MESSAGE).await,
            Err(Error::SignatureVerification)
        ));
    }

    #[tokio::test]
    async fn rejects_wrong_algorithm() {
        let server = MockServer::start_async().await;
        mock_token(&server);
        mock_public_key(&server, "EC_SIGN_SECP256K1_SHA256");

        let err = KmsSigner::new(
            KEY_VERSION.to_string(),
            server.base_url(),
            token_source(&server),
        )
        .await
        .unwrap_err();
        assert!(matches!(
            err,
            Error::WrongAlgorithm { ref algorithm, .. } if algorithm == "EC_SIGN_SECP256K1_SHA256"
        ));
    }

    #[tokio::test]
    async fn public_key_failures() {
        let server = MockServer::start_async().await;
        mock_token(&server);
        let mut public_key = server.mock(|when, then| {
            when.method("GET").path(format!("/{KEY_VERSION}/publicKey"));
            then.status(403).body(r#"{"error":{"code":403}}"#);
        });
        let err = KmsSigner::new(
            KEY_VERSION.to_string(),
            server.base_url(),
            token_source(&server),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, Error::KmsStatus { status: 403, .. }));

        public_key.delete();
        server.mock(|when, then| {
            when.method("GET").path(format!("/{KEY_VERSION}/publicKey"));
            then.status(200).json_body(serde_json::json!({
                "pem": "-----BEGIN PUBLIC KEY-----\nnot a key\n-----END PUBLIC KEY-----\n",
                "algorithm": REQUIRED_ALGORITHM,
            }));
        });
        let err = KmsSigner::new(
            KEY_VERSION.to_string(),
            server.base_url(),
            token_source(&server),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, Error::Spki(_)));
    }

    async fn sign_error(status: u16, body: &'static str) -> Error {
        let server = MockServer::start_async().await;
        mock_token(&server);
        mock_public_key(&server, REQUIRED_ALGORITHM);
        mock_sign_with(&server, move |_| json_response(status, body));
        kms_signer(&server).await.sign(MESSAGE).await.unwrap_err()
    }

    #[tokio::test]
    async fn sign_failures() {
        let err = sign_error(500, r#"{"error":{"code":500}}"#).await;
        assert!(
            matches!(err, Error::KmsStatus { status: 500, .. }),
            "{err:?}"
        );
        let err = sign_error(200, r#"{"signature":"***"}"#).await;
        assert!(matches!(err, Error::Base64(_)), "{err:?}");
        let err = sign_error(200, r#"{"signature":"AAEC"}"#).await;
        assert!(matches!(err, Error::Ecdsa(_)), "{err:?}");
    }

    #[tokio::test]
    async fn env_token_skips_metadata_server() {
        let server = MockServer::start_async().await;
        let token = mock_token(&server);
        mock_public_key(&server, REQUIRED_ALGORITHM);
        mock_sign(&server);

        let signer = KmsSigner::new(
            KEY_VERSION.to_string(),
            server.base_url(),
            AccessTokenSource::EnvToken(ACCESS_TOKEN.to_string()),
        )
        .await
        .unwrap();
        signer.sign(MESSAGE).await.unwrap();
        token.assert_calls(0);
    }

    #[tokio::test]
    async fn redirects_are_not_followed() {
        let server = MockServer::start_async().await;
        let mut token = server.mock(|when, then| {
            when.method("GET").path("/token");
            then.status(302)
                .header("location", server.url("/elsewhere"));
        });
        let elsewhere = server.mock(|when, then| {
            when.path("/elsewhere");
            then.status(200)
                .json_body(serde_json::json!({ "access_token": ACCESS_TOKEN }));
        });
        let err = KmsSigner::new(
            KEY_VERSION.to_string(),
            server.base_url(),
            token_source(&server),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, Error::TokenStatus { status: 302 }), "{err:?}");

        token.delete();
        mock_token(&server);
        mock_public_key(&server, REQUIRED_ALGORITHM);
        mock_sign_with(&server, |_| {
            HttpMockResponse::builder()
                .status(302)
                .header("location", "/elsewhere")
                .build()
        });
        let err = kms_signer(&server).await.sign(MESSAGE).await.unwrap_err();
        assert!(
            matches!(err, Error::KmsStatus { status: 302, .. }),
            "{err:?}"
        );
        elsewhere.assert_calls(0);
    }

    #[tokio::test]
    async fn metadata_failures_hide_token() {
        let server = MockServer::start_async().await;
        let mut token = server.mock(|when, then| {
            when.method("GET").path("/token");
            then.status(500).body(ACCESS_TOKEN);
        });
        let err = KmsSigner::new(
            KEY_VERSION.to_string(),
            server.base_url(),
            token_source(&server),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, Error::TokenStatus { status: 500 }));
        assert!(!format!("{err} {err:?}").contains(ACCESS_TOKEN));

        for body in [
            format!(r#"{{"access_token":"{ACCESS_TOKEN}","expires_in":"#),
            format!(r#""{ACCESS_TOKEN}""#),
            format!(r#"{{"access_token":["{ACCESS_TOKEN}"]}}"#),
        ] {
            token.delete();
            token = server.mock(|when, then| {
                when.method("GET").path("/token");
                then.status(200).body(body);
            });
            let err = KmsSigner::new(
                KEY_VERSION.to_string(),
                server.base_url(),
                token_source(&server),
            )
            .await
            .unwrap_err();
            assert!(matches!(err, Error::TokenResponse), "{err:?}");
            assert!(!format!("{err} {err:?}").contains(ACCESS_TOKEN));
        }
    }
}
