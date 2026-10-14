use alloy_transport::TransportError;

/// Errors from building an RPC client or authenticating its requests.
///
/// No variant holds the RPC URL, a JWT or a Google access token. HTTP
/// bodies appear only for non-2xx KMS responses (Google error JSON).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("RPC URL does not parse")]
    InvalidUrl,
    #[error("RPC URL scheme must be http or https")]
    UnsupportedScheme,
    #[error("RPC URL points at an Alchemy /v2 endpoint but is not the bare `https://<network>.g.alchemy.com/v2` form")]
    MalformedAlchemyUrl,
    #[error("a bare Alchemy /v2 URL needs a KMS-signed JWT, but {missing} is not set")]
    MissingJwtConfig { missing: &'static str },
    #[error("Alchemy JWT startup check did not finish within its time limit")]
    StartupTimeout,
    #[error("HTTP request failed")]
    Http(#[source] reqwest::Error),
    #[error("JWT signing is backing off after a failed KMS call")]
    KmsBackoff,
    #[error("metadata token endpoint returned HTTP {status}")]
    TokenStatus { status: u16 },
    #[error("metadata token response is not the expected JSON")]
    TokenResponse,
    #[error("KMS returned HTTP {status}: {body}")]
    KmsStatus { status: u16, body: String },
    #[error("KMS key version {key_version} has algorithm {algorithm}; ES256 requires EC_SIGN_P256_SHA256")]
    WrongAlgorithm {
        key_version: String,
        algorithm: String,
    },
    #[error("KMS public key PEM does not parse: {0}")]
    Spki(#[from] p256::pkcs8::spki::Error),
    #[error("KMS base64 does not decode: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("KMS signature is not DER ECDSA P-256: {0}")]
    Ecdsa(#[from] p256::ecdsa::Error),
    #[error("KMS signature does not verify with the key's public half")]
    SignatureVerification,
    #[error("JSON encoding failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("system clock is before the Unix epoch or out of range")]
    Clock,
    #[error("KMS signing finished after the JWT's expiry")]
    MintedExpired,
    #[error("Alchemy JWT startup check failed")]
    Rpc(#[source] TransportError),
}

impl From<reqwest::Error> for Error {
    fn from(err: reqwest::Error) -> Self {
        Self::Http(err.without_url())
    }
}
