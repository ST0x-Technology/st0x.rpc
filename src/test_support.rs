use std::sync::{Arc, Mutex};

use base64::prelude::BASE64_STANDARD;
use base64::Engine as _;
use httpmock::{HttpMockRequest, HttpMockResponse, Mock, MockServer};
use p256::ecdsa::signature::hazmat::PrehashSigner as _;
use p256::ecdsa::{Signature, SigningKey};
use p256::pkcs8::EncodePublicKey as _;

use crate::kms::{AccessTokenSource, KmsSigner};

pub(crate) const KEY_VERSION: &str =
    "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1";
pub(crate) const ACCESS_TOKEN: &str = "ya29.test-access-token";
pub(crate) const CHAIN_ID: &str = "0x2105";

pub(crate) fn signing_key() -> SigningKey {
    SigningKey::from_slice(&[7; 32]).unwrap()
}

pub(crate) fn token_source(server: &MockServer) -> AccessTokenSource {
    AccessTokenSource::Endpoint(server.url("/token"))
}

pub(crate) fn mock_token(server: &MockServer) -> Mock<'_> {
    server.mock(|when, then| {
        when.method("GET")
            .path("/token")
            .header("Metadata-Flavor", "Google");
        then.status(200).json_body(serde_json::json!({
            "access_token": ACCESS_TOKEN,
            "expires_in": 3599,
            "token_type": "Bearer",
        }));
    })
}

pub(crate) fn mock_public_key<'a>(server: &'a MockServer, algorithm: &str) -> Mock<'a> {
    let pem = signing_key()
        .verifying_key()
        .to_public_key_pem(p256::pkcs8::LineEnding::LF)
        .unwrap();
    server.mock(|when, then| {
        when.method("GET").path(format!("/{KEY_VERSION}/publicKey"));
        then.status(200).json_body(serde_json::json!({
            "pem": pem,
            "algorithm": algorithm,
        }));
    })
}

/// KMS `asymmetricSign` that signs the posted digest with `signing_key()`
/// when called with `ACCESS_TOKEN`.
pub(crate) fn mock_sign(server: &MockServer) -> Mock<'_> {
    server.mock(|when, then| {
        when.method("POST")
            .path(format!("/{KEY_VERSION}:asymmetricSign"))
            .header("authorization", format!("Bearer {ACCESS_TOKEN}"));
        then.respond_with(|request| sign_response(request, &signing_key()));
    })
}

pub(crate) fn sign_response(request: &HttpMockRequest, key: &SigningKey) -> HttpMockResponse {
    let signature = sign_requested_digest(request, key);
    kms_signature_response(&signature)
}

pub(crate) fn sign_requested_digest(request: &HttpMockRequest, key: &SigningKey) -> Signature {
    let body: serde_json::Value = serde_json::from_slice(&request.body().to_vec()).unwrap();
    let digest = BASE64_STANDARD
        .decode(body["digest"]["sha256"].as_str().unwrap())
        .unwrap();
    key.sign_prehash(&digest).unwrap()
}

pub(crate) fn kms_signature_response(signature: &Signature) -> HttpMockResponse {
    let body = serde_json::json!({ "signature": BASE64_STANDARD.encode(signature.to_der()) });
    HttpMockResponse::builder()
        .status(200)
        .header("content-type", "application/json")
        .body(body.to_string())
        .build()
}

pub(crate) async fn kms_signer(server: &MockServer) -> KmsSigner {
    KmsSigner::new(
        KEY_VERSION.to_string(),
        server.base_url(),
        token_source(server),
    )
    .await
    .unwrap()
}

/// `Authorization` header values of every RPC request, in order.
pub(crate) type SeenAuthorization = Arc<Mutex<Vec<Vec<String>>>>;

/// JSON-RPC endpoint at `path` that answers every call, single or batch,
/// with `CHAIN_ID` and records the `Authorization` headers it saw.
pub(crate) fn mock_rpc<'a>(server: &'a MockServer, path: &str) -> (Mock<'a>, SeenAuthorization) {
    let seen = SeenAuthorization::default();
    let recorder = Arc::clone(&seen);
    let mock = server.mock(move |when, then| {
        when.method("POST").path(path);
        then.respond_with(move |request| {
            let authorization = request
                .headers()
                .get_all("authorization")
                .iter()
                .map(|value| value.to_str().unwrap().to_string())
                .collect();
            recorder.lock().unwrap().push(authorization);
            let body: serde_json::Value =
                serde_json::from_slice(&request.body().to_vec()).unwrap();
            let answer = |call: &serde_json::Value| {
                serde_json::json!({ "jsonrpc": "2.0", "id": call["id"], "result": CHAIN_ID })
            };
            let response = match body.as_array() {
                Some(calls) => calls.iter().map(answer).collect(),
                None => answer(&body),
            };
            HttpMockResponse::builder()
                .status(200)
                .header("content-type", "application/json")
                .body(response.to_string())
                .build()
        });
    });
    (mock, seen)
}
