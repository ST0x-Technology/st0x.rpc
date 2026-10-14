//! JSON-RPC over HTTP POST. Unlike alloy's `Http` transport, no error or
//! span carries the URL, which can hold an Alchemy API key, and
//! redirects are not followed.

use std::sync::Arc;
use std::task::{Context, Poll};

use alloy_json_rpc::{RequestPacket, ResponsePacket};
use alloy_transport::{TransportError, TransportErrorKind, TransportFut, TransportResult};
use reqwest::header::{HeaderValue, AUTHORIZATION};
use reqwest::Url;

use crate::jwt::JwtMinter;
use crate::{Error, Timeouts};

/// Response text kept in an error is cut to this many bytes.
const MAX_ERROR_BODY: usize = 1024;
/// URL parts at least this long are treated as secrets: API keys are
/// 32 characters, network names and `v2` are short.
const MIN_SECRET_LEN: usize = 16;

#[derive(Clone)]
pub(crate) struct St0xHttp {
    client: reqwest::Client,
    url: Url,
    minter: Option<Arc<JwtMinter>>,
}

impl St0xHttp {
    pub(crate) fn new(
        url: Url,
        minter: Option<Arc<JwtMinter>>,
        timeouts: Timeouts,
    ) -> Result<Self, Error> {
        let mut builder = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none());
        if let Some(connect) = timeouts.connect {
            builder = builder.connect_timeout(connect);
        }
        if let Some(request) = timeouts.request {
            builder = builder.timeout(request);
        }
        let client = builder.build()?;
        Ok(Self {
            client,
            url,
            minter,
        })
    }

    async fn send(self, request: RequestPacket) -> TransportResult<ResponsePacket> {
        let mut headers = request.headers();
        if let Some(minter) = &self.minter {
            let token = minter.bearer().await.map_err(TransportErrorKind::custom)?;
            let mut bearer = HeaderValue::try_from(format!("Bearer {token}"))
                .map_err(TransportErrorKind::custom)?;
            bearer.set_sensitive(true);
            headers.insert(AUTHORIZATION, bearer);
        }

        let response = self
            .client
            .post(self.url.clone())
            .json(&request)
            .headers(headers)
            .send()
            .await
            .map_err(|err| TransportErrorKind::custom(err.without_url()))?;
        let status = response.status();
        let body = response
            .bytes()
            .await
            .map_err(|err| TransportErrorKind::custom(err.without_url()))?;

        if !status.is_success() {
            return Err(TransportErrorKind::http_error(
                status.as_u16(),
                redacted_body(&body, &self.url),
            ));
        }
        serde_json::from_slice(&body)
            .map_err(|err| TransportError::deser_err(err, redacted_body(&body, &self.url)))
    }
}

/// The response text for an error, without the URL's long path segments,
/// query values and credentials (an endpoint can echo its keyed path), and
/// cut to `MAX_ERROR_BODY` bytes.
fn redacted_body(body: &[u8], url: &Url) -> String {
    let mut text = String::from_utf8_lossy(body).into_owned();
    let path = url.path_segments().into_iter().flatten().map(str::to_owned);
    let query = url.query_pairs().map(|(_, value)| value.into_owned());
    let credentials = [url.username().to_owned()]
        .into_iter()
        .chain(url.password().map(str::to_owned));
    for secret in path
        .chain(query)
        .chain(credentials)
        .filter(|part| part.len() >= MIN_SECRET_LEN)
    {
        text = text.replace(&secret, "<redacted>");
    }
    if text.len() > MAX_ERROR_BODY {
        let end = (0..=MAX_ERROR_BODY)
            .rev()
            .find(|&index| text.is_char_boundary(index))
            .unwrap_or(0);
        text.truncate(end);
        text.push_str("...");
    }
    text
}

impl tower::Service<RequestPacket> for St0xHttp {
    type Response = ResponsePacket;
    type Error = TransportError;
    type Future = TransportFut<'static>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: RequestPacket) -> Self::Future {
        Box::pin(self.clone().send(request))
    }
}

#[cfg(test)]
mod tests {
    use alloy_json_rpc::{Id, Request};
    use alloy_rpc_client::{ClientBuilder, RpcClient};
    use httpmock::MockServer;
    use tower::Service as _;

    use super::*;
    use crate::kms::JwsSigner;
    use crate::test_support::{
        kms_signer, mock_public_key, mock_rpc, mock_sign, mock_token, ACCESS_TOKEN, CHAIN_ID,
    };

    const SECRET_PATH: &str = "/v2/secret-api-key";

    async fn minter(server: &MockServer) -> Arc<JwtMinter> {
        mock_token(server);
        mock_public_key(server, "EC_SIGN_P256_SHA256");
        mock_sign(server);
        Arc::new(JwtMinter::new(kms_signer(server).await, "kid".to_string()))
    }

    fn client(url: &str, minter: Option<Arc<JwtMinter>>) -> RpcClient {
        client_with(url, minter, Timeouts::default())
    }

    fn client_with(url: &str, minter: Option<Arc<JwtMinter>>, timeouts: Timeouts) -> RpcClient {
        ClientBuilder::default().transport(
            St0xHttp::new(url.parse().unwrap(), minter, timeouts).unwrap(),
            true,
        )
    }

    /// An `eth_chainId` request whose packet already carries
    /// `Authorization: Bearer stale`.
    fn request_with_stale_authorization(id: u64) -> alloy_json_rpc::SerializedRequest {
        let mut request = Request::new("eth_chainId", Id::Number(id), ())
            .serialize()
            .unwrap();
        request
            .headers_mut()
            .insert(AUTHORIZATION, HeaderValue::from_static("Bearer stale"));
        request
    }

    fn assert_no_secrets(rendered: &str, server: &MockServer, jwt: Option<&str>) {
        assert!(!rendered.contains(SECRET_PATH), "{rendered}");
        assert!(
            !rendered.contains(&server.address().to_string()),
            "{rendered}"
        );
        assert!(!rendered.contains(ACCESS_TOKEN), "{rendered}");
        if let Some(jwt) = jwt {
            assert!(!rendered.contains(jwt), "{rendered}");
        }
    }

    #[tokio::test]
    async fn sends_one_bearer_on_single_and_batch() {
        let server = MockServer::start_async().await;
        let minter = minter(&server).await;
        let (rpc, seen) = mock_rpc(&server, "/v2");
        let mut transport = St0xHttp::new(
            server.url("/v2").parse().unwrap(),
            Some(Arc::clone(&minter)),
            Timeouts::default(),
        )
        .unwrap();

        transport
            .call(RequestPacket::Single(request_with_stale_authorization(1)))
            .await
            .unwrap();
        let response = transport
            .call(RequestPacket::Batch(vec![
                request_with_stale_authorization(2),
                request_with_stale_authorization(3),
            ]))
            .await
            .unwrap();
        assert!(matches!(response, ResponsePacket::Batch(ref responses) if responses.len() == 2));

        let jwt = minter.bearer().await.unwrap();
        let expected = vec![format!("Bearer {jwt}")];
        assert_eq!(*seen.lock().unwrap(), vec![expected.clone(), expected]);
        rpc.assert_calls(2);
    }

    #[tokio::test]
    async fn plain_mode_forwards_request_unchanged() {
        let server = MockServer::start_async().await;
        let (_rpc, seen) = mock_rpc(&server, "/rpc");

        let chain_id: String = client(&server.url("/rpc"), None)
            .request_noparams("eth_chainId")
            .await
            .unwrap();
        assert_eq!(chain_id, CHAIN_ID);
        assert_eq!(*seen.lock().unwrap(), vec![Vec::<String>::new()]);
    }

    #[tokio::test]
    async fn does_not_follow_redirects() {
        let server = MockServer::start_async().await;
        server.mock(|when, then| {
            when.method("POST").path(SECRET_PATH);
            then.status(302)
                .header("location", server.url("/elsewhere"));
        });
        let (target, _) = mock_rpc(&server, "/elsewhere");

        let err = client(&server.url(SECRET_PATH), None)
            .request_noparams::<String>("eth_chainId")
            .await
            .unwrap_err();
        assert!(
            err.as_transport_err()
                .is_some_and(|kind| kind.as_http_error().is_some_and(|http| http.status == 302)),
            "{err:?}"
        );
        target.assert_calls(0);
    }

    #[tokio::test]
    async fn errors_carry_no_url_or_tokens() {
        let server = MockServer::start_async().await;
        let minter = minter(&server).await;
        let jwt = minter.bearer().await.unwrap();
        for status in [401, 500] {
            let path = format!("{SECRET_PATH}-{status}");
            server.mock(|when, then| {
                when.method("POST").path(path.as_str());
                then.status(status).body("unauthorized");
            });
            let err = client(&server.url(&path), Some(Arc::clone(&minter)))
                .request_noparams::<String>("eth_chainId")
                .await
                .unwrap_err();
            assert_no_secrets(&format!("{err} {err:?}"), &server, Some(&jwt));
        }

        let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let closed_url = format!("http://{}{SECRET_PATH}", closed.local_addr().unwrap());
        drop(closed);
        let err = client(&closed_url, Some(minter))
            .request_noparams::<String>("eth_chainId")
            .await
            .unwrap_err();
        let rendered = format!("{err} {err:?}");
        assert!(!rendered.contains(SECRET_PATH), "{rendered}");
        assert!(!rendered.contains(&jwt), "{rendered}");
    }

    #[tokio::test]
    async fn request_timeout_bounds_a_hung_endpoint() {
        let server = MockServer::start_async().await;
        server.mock(|when, then| {
            when.method("POST").path(SECRET_PATH);
            then.status(200).delay(std::time::Duration::from_secs(5));
        });
        let timeouts = Timeouts {
            request: Some(std::time::Duration::from_millis(200)),
            ..Timeouts::default()
        };

        let started = std::time::Instant::now();
        let err = client_with(&server.url(SECRET_PATH), None, timeouts)
            .request_noparams::<String>("eth_chainId")
            .await
            .unwrap_err();
        assert!(
            started.elapsed() < std::time::Duration::from_secs(2),
            "{err:?}"
        );
        assert_no_secrets(&format!("{err} {err:?}"), &server, None);
    }

    #[tokio::test]
    async fn accepts_gzip_responses() {
        use std::io::Write as _;

        let server = MockServer::start_async().await;
        let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gzip.write_all(format!(r#"{{"jsonrpc":"2.0","id":0,"result":"{CHAIN_ID}"}}"#).as_bytes())
            .unwrap();
        let body = gzip.finish().unwrap();
        server.mock(|when, then| {
            when.method("POST")
                .path("/rpc")
                .header_includes("accept-encoding", "gzip");
            then.status(200)
                .header("content-type", "application/json")
                .header("content-encoding", "gzip")
                .body(body);
        });

        let chain_id: String = client(&server.url("/rpc"), None)
            .request_noparams("eth_chainId")
            .await
            .unwrap();
        assert_eq!(chain_id, CHAIN_ID);
    }

    #[tokio::test]
    async fn mint_failure_is_a_transport_error() {
        let server = MockServer::start_async().await;
        mock_token(&server);
        mock_public_key(&server, "EC_SIGN_P256_SHA256");
        server.mock(|when, then| {
            when.method("POST").path_includes(":asymmetricSign");
            then.status(503).body("{}");
        });
        let signer = kms_signer(&server).await;
        assert!(signer.sign(b"x").await.is_err());
        let minter = Arc::new(JwtMinter::new(signer, "kid".to_string()));
        let (rpc, _) = mock_rpc(&server, "/v2");

        let err = client(&server.url("/v2"), Some(minter))
            .request_noparams::<String>("eth_chainId")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("KMS returned HTTP 503"), "{err}");
        rpc.assert_calls(0);
    }

    #[tokio::test]
    async fn echoed_keyed_path_is_redacted_from_errors() {
        const KEY: &str = "AbCdEf0123456789ghijKLMNopqr";
        let server = MockServer::start_async().await;
        let keyed = format!("/v2/{KEY}");
        for (path, status, body) in [
            ("/http-error", 500, format!("no route for {keyed}")),
            ("/bad-json", 200, format!("<html>{keyed}</html>")),
        ] {
            let url_path = format!("{path}{keyed}");
            server.mock(|when, then| {
                when.method("POST").path(url_path.as_str());
                then.status(status).body(body.as_str());
            });
            let err = client(&server.url(&url_path), None)
                .request_noparams::<String>("eth_chainId")
                .await
                .unwrap_err();
            let rendered = format!("{err} {err:?}");
            assert!(!rendered.contains(KEY), "{rendered}");
            assert!(rendered.contains("<redacted>"), "{rendered}");
        }
    }

    #[test]
    fn long_error_body_is_capped() {
        let url: Url = "https://base-mainnet.g.alchemy.com/v2".parse().unwrap();
        let text = redacted_body("é".repeat(MAX_ERROR_BODY).as_bytes(), &url);
        assert!(text.len() <= MAX_ERROR_BODY + 3);
        assert!(text.ends_with("..."));
    }
}
