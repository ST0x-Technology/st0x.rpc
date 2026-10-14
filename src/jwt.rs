//! Alchemy JWTs: `{"alg":"ES256","typ":"JWT","kid":…}` over
//! `{"iat":…,"exp":iat+600}`, cached and re-minted two minutes before
//! expiry.

use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde::Serialize;
use tokio::sync::OwnedMutexGuard;
use tokio::task::JoinHandle;
use tracing::warn;

use crate::kms::{JwsSigner, KmsSigner};
use crate::Error;

const TTL_SECS: u64 = 600;
const REFRESH_BEFORE_EXPIRY_SECS: u64 = 120;
/// After a failed mint, no new KMS call is made for this long.
const RETRY_BACKOFF_SECS: u64 = 10;

/// Wall-clock seconds since the Unix epoch: Alchemy checks `exp` against
/// its own clock, so the monotonic clock does not fit.
pub(crate) type Clock = Box<dyn Fn() -> Result<u64, Error> + Send + Sync>;

fn system_clock() -> Result<u64, Error> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .map_err(|_| Error::Clock)
}

#[derive(Serialize)]
struct Header<'a> {
    alg: &'static str,
    typ: &'static str,
    kid: &'a str,
}

#[derive(Serialize)]
struct Claims {
    iat: u64,
    exp: u64,
}

struct Cached {
    token: String,
    exp: u64,
}

#[derive(Default)]
struct State {
    cached: Option<Cached>,
    retry_after: u64,
}

pub(crate) struct JwtMinter<S = KmsSigner> {
    signer: S,
    kid: String,
    clock: Clock,
    state: Mutex<State>,
    /// Held by the one mint in flight, so a burst makes one KMS call.
    refresh: Arc<tokio::sync::Mutex<()>>,
}

impl<S: std::fmt::Debug> std::fmt::Debug for JwtMinter<S> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("JwtMinter")
            .field("kid", &self.kid)
            .field("signer", &self.signer)
            .finish_non_exhaustive()
    }
}

/// Outcome of reading the cache without minting.
enum Lookup {
    Ready(String),
    /// Usable token in its refresh window: this caller may refresh it.
    Refresh(String),
    Mint,
}

impl<S: JwsSigner> JwtMinter<S> {
    pub(crate) fn new(signer: S, kid: String) -> Self {
        Self::with_clock(signer, kid, Box::new(system_clock))
    }

    pub(crate) fn with_clock(signer: S, kid: String, clock: Clock) -> Self {
        Self {
            signer,
            kid,
            clock,
            state: Mutex::new(State::default()),
            refresh: Arc::new(tokio::sync::Mutex::new(())),
        }
    }

    /// An unexpired JWT. Inside the refresh window the cached token is
    /// returned at once while a background task mints the next one; an
    /// expired token is never returned.
    pub(crate) async fn bearer(self: &Arc<Self>) -> Result<String, Error> {
        match self.lookup()? {
            Lookup::Ready(token) => Ok(token),
            Lookup::Refresh(cached) => {
                if let Ok(guard) = Arc::clone(&self.refresh).try_lock_owned() {
                    drop(self.spawn_mint(guard));
                }
                Ok(cached)
            }
            Lookup::Mint => {
                let guard = Arc::clone(&self.refresh).lock_owned().await;
                self.spawn_mint(guard)
                    .await
                    .unwrap_or_else(|err| std::panic::resume_unwind(err.into_panic()))?;
                // This caller may resume long after the mint finished.
                match self.lookup()? {
                    Lookup::Ready(token) | Lookup::Refresh(token) => Ok(token),
                    Lookup::Mint => Err(Error::MintedExpired),
                }
            }
        }
    }

    /// Mints in its own task, so a caller cancelled mid-mint still leaves
    /// the new token or the backoff behind.
    fn spawn_mint(
        self: &Arc<Self>,
        guard: OwnedMutexGuard<()>,
    ) -> JoinHandle<Result<String, Error>> {
        let minter = Arc::clone(self);
        tokio::spawn(async move {
            let _guard = guard;
            minter.mint_unless_ready().await
        })
    }

    /// Caller holds `refresh`; another mint may have finished meanwhile.
    async fn mint_unless_ready(&self) -> Result<String, Error> {
        match self.lookup()? {
            Lookup::Ready(token) => Ok(token),
            Lookup::Refresh(_) | Lookup::Mint => self.mint().await,
        }
    }

    fn lookup(&self) -> Result<Lookup, Error> {
        let now = (self.clock)()?;
        let state = self.lock_state();
        let usable = state.cached.as_ref().filter(|cached| now < cached.exp);
        let backing_off = now < state.retry_after;
        Ok(match usable {
            Some(cached)
                if backing_off || now.saturating_add(REFRESH_BEFORE_EXPIRY_SECS) < cached.exp =>
            {
                Lookup::Ready(cached.token.clone())
            }
            Some(cached) => Lookup::Refresh(cached.token.clone()),
            None if backing_off => return Err(Error::KmsBackoff),
            None => Lookup::Mint,
        })
    }

    async fn mint(&self) -> Result<String, Error> {
        let iat = (self.clock)()?;
        let exp = iat.checked_add(TTL_SECS).ok_or(Error::Clock)?;
        let minted = self.encode(iat, exp).await;
        let now = (self.clock)()?;
        let minted = minted.and_then(|token| {
            if now < exp {
                Ok(token)
            } else {
                Err(Error::MintedExpired)
            }
        });
        let mut state = self.lock_state();
        match minted {
            Ok(token) => {
                state.cached = Some(Cached {
                    token: token.clone(),
                    exp,
                });
                state.retry_after = 0;
                Ok(token)
            }
            Err(err) => {
                state.retry_after = now.saturating_add(RETRY_BACKOFF_SECS);
                warn!(kid = %self.kid, error = %err, "Alchemy JWT mint failed");
                match state.cached.as_ref().filter(|cached| now < cached.exp) {
                    Some(cached) => Ok(cached.token.clone()),
                    None => Err(err),
                }
            }
        }
    }

    async fn encode(&self, iat: u64, exp: u64) -> Result<String, Error> {
        let header = serde_json::to_vec(&Header {
            alg: "ES256",
            typ: "JWT",
            kid: &self.kid,
        })?;
        let claims = serde_json::to_vec(&Claims { iat, exp })?;
        let signing_input = format!(
            "{}.{}",
            BASE64_URL_SAFE_NO_PAD.encode(header),
            BASE64_URL_SAFE_NO_PAD.encode(claims)
        );
        let signature = self.signer.sign(signing_input.as_bytes()).await?;
        Ok(format!(
            "{signing_input}.{}",
            BASE64_URL_SAFE_NO_PAD.encode(signature.to_bytes())
        ))
    }

    fn lock_state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    use p256::ecdsa::signature::{Signer as _, Verifier as _};
    use p256::ecdsa::{Signature, SigningKey};
    use tokio::sync::Semaphore;

    use super::*;
    use crate::test_support::signing_key;

    const KID: &str = "test-kid";
    const IAT: u64 = 1_000;

    /// Signs locally; `gate` holds each call until a permit is added, and
    /// `fail` makes calls fail.
    struct FakeSigner {
        key: SigningKey,
        calls: AtomicUsize,
        fail: AtomicBool,
        gate: Semaphore,
    }

    impl FakeSigner {
        fn open() -> Self {
            Self::with_permits(Semaphore::MAX_PERMITS)
        }

        fn gated() -> Self {
            Self::with_permits(0)
        }

        fn with_permits(permits: usize) -> Self {
            Self {
                key: signing_key(),
                calls: AtomicUsize::new(0),
                fail: AtomicBool::new(false),
                gate: Semaphore::new(permits),
            }
        }
    }

    impl JwsSigner for FakeSigner {
        async fn sign(&self, message: &[u8]) -> Result<Signature, Error> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.gate.acquire().await.unwrap().forget();
            if self.fail.load(Ordering::SeqCst) {
                return Err(Error::KmsStatus {
                    status: 503,
                    body: String::new(),
                });
            }
            Ok(self.key.sign(message))
        }
    }

    struct Harness {
        minter: Arc<JwtMinter<FakeSigner>>,
        now: Arc<AtomicU64>,
    }

    impl Harness {
        fn new(signer: FakeSigner) -> Self {
            let now = Arc::new(AtomicU64::new(IAT));
            let clock = Arc::clone(&now);
            let minter = JwtMinter::with_clock(
                signer,
                KID.to_string(),
                Box::new(move || Ok(clock.load(Ordering::SeqCst))),
            );
            Self {
                minter: Arc::new(minter),
                now,
            }
        }

        fn set_now(&self, now: u64) {
            self.now.store(now, Ordering::SeqCst);
        }

        fn signer(&self) -> &FakeSigner {
            &self.minter.signer
        }

        fn calls(&self) -> usize {
            self.signer().calls.load(Ordering::SeqCst)
        }

        /// Waits for an in-flight mint to finish.
        async fn settle(&self) {
            drop(self.minter.refresh.lock().await);
        }

        async fn wait_for_calls(&self, calls: usize) {
            tokio::time::timeout(Duration::from_secs(5), async {
                while self.calls() < calls {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
            })
            .await
            .expect("signer was not called");
        }

        fn set_failing(&self, fail: bool) {
            self.signer().fail.store(fail, Ordering::SeqCst);
        }

        fn spawn_bearer(&self) -> tokio::task::JoinHandle<Result<String, Error>> {
            let minter = Arc::clone(&self.minter);
            tokio::spawn(async move { minter.bearer().await })
        }
    }

    fn decode_part(part: &str) -> String {
        String::from_utf8(BASE64_URL_SAFE_NO_PAD.decode(part).unwrap()).unwrap()
    }

    #[tokio::test]
    async fn token_shape() {
        let harness = Harness::new(FakeSigner::open());
        let token = harness.minter.bearer().await.unwrap();

        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3);
        assert_eq!(
            decode_part(parts[0]),
            r#"{"alg":"ES256","typ":"JWT","kid":"test-kid"}"#
        );
        assert_eq!(decode_part(parts[1]), r#"{"iat":1000,"exp":1600}"#);
        let signature =
            Signature::from_slice(&BASE64_URL_SAFE_NO_PAD.decode(parts[2]).unwrap()).unwrap();
        let signing_input = format!("{}.{}", parts[0], parts[1]);
        signing_key()
            .verifying_key()
            .verify(signing_input.as_bytes(), &signature)
            .unwrap();
    }

    #[tokio::test]
    async fn reuses_token_until_refresh_window() {
        let harness = Harness::new(FakeSigner::open());
        let first = harness.minter.bearer().await.unwrap();

        harness.set_now(IAT + TTL_SECS - REFRESH_BEFORE_EXPIRY_SECS - 1);
        assert_eq!(harness.minter.bearer().await.unwrap(), first);
        harness.settle().await;
        assert_eq!(harness.calls(), 1);

        harness.set_now(IAT + TTL_SECS - REFRESH_BEFORE_EXPIRY_SECS);
        assert_eq!(harness.minter.bearer().await.unwrap(), first);
        harness.wait_for_calls(2).await;
        harness.settle().await;
        let second = harness.minter.bearer().await.unwrap();
        assert_ne!(second, first);
        assert_eq!(harness.calls(), 2);
    }

    #[tokio::test]
    async fn refresh_never_blocks_callers() {
        let harness = Harness::new(FakeSigner::open());
        let first = harness.minter.bearer().await.unwrap();
        harness.signer().gate.forget_permits(Semaphore::MAX_PERMITS);

        harness.set_now(IAT + TTL_SECS - REFRESH_BEFORE_EXPIRY_SECS);
        for _ in 0..3 {
            let token = tokio::time::timeout(Duration::from_secs(1), harness.minter.bearer())
                .await
                .expect("a caller must not wait on a refresh");
            assert_eq!(token.unwrap(), first);
        }
        harness.wait_for_calls(2).await;

        harness.signer().gate.add_permits(1);
        harness.settle().await;
        assert_ne!(harness.minter.bearer().await.unwrap(), first);
        assert_eq!(harness.calls(), 2);
    }

    #[tokio::test]
    async fn failed_refresh_keeps_cached_token_and_backs_off() {
        let harness = Harness::new(FakeSigner::open());
        let first = harness.minter.bearer().await.unwrap();
        harness.set_failing(true);

        let refresh_at = IAT + TTL_SECS - REFRESH_BEFORE_EXPIRY_SECS;
        harness.set_now(refresh_at);
        assert_eq!(harness.minter.bearer().await.unwrap(), first);
        harness.wait_for_calls(2).await;
        harness.settle().await;

        harness.set_now(refresh_at + RETRY_BACKOFF_SECS - 1);
        assert_eq!(harness.minter.bearer().await.unwrap(), first);
        harness.settle().await;
        assert_eq!(harness.calls(), 2);

        harness.set_now(refresh_at + RETRY_BACKOFF_SECS);
        assert_eq!(harness.minter.bearer().await.unwrap(), first);
        harness.wait_for_calls(3).await;
        harness.settle().await;
    }

    #[tokio::test]
    async fn expired_token_is_never_returned() {
        let harness = Harness::new(FakeSigner::open());
        harness.minter.bearer().await.unwrap();
        harness.set_failing(true);

        let exp = IAT + TTL_SECS;
        harness.set_now(exp);
        assert!(matches!(
            harness.minter.bearer().await,
            Err(Error::KmsStatus { status: 503, .. })
        ));
        assert_eq!(harness.calls(), 2);

        harness.set_now(exp + RETRY_BACKOFF_SECS - 1);
        assert!(matches!(
            harness.minter.bearer().await,
            Err(Error::KmsBackoff)
        ));
        assert_eq!(harness.calls(), 2);

        harness.set_failing(false);
        harness.set_now(exp + RETRY_BACKOFF_SECS);
        harness.minter.bearer().await.unwrap();
        assert_eq!(harness.calls(), 3);
    }

    #[tokio::test]
    async fn token_expiring_during_failed_refresh_is_not_returned() {
        let harness = Harness::new(FakeSigner::open());
        harness.minter.bearer().await.unwrap();
        harness.set_failing(true);
        harness.signer().gate.forget_permits(Semaphore::MAX_PERMITS);

        harness.set_now(IAT + TTL_SECS - 1);
        harness.minter.bearer().await.unwrap();
        harness.wait_for_calls(2).await;
        harness.set_now(IAT + TTL_SECS);
        harness.signer().gate.add_permits(1);
        harness.settle().await;

        assert!(matches!(
            harness.minter.bearer().await,
            Err(Error::KmsBackoff)
        ));
    }

    #[tokio::test]
    async fn token_expiring_during_successful_mint_is_not_returned() {
        let harness = Harness::new(FakeSigner::gated());
        let minting = harness.spawn_bearer();
        harness.wait_for_calls(1).await;
        harness.set_now(IAT + TTL_SECS);
        harness.signer().gate.add_permits(1);

        assert!(matches!(minting.await.unwrap(), Err(Error::MintedExpired)));
    }

    #[tokio::test]
    async fn caller_resuming_after_expiry_gets_no_token() {
        // Clock reads: the caller's lookup, the task's lookup, iat, the
        // post-sign check; the caller's final lookup lands after expiry.
        let reads = AtomicUsize::new(0);
        let minter = Arc::new(JwtMinter::with_clock(
            FakeSigner::open(),
            KID.to_string(),
            Box::new(move || {
                Ok(if reads.fetch_add(1, Ordering::SeqCst) < 4 {
                    IAT
                } else {
                    IAT + TTL_SECS
                })
            }),
        ));

        assert!(matches!(minter.bearer().await, Err(Error::MintedExpired)));
        assert_eq!(
            minter.lock_state().cached.as_ref().map(|cached| cached.exp),
            Some(IAT + TTL_SECS),
            "the mint succeeded, so the error must come from the caller's re-lookup"
        );
    }

    #[tokio::test]
    async fn cancelled_caller_still_completes_mint() {
        let harness = Harness::new(FakeSigner::gated());
        let minting = harness.spawn_bearer();
        harness.wait_for_calls(1).await;
        minting.abort();
        assert!(minting.await.unwrap_err().is_cancelled());

        harness.signer().gate.add_permits(1);
        harness.settle().await;
        harness.minter.bearer().await.unwrap();
        assert_eq!(harness.calls(), 1);
    }

    #[tokio::test]
    async fn concurrent_callers_share_one_mint() {
        let harness = Harness::new(FakeSigner::gated());
        let callers: Vec<_> = (0..16).map(|_| harness.spawn_bearer()).collect();
        harness.wait_for_calls(1).await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        harness.signer().gate.add_permits(1);

        let mut tokens = Vec::new();
        for caller in callers {
            tokens.push(caller.await.unwrap().unwrap());
        }
        assert!(tokens.windows(2).all(|pair| pair[0] == pair[1]));
        assert_eq!(harness.calls(), 1);
    }

    #[tokio::test]
    async fn waiters_after_failed_mint_back_off() {
        let harness = Harness::new(FakeSigner::gated());
        harness.set_failing(true);
        let callers: Vec<_> = (0..8).map(|_| harness.spawn_bearer()).collect();
        harness.wait_for_calls(1).await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        harness.signer().gate.add_permits(1);

        for caller in callers {
            assert!(caller.await.unwrap().is_err());
        }
        assert_eq!(harness.calls(), 1);
    }
}
