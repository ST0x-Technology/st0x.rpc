use reqwest::Url;

/// Full KMS key-version name, `projects/…/cryptoKeyVersions/N`.
pub const KEY_VERSION_VAR: &str = "ALCHEMY_JWT_KMS_KEY_VERSION";
/// Key id Alchemy assigned to the registered public key.
pub const KID_VAR: &str = "ALCHEMY_JWT_KID";

const BOTH_VARS: &str = "ALCHEMY_JWT_KMS_KEY_VERSION or ALCHEMY_JWT_KID";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlchemyJwtConfig {
    pub key_version: String,
    pub kid: String,
}

/// What the environment says about Alchemy JWT signing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JwtEnv {
    Both(AlchemyJwtConfig),
    Partial { missing: &'static str },
    Unset,
}

impl JwtEnv {
    /// Reads [`KEY_VERSION_VAR`] and [`KID_VAR`]; an empty value counts as
    /// unset.
    pub fn from_env() -> Self {
        Self::from_values(
            std::env::var(KEY_VERSION_VAR).ok(),
            std::env::var(KID_VAR).ok(),
        )
    }

    pub fn from_values(key_version: Option<String>, kid: Option<String>) -> Self {
        let key_version = key_version.filter(|value| !value.is_empty());
        let kid = kid.filter(|value| !value.is_empty());
        match (key_version, kid) {
            (Some(key_version), Some(kid)) => Self::Both(AlchemyJwtConfig { key_version, kid }),
            (None, Some(_)) => Self::Partial {
                missing: KEY_VERSION_VAR,
            },
            (Some(_), None) => Self::Partial { missing: KID_VAR },
            (None, None) => Self::Unset,
        }
    }

    pub(crate) fn missing(&self) -> Option<&'static str> {
        match self {
            Self::Both(_) => None,
            Self::Partial { missing } => Some(missing),
            Self::Unset => Some(BOTH_VARS),
        }
    }
}

/// A bare Alchemy endpoint, `https://<network>.g.alchemy.com/v2`, which
/// authenticates by bearer JWT instead of a key in the path.
pub(crate) fn is_alchemy_jwt_url(url: &Url) -> bool {
    url.scheme() == "https"
        && url.username().is_empty()
        && url.password().is_none()
        && url.port().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
        && url
            .domain()
            .and_then(|host| host.strip_suffix(".g.alchemy.com"))
            .is_some_and(|network| !network.is_empty())
        && matches!(url.path(), "/v2" | "/v2/")
}

/// An Alchemy URL that can authenticate neither way: not the bare JWT form
/// and no `/v2/<key>` path, such as `http://`, a trailing-dot host or a
/// missing `/v2`. Every call to it would get 401.
pub(crate) fn is_malformed_alchemy_jwt_url(url: &Url) -> bool {
    let alchemy_host = url.host_str().is_some_and(|host| {
        host.to_ascii_lowercase()
            .trim_end_matches('.')
            .ends_with(".g.alchemy.com")
    });
    alchemy_host && !is_alchemy_jwt_url(url) && !has_path_key(url)
}

/// `/v2/<key>`, with an optional trailing slash.
fn has_path_key(url: &Url) -> bool {
    let path = url.path();
    path.strip_suffix('/')
        .unwrap_or(path)
        .strip_prefix("/v2/")
        .is_some_and(|key| !key.is_empty() && !key.contains('/'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alchemy_jwt_url_rule() {
        let cases = [
            ("https://base-mainnet.g.alchemy.com/v2", true),
            ("https://base-mainnet.g.alchemy.com/v2/", true),
            ("https://base-mainnet.g.alchemy.com:443/v2", true),
            ("https://BASE-MAINNET.G.ALCHEMY.COM/v2", true),
            ("https://base-mainnet.g.alchemy.com/v2/abc123", false),
            ("http://base-mainnet.g.alchemy.com/v2", false),
            ("https://base-mainnet.g.alchemy.com./v2", false),
            ("https://base-mainnet.g.alchemy.com/v3", false),
            ("https://base-mainnet.g.alchemy.com", false),
            ("https://base-mainnet.g.alchemy.com:8443/v2", false),
            ("https://base-mainnet.g.alchemy.com.evil.example/v2", false),
            ("https://evilg.alchemy.com/v2", false),
            ("https://g.alchemy.com/v2", false),
            ("https://base-mainnet.g.alchemy.com/v2?key=abc", false),
            ("https://base-mainnet.g.alchemy.com/v2#frag", false),
            ("https://user:pass@base-mainnet.g.alchemy.com/v2", false),
            ("https://user@base-mainnet.g.alchemy.com/v2", false),
            ("https://mainnet.base.org", false),
        ];
        for (url, expected) in cases {
            assert_eq!(crate::uses_alchemy_jwt(url), expected, "{url}");
        }
        assert!(!crate::uses_alchemy_jwt("not a url"));
    }

    #[test]
    fn malformed_alchemy_jwt_url_rule() {
        let cases = [
            ("http://base-mainnet.g.alchemy.com/v2", true),
            ("https://base-mainnet.g.alchemy.com./v2", true),
            ("https://base-mainnet.g.alchemy.com:8443/v2/", true),
            ("https://base-mainnet.g.alchemy.com/v2?key=abc", true),
            ("https://base-mainnet.g.alchemy.com", true),
            ("https://base-mainnet.g.alchemy.com/v2//", true),
            ("https://base-mainnet.g.alchemy.com/V2", true),
            ("https://base-mainnet.g.alchemy.com/v2/abc123/extra", true),
            ("https://base-mainnet.g.alchemy.com/v2", false),
            ("https://base-mainnet.g.alchemy.com/v2/abc123", false),
            ("https://base-mainnet.g.alchemy.com/v2/abc123/", false),
            ("https://mainnet.base.org/v2", false),
        ];
        for (url, expected) in cases {
            let parsed: Url = url.parse().unwrap();
            assert_eq!(is_malformed_alchemy_jwt_url(&parsed), expected, "{url}");
        }
    }

    #[test]
    fn env_values() {
        let some = |value: &str| Some(value.to_string());
        assert_eq!(
            JwtEnv::from_values(some("projects/p/cryptoKeyVersions/1"), some("kid")),
            JwtEnv::Both(AlchemyJwtConfig {
                key_version: "projects/p/cryptoKeyVersions/1".to_string(),
                kid: "kid".to_string(),
            })
        );
        assert_eq!(
            JwtEnv::from_values(some(""), some("kid")),
            JwtEnv::Partial {
                missing: KEY_VERSION_VAR
            }
        );
        assert_eq!(
            JwtEnv::from_values(some("projects/p/cryptoKeyVersions/1"), None),
            JwtEnv::Partial { missing: KID_VAR }
        );
        assert_eq!(JwtEnv::from_values(None, some("")), JwtEnv::Unset);
        assert_eq!(JwtEnv::from_values(None, None), JwtEnv::Unset);
    }
}
