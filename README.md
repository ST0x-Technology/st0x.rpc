# st0x-rpc

Shared alloy JSON-RPC client for ST0x services. It calls a bare Alchemy endpoint
with an ES256 JWT signed by a Cloud KMS key instead of an API key in the URL.

## Use

```toml
st0x-rpc = { git = "https://github.com/ST0x-Technology/st0x.rpc", tag = "v0.1.0" }
```

```rust
let client = st0x_rpc::connect(&rpc_url).await?;
let provider = ProviderBuilder::new().wallet(wallet).connect_client(client);
```

## Configuration

| Env var                       | Value                                                                                                                                                               |
| ----------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `ALCHEMY_JWT_KMS_KEY_VERSION` | Full KMS key-version name, `projects/<project>/locations/<location>/keyRings/<ring>/cryptoKeys/<key>/cryptoKeyVersions/<n>`. The key must be `EC_SIGN_P256_SHA256`. |
| `ALCHEMY_JWT_KID`             | Key id Alchemy shows for the public key registered with the app.                                                                                                    |

Which mode `connect` picks depends on the URL:

- `https://<network>.g.alchemy.com/v2` (no key, query, port or credentials):
  every request carries `Authorization: Bearer <JWT>`. Both env vars are
  required; without them `connect` fails. Before returning, `connect` builds the
  signer and calls `eth_chainId` within 10 seconds, so a key Alchemy does not
  accept stops startup.
- Any other `http` or `https` URL: requests go out without a bearer token, and
  the env vars are not used. Other schemes, such as `wss`, are refused.

In both modes, errors and logs never contain the URL, redirects are not
followed, and responses may be gzip-compressed and served over HTTP/2.
`connect_with_timeouts` adds connect and per-request time limits; `connect` and
`connect_with` set none.

The JWT has header `{"alg":"ES256","typ":"JWT","kid":<kid>}` and claims
`{"iat":<now>,"exp":<now+600>}`. It is cached; in its last two minutes a
background task mints the next one while requests keep using the cached token.
If KMS fails, the cached token is used until it expires, and KMS is not called
again for 10 seconds.

## Access

KMS is called through its REST API with the access token of the instance's
service account, read from the GCE metadata server. That account needs
`roles/cloudkms.signerVerifier` on the crypto key (or its key ring). For local
runs, `GOOGLE_OAUTH_ACCESS_TOKEN` overrides the metadata server.

## Development

```sh
nix develop -c cargo test
```

`examples/alchemy_chain_id.rs` calls `eth_chainId` on a real Alchemy app; its
header lists what it needs.
