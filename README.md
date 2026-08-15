# PASETO Identity Resolver (`dev.mcpg.identity.paseto`)

An **identity_provider** that resolves the caller's identity from a **PASETO v4**
token verified against operator-supplied **static keys** — the PASETO sibling of
`dev.mcpg.identity.jwt`. Supports both v4 purposes:

- **v4.public** — Ed25519 signature, verified with a public key.
- **v4.local** — XChaCha20-Poly1305, decrypted with a shared symmetric key.

It validates the registered claims (`exp` always; `iss` and `aud` when
configured), then maps token claims to `subject_id` / roles / groups / scopes /
attributes. **No network** — pure synchronous compute; keys are parsed once at
boot. The plugin **fails closed**: a bad config or an unloadable key refuses to
register.

## Configuration

| Field | Type | Default | Description |
|---|---|---|---|
| `token_source` | object | `Authorization: Bearer` | Where the token comes from (`kind`: `authorization_bearer` \| `custom_header`, `header_name`, `header_prefix`). |
| `issuers` | array | *(required, ≥1)* | One or more issuer verification profiles. |
| `resolution.trust_level` | `verified` \| `header_asserted` | `verified` | Trust bucket for a resolved identity. |
| `resolution.auth_provider_label` | string | `paseto` | `auth_provider` on the resolved identity. |

### Each `issuers[]` entry

| Field | Type | Default | Description |
|---|---|---|---|
| `issuer` | string | *(required)* | Exact `iss` claim to match. |
| `audiences` | array of string | `[]` | Accepted `aud` values. Empty requires `allow_any_audience: true`. |
| `allow_any_audience` | bool | `false` | Opt out of audience validation (leave false in production). |
| `key` | object | *(required)* | Verification key (see below). The key kind selects the PASETO purpose. |
| `claim_mappings` | object | *(see below)* | How claims map to the resolved identity. |

### `key` (one of)

| `kind` | Field | Purpose |
|---|---|---|
| `public_hex` | `hex` (32-byte Ed25519 public key, hex) | v4.public — verify a signed token. |
| `local_hex` | `hex` (32-byte symmetric key, hex) | v4.local — decrypt an encrypted token. |

### `claim_mappings`

| Field | Default | Description |
|---|---|---|
| `subject_claim` | `sub` | Claim → `subject_id` (missing/empty ⇒ token rejected). |
| `role_claim_paths` | `[]` | Dotted paths (e.g. `realm_access.roles`) → roles. |
| `group_claim_paths` | `[]` | → groups. |
| `scope_claim_paths` | `["scope","scp"]` | → scopes (space-separated strings are split). |
| `attribute_claim_mappings` | `{}` | `{claim → attribute_name}` string claims → attributes. |

All structs reject unknown fields.

## Example

```yaml
plugins:
  - id: dev.mcpg.identity.paseto
    class: identity_provider
    source: { oci: "oci://ghcr.io/mcpg-dev/plugins/identity-paseto:protocol-1" }
    config:
      issuers:
        - issuer: https://auth.partner.example
          audiences: ["https://gateway.mcpg.dev"]
          key:
            kind: public_hex
            hex: ${env.PARTNER_PASETO_V4_PUBLIC_HEX}
          claim_mappings:
            role_claim_paths: ["roles"]
            attribute_claim_mappings: { tenant: "tenant" }
```

## Notes

- `exp` is **required** by default (PASETO secure default) — a token without an
  expiry is rejected.
- For multiple acceptable audiences the token's `aud` must be one of the list.
- Distinct from `dev.mcpg.identity.jwt` (verifies JWTs) — same trait + config
  shape, different token format.
- Pure-Rust (`pasetors` on orion + ed25519-compact, MIT), rustls-clean,
  `default-members`. No host capabilities required.

## Building and testing

```sh
cargo build --release   # builds the plugin cdylib into target/release/
cargo test
```
