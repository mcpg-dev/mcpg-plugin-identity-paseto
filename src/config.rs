//! Operator-supplied configuration for `dev.mcpg.identity.paseto`.
//!
//! Mirrors the JWT plugin's token-source + claim-mapping shape, for PASETO v4
//! tokens verified against STATIC keys. All structs reject unknown fields.

use std::collections::BTreeMap;

use anyhow::{Context, Result};
use serde::Deserialize;

/// Length in bytes of a v4 key (Ed25519 public key or XChaCha20 symmetric key).
const V4_KEY_BYTES: usize = 32;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PasetoConfig {
    #[serde(default)]
    pub token_source: TokenSourceConfig,
    pub issuers: Vec<IssuerConfig>,
    #[serde(default)]
    pub resolution: ResolutionConfig,
}

impl PasetoConfig {
    pub fn parse(s: &str) -> Result<Self> {
        let cfg: Self = serde_json::from_str(s).context("invalid identity.paseto config JSON")?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> Result<()> {
        if self.issuers.is_empty() {
            return Err(anyhow::anyhow!(
                "identity.paseto: `issuers` must be non-empty"
            ));
        }
        let mut seen = std::collections::HashSet::new();
        for (i, issuer) in self.issuers.iter().enumerate() {
            issuer
                .validate()
                .with_context(|| format!("identity.paseto: issuers[{i}]"))?;
            if !seen.insert(issuer.issuer.clone()) {
                return Err(anyhow::anyhow!(
                    "identity.paseto: duplicate issuer '{}'",
                    issuer.issuer
                ));
            }
        }
        self.resolution.validate()?;
        Ok(())
    }
}

// --- token source (identical shape to the JWT plugin) -----------------------

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenSourceConfig {
    #[serde(default = "default_token_source_kind")]
    pub kind: TokenSourceKind,
    #[serde(default)]
    pub header_name: Option<String>,
    #[serde(default)]
    pub header_prefix: Option<String>,
}

impl Default for TokenSourceConfig {
    fn default() -> Self {
        Self {
            kind: TokenSourceKind::AuthorizationBearer,
            header_name: None,
            header_prefix: None,
        }
    }
}

impl TokenSourceConfig {
    pub fn effective_header_name(&self) -> &str {
        match self.kind {
            TokenSourceKind::AuthorizationBearer => "authorization",
            TokenSourceKind::CustomHeader => self.header_name.as_deref().unwrap_or("authorization"),
        }
    }

    pub fn effective_header_prefix(&self) -> &str {
        if let Some(ref prefix) = self.header_prefix {
            return prefix;
        }
        match self.kind {
            TokenSourceKind::AuthorizationBearer => "Bearer ",
            TokenSourceKind::CustomHeader => "",
        }
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TokenSourceKind {
    AuthorizationBearer,
    CustomHeader,
}

fn default_token_source_kind() -> TokenSourceKind {
    TokenSourceKind::AuthorizationBearer
}

// --- issuer + key material --------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssuerConfig {
    /// Exact `iss` claim to match.
    pub issuer: String,
    #[serde(default)]
    pub audiences: Vec<String>,
    /// Opt out of audience validation. Empty `audiences` without this is a hard
    /// error (a token minted for another service would verify).
    #[serde(default)]
    pub allow_any_audience: bool,
    /// Verification key. The key kind selects the PASETO purpose:
    /// `public_hex` → v4.public (Ed25519 verify), `local_hex` → v4.local
    /// (XChaCha20 decrypt).
    pub key: KeyMaterialConfig,
    #[serde(default)]
    pub claim_mappings: ClaimMappingConfig,
}

impl IssuerConfig {
    pub fn validate(&self) -> Result<()> {
        if self.issuer.trim().is_empty() {
            return Err(anyhow::anyhow!("issuer must not be empty"));
        }
        if self.audiences.is_empty() && !self.allow_any_audience {
            return Err(anyhow::anyhow!(
                "audiences is empty — refusing to skip audience validation (a token minted for \
                 another service would be accepted). Set `audiences`, or opt in with \
                 `allow_any_audience: true`"
            ));
        }
        self.key.validate()?;
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum KeyMaterialConfig {
    /// v4.public verify key: a 32-byte Ed25519 public key, hex-encoded.
    PublicHex { hex: String },
    /// v4.local symmetric key: 32 bytes, hex-encoded.
    LocalHex { hex: String },
}

impl KeyMaterialConfig {
    /// Decode the configured key to its raw bytes (exactly 32).
    pub fn key_bytes(&self) -> Result<Vec<u8>> {
        let h = match self {
            KeyMaterialConfig::PublicHex { hex } | KeyMaterialConfig::LocalHex { hex } => hex,
        };
        let bytes = hex::decode(h.trim()).context("key hex is not valid hex")?;
        if bytes.len() != V4_KEY_BYTES {
            return Err(anyhow::anyhow!(
                "key must decode to {V4_KEY_BYTES} bytes, got {}",
                bytes.len()
            ));
        }
        Ok(bytes)
    }

    fn validate(&self) -> Result<()> {
        self.key_bytes().map(|_| ())
    }
}

// --- claim mappings (identical to the JWT plugin) ---------------------------

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimMappingConfig {
    #[serde(default = "default_subject_claim")]
    pub subject_claim: String,
    #[serde(default)]
    pub group_claim_paths: Vec<String>,
    #[serde(default)]
    pub role_claim_paths: Vec<String>,
    #[serde(default = "default_scope_claim_paths")]
    pub scope_claim_paths: Vec<String>,
    #[serde(default)]
    pub attribute_claim_mappings: BTreeMap<String, String>,
}

impl Default for ClaimMappingConfig {
    fn default() -> Self {
        Self {
            subject_claim: default_subject_claim(),
            group_claim_paths: vec![],
            role_claim_paths: vec![],
            scope_claim_paths: default_scope_claim_paths(),
            attribute_claim_mappings: BTreeMap::new(),
        }
    }
}

fn default_subject_claim() -> String {
    "sub".to_owned()
}
fn default_scope_claim_paths() -> Vec<String> {
    vec!["scope".to_owned(), "scp".to_owned()]
}

// --- resolution -------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolutionConfig {
    #[serde(default = "default_trust_level")]
    pub trust_level: String,
    #[serde(default = "default_auth_provider_label")]
    pub auth_provider_label: String,
}

impl Default for ResolutionConfig {
    fn default() -> Self {
        Self {
            trust_level: default_trust_level(),
            auth_provider_label: default_auth_provider_label(),
        }
    }
}

impl ResolutionConfig {
    fn validate(&self) -> Result<()> {
        if !matches!(self.trust_level.as_str(), "verified" | "header_asserted") {
            return Err(anyhow::anyhow!(
                "resolution.trust_level must be `verified` or `header_asserted`, got '{}'",
                self.trust_level
            ));
        }
        Ok(())
    }
}

fn default_trust_level() -> String {
    "verified".to_owned()
}
fn default_auth_provider_label() -> String {
    "paseto".to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn pub_issuer() -> serde_json::Value {
        json!({
            "issuer": "https://idp.example",
            "audiences": ["mcpg"],
            "key": { "kind": "public_hex", "hex": "0".repeat(64) }
        })
    }

    #[test]
    fn minimal_config_parses() {
        let cfg = PasetoConfig::parse(&json!({ "issuers": [pub_issuer()] }).to_string()).unwrap();
        assert_eq!(cfg.issuers.len(), 1);
        assert_eq!(cfg.resolution.auth_provider_label, "paseto");
    }

    #[test]
    fn deny_unknown_and_empty_issuers() {
        assert!(
            PasetoConfig::parse(&json!({ "issuers": [pub_issuer()], "x": 1 }).to_string()).is_err()
        );
        assert!(PasetoConfig::parse(&json!({ "issuers": [] }).to_string()).is_err());
    }

    #[test]
    fn duplicate_issuer_rejected() {
        let err =
            PasetoConfig::parse(&json!({ "issuers": [pub_issuer(), pub_issuer()] }).to_string())
                .unwrap_err()
                .to_string();
        assert!(err.contains("duplicate issuer"), "{err}");
    }

    #[test]
    fn bad_key_length_rejected() {
        let mut iss = pub_issuer();
        iss["key"] = json!({ "kind": "public_hex", "hex": "abcd" });
        assert!(PasetoConfig::parse(&json!({ "issuers": [iss] }).to_string()).is_err());
    }

    #[test]
    fn non_hex_key_rejected() {
        let mut iss = pub_issuer();
        iss["key"] = json!({ "kind": "local_hex", "hex": "z".repeat(64) });
        assert!(PasetoConfig::parse(&json!({ "issuers": [iss] }).to_string()).is_err());
    }

    #[test]
    fn empty_audiences_needs_opt_in() {
        let mut iss = pub_issuer();
        iss.as_object_mut()
            .unwrap()
            .insert("audiences".into(), json!([]));
        assert!(PasetoConfig::parse(&json!({ "issuers": [iss.clone()] }).to_string()).is_err());
        iss.as_object_mut()
            .unwrap()
            .insert("allow_any_audience".into(), json!(true));
        PasetoConfig::parse(&json!({ "issuers": [iss] }).to_string()).unwrap();
    }

    #[test]
    fn bad_trust_level_rejected() {
        let v = json!({ "issuers": [pub_issuer()], "resolution": { "trust_level": "root" } });
        assert!(PasetoConfig::parse(&v.to_string()).is_err());
    }
}
