//! `dev.mcpg.identity.paseto` — PASETO v4 identity_provider.
//!
//! Verifies caller-presented PASETO **v4.public** (Ed25519-signed) or
//! **v4.local** (XChaCha20-encrypted) tokens against operator-supplied STATIC
//! keys, validates the registered claims (`exp`/`iss`/`aud`), and maps token
//! claims to `subject_id` / roles / groups / scopes / attributes. No network —
//! pure synchronous compute. Keys are parsed once at boot. Fails closed on bad
//! config (a misconfigured identity resolver is a security hole).

pub mod config;

use std::sync::Arc;

use mcpg_plugin_protocol::types::RequestMetadata;
use mcpg_plugin_protocol::{
    IdentityResolution, PluginIdentity, PluginManifest, firstparty_manifest,
};
use mcpg_plugin_sdk::ffi::SyncIdentityResolver;
use pasetors::claims::ClaimsValidationRules;
use pasetors::keys::{AsymmetricPublicKey, SymmetricKey};
use pasetors::token::{Local, Public, UntrustedToken};
use pasetors::version4::V4;
use serde_json::Value;
use std::collections::BTreeMap;
use tracing::{info_span, warn};

pub use config::{
    ClaimMappingConfig, IssuerConfig, KeyMaterialConfig, PasetoConfig, ResolutionConfig,
    TokenSourceConfig,
};

const PLUGIN_ID: &str = "dev.mcpg.identity.paseto";

enum CompiledKey {
    Public(AsymmetricPublicKey<V4>),
    Local(SymmetricKey<V4>),
}

struct CompiledIssuer {
    issuer: String,
    audiences: Vec<String>,
    key: CompiledKey,
    claim_mappings: ClaimMappingConfig,
}

pub struct PasetoIdentityPlugin {
    inner: Arc<Inner>,
}

struct Inner {
    manifest: PluginManifest,
    token_source: TokenSourceConfig,
    issuers: Vec<CompiledIssuer>,
    resolution: ResolutionConfig,
}

fn compile_issuer(ic: IssuerConfig) -> anyhow::Result<CompiledIssuer> {
    let bytes = ic.key.key_bytes()?;
    let key = match &ic.key {
        KeyMaterialConfig::PublicHex { .. } => CompiledKey::Public(
            AsymmetricPublicKey::<V4>::from(&bytes)
                .map_err(|e| anyhow::anyhow!("invalid v4.public key: {e}"))?,
        ),
        KeyMaterialConfig::LocalHex { .. } => CompiledKey::Local(
            SymmetricKey::<V4>::from(&bytes)
                .map_err(|e| anyhow::anyhow!("invalid v4.local key: {e}"))?,
        ),
    };
    Ok(CompiledIssuer {
        issuer: ic.issuer,
        audiences: ic.audiences,
        key,
        claim_mappings: ic.claim_mappings,
    })
}

impl PasetoIdentityPlugin {
    pub fn from_config_json(config_json: &str) -> Self {
        let cfg = PasetoConfig::parse(config_json).unwrap_or_else(|err| {
            tracing::error!(
                plugin_id = PLUGIN_ID,
                error = %err,
                "identity.paseto: config parse failed; refusing to register"
            );
            panic!(
                "identity.paseto config parse failed: {err}. A misconfigured identity \
                 resolver is a security hole; refusing to load rather than falling back \
                 to defaults. Fix operator config and retry."
            )
        });

        let issuers = cfg
            .issuers
            .into_iter()
            .map(compile_issuer)
            .collect::<anyhow::Result<Vec<_>>>()
            .unwrap_or_else(|err| {
                tracing::error!(
                    plugin_id = PLUGIN_ID,
                    error = %err,
                    "identity.paseto: key compile failed; refusing to register"
                );
                panic!("identity.paseto config parse failed: {err}. Fix operator config and retry.")
            });

        tracing::info!(
            plugin_id = PLUGIN_ID,
            issuers_loaded = issuers.len(),
            "identity.paseto: registry compiled"
        );

        Self {
            inner: Arc::new(Inner {
                manifest: firstparty_manifest! {
                    id: PLUGIN_ID,
                    name: "PASETO Identity Resolver",
                    class: IdentityProvider,
                },
                token_source: cfg.token_source,
                issuers,
                resolution: cfg.resolution,
            }),
        }
    }
}

fn record_resolve_outcome(result: &IdentityResolution, elapsed: std::time::Duration) {
    let outcome = match result {
        IdentityResolution::Resolved { .. } => "resolved",
        IdentityResolution::None => "none",
        IdentityResolution::Invalid { .. } => "invalid",
    };
    metrics::counter!("mcpg_identity_paseto_resolutions_total", "outcome" => outcome).increment(1);
    metrics::histogram!("mcpg_identity_paseto_resolve_ms").record(elapsed.as_millis() as f64);
    if let IdentityResolution::Invalid { reason } = result {
        warn!(reason = %reason, "identity.paseto: invalid token");
    }
}

fn extract_token(token_source: &TokenSourceConfig, headers: &[(String, String)]) -> Option<String> {
    let value = lookup_header(headers, token_source.effective_header_name())?;
    let prefix = token_source.effective_header_prefix();
    let rest = if prefix.is_empty() {
        Some(value)
    } else {
        strip_ascii_prefix(value, prefix)
    }?;
    if rest.is_empty() {
        None
    } else {
        Some(rest.to_owned())
    }
}

fn lookup_header<'a>(headers: &'a [(String, String)], target: &str) -> Option<&'a str> {
    headers
        .iter()
        .find_map(|(name, value)| name.eq_ignore_ascii_case(target).then_some(value.as_str()))
}

fn strip_ascii_prefix<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    if s.len() < prefix.len() {
        return None;
    }
    let (head, tail) = s.split_at(prefix.len());
    head.eq_ignore_ascii_case(prefix).then_some(tail)
}

fn resolve(inner: &Inner, headers: &[(String, String)]) -> IdentityResolution {
    let token = match extract_token(&inner.token_source, headers) {
        Some(t) => t,
        None => return IdentityResolution::None,
    };
    // The `iss`/key live inside the signed/encrypted payload, so route by trying
    // each configured issuer; signature/decryption + issuer-binding gate
    // acceptance. First success wins.
    let mut last = IdentityResolution::Invalid {
        reason: "no configured issuer accepted the token".to_owned(),
    };
    for ci in &inner.issuers {
        match verify_against_issuer(ci, &token, &inner.resolution) {
            resolved @ IdentityResolution::Resolved { .. } => return resolved,
            other => last = other,
        }
    }
    last
}

fn verify_against_issuer(
    ci: &CompiledIssuer,
    token: &str,
    resolution: &ResolutionConfig,
) -> IdentityResolution {
    let mut rules = ClaimsValidationRules::new();
    rules.validate_issuer_with(&ci.issuer);
    if ci.audiences.len() == 1 {
        rules.validate_audience_with(&ci.audiences[0]);
    }

    let trusted = match &ci.key {
        CompiledKey::Public(pk) => match UntrustedToken::<Public, V4>::try_from(token) {
            Ok(ut) => pasetors::public::verify(pk, &ut, &rules, None, None),
            Err(e) => {
                return IdentityResolution::Invalid {
                    reason: format!("not a v4.public token for issuer '{}': {e}", ci.issuer),
                };
            }
        },
        CompiledKey::Local(sk) => match UntrustedToken::<Local, V4>::try_from(token) {
            Ok(ut) => pasetors::local::decrypt(sk, &ut, &rules, None, None),
            Err(e) => {
                return IdentityResolution::Invalid {
                    reason: format!("not a v4.local token for issuer '{}': {e}", ci.issuer),
                };
            }
        },
    };

    let trusted = match trusted {
        Ok(t) => t,
        Err(e) => {
            return IdentityResolution::Invalid {
                reason: format!("token verification failed for issuer '{}': {e}", ci.issuer),
            };
        }
    };

    let claims = match trusted.payload_claims() {
        Some(c) => c,
        None => {
            return IdentityResolution::Invalid {
                reason: "verified token carried no claims".to_owned(),
            };
        }
    };
    // `Claims` serialises to its JSON object via `to_string`; parse that back to
    // a `Value` so the dotted-path claim mappers below can navigate it.
    let val: Value = match claims
        .to_string()
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
    {
        Some(v) => v,
        None => {
            return IdentityResolution::Invalid {
                reason: "could not read verified token claims".to_owned(),
            };
        }
    };

    // Multiple acceptable audiences: pasetors validates only one expected value,
    // so check membership manually here.
    if ci.audiences.len() > 1 {
        let ok = val
            .get("aud")
            .and_then(|a| a.as_str())
            .map(|s| ci.audiences.iter().any(|x| x == s))
            .unwrap_or(false);
        if !ok {
            return IdentityResolution::Invalid {
                reason: format!("audience not allowed for issuer '{}'", ci.issuer),
            };
        }
    }

    map_claims(ci, &val, resolution)
}

fn map_claims(
    ci: &CompiledIssuer,
    val: &Value,
    resolution: &ResolutionConfig,
) -> IdentityResolution {
    let m = &ci.claim_mappings;
    let subject_id = match extract_string_claim(val, &m.subject_claim) {
        Some(s) if !s.trim().is_empty() => s,
        _ => {
            return IdentityResolution::Invalid {
                reason: format!("missing or empty '{}' (subject) claim", m.subject_claim),
            };
        }
    };
    let attributes = {
        let mut attrs = BTreeMap::new();
        for (claim_name, attr_name) in &m.attribute_claim_mappings {
            if let Some(v) = extract_string_claim(val, claim_name) {
                attrs.insert(attr_name.clone(), v);
            }
        }
        attrs
    };
    IdentityResolution::Resolved {
        identity: PluginIdentity {
            kind: resolution.trust_level.clone(),
            trust_level: resolution.trust_level.clone(),
            subject_id: Some(subject_id),
            auth_provider: Some(resolution.auth_provider_label.clone()),
            issuer: Some(ci.issuer.clone()),
            roles: extract_string_list_claims(val, &m.role_claim_paths),
            groups: extract_string_list_claims(val, &m.group_claim_paths),
            scopes: extract_string_list_claims(val, &m.scope_claim_paths),
            attributes,
        },
    }
}

fn extract_string_claim(claims: &Value, path: &str) -> Option<String> {
    resolve_json_path(claims, path)?.as_str().map(String::from)
}

fn extract_string_list_claims(claims: &Value, paths: &[String]) -> Vec<String> {
    let mut result = Vec::new();
    for path in paths {
        if let Some(value) = resolve_json_path(claims, path) {
            match value {
                Value::Array(arr) => {
                    for item in arr {
                        if let Some(s) = item.as_str() {
                            result.push(s.to_owned());
                        }
                    }
                }
                Value::String(s) => {
                    for part in s.split_whitespace() {
                        result.push(part.to_owned());
                    }
                }
                _ => {}
            }
        }
    }
    result
}

fn resolve_json_path<'a>(value: &'a Value, path: &str) -> Option<&'a Value> {
    let mut current = value;
    for segment in path.split('.') {
        current = current.get(segment)?;
    }
    Some(current)
}

impl SyncIdentityResolver for PasetoIdentityPlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.inner.manifest
    }

    fn resolve_identity(
        &self,
        headers: &[(String, String)],
        _metadata: &RequestMetadata,
        _config: &Value,
    ) -> IdentityResolution {
        let _span = info_span!("identity_paseto_resolve", plugin_id = PLUGIN_ID).entered();
        let started = std::time::Instant::now();
        let result = resolve(&self.inner, headers);
        record_resolve_outcome(&result, started.elapsed());
        result
    }
}

#[cfg(any(feature = "cdylib-export", feature = "static-firstparty"))]
mcpg_plugin_sdk::declare_plugin! {
    plugin_id: "dev.mcpg.identity.paseto",
    plugin_version: env!("CARGO_PKG_VERSION"),
    descriptor_yaml: include_str!("../plugin.yaml"),
    capabilities: &[],
    entities: [
        identity as id {
            inner_name: "",
            plugin_type: PasetoIdentityPlugin,
            factory: |cfg: &str, _host: ::mcpg_plugin_sdk::HostHandle| -> PasetoIdentityPlugin {
                PasetoIdentityPlugin::from_config_json(cfg)
            },
        }
    ],
}

#[cfg(test)]
mod tests;
