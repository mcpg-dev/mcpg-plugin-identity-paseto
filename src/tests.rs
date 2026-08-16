use mcpg_plugin_protocol::IdentityResolution;
use mcpg_plugin_protocol::types::RequestMetadata;
use mcpg_plugin_sdk::ffi::SyncIdentityResolver;
use serde_json::{Value, json};

use pasetors::claims::Claims;
use pasetors::keys::{AsymmetricKeyPair, Generate, SymmetricKey};
use pasetors::version4::V4;

use super::{PLUGIN_ID, PasetoIdentityPlugin};

const DESCRIPTOR: &str = include_str!("../plugin.yaml");
const ISS: &str = "https://idp.example";

fn build(cfg: Value) -> PasetoIdentityPlugin {
    PasetoIdentityPlugin::from_config_json(&cfg.to_string())
}

fn resolve(p: &PasetoIdentityPlugin, token: &str) -> IdentityResolution {
    let headers = vec![("Authorization".to_owned(), format!("Bearer {token}"))];
    p.resolve_identity(&headers, &RequestMetadata::default(), &json!({}))
}

/// Claims with a 1-hour future expiry (Claims::new sets iat/nbf/exp).
fn claims(iss: &str, aud: &str, sub: &str) -> Claims {
    let mut c = Claims::new().unwrap();
    c.issuer(iss).unwrap();
    c.audience(aud).unwrap();
    c.subject(sub).unwrap();
    c
}

fn public_plugin(kp: &AsymmetricKeyPair<V4>) -> PasetoIdentityPlugin {
    build(json!({
        "issuers": [{
            "issuer": ISS,
            "audiences": ["mcpg"],
            "key": { "kind": "public_hex", "hex": hex::encode(kp.public.as_bytes()) }
        }]
    }))
}

fn local_plugin(sk: &SymmetricKey<V4>) -> PasetoIdentityPlugin {
    build(json!({
        "issuers": [{
            "issuer": ISS,
            "audiences": ["mcpg"],
            "key": { "kind": "local_hex", "hex": hex::encode(sk.as_bytes()) }
        }]
    }))
}

#[test]
fn v4_public_valid_resolves() {
    let kp = AsymmetricKeyPair::<V4>::generate().unwrap();
    let p = public_plugin(&kp);
    let token =
        pasetors::public::sign(&kp.secret, &claims(ISS, "mcpg", "alice"), None, None).unwrap();
    match resolve(&p, &token) {
        IdentityResolution::Resolved { identity } => {
            assert_eq!(identity.subject_id.as_deref(), Some("alice"));
            assert_eq!(identity.trust_level, "verified");
            assert_eq!(identity.auth_provider.as_deref(), Some("paseto"));
            assert_eq!(identity.issuer.as_deref(), Some(ISS));
        }
        other => panic!("expected Resolved, got {other:?}"),
    }
}

#[test]
fn v4_local_valid_resolves() {
    let sk = SymmetricKey::<V4>::generate().unwrap();
    let p = local_plugin(&sk);
    let token = pasetors::local::encrypt(&sk, &claims(ISS, "mcpg", "bob"), None, None).unwrap();
    match resolve(&p, &token) {
        IdentityResolution::Resolved { identity } => {
            assert_eq!(identity.subject_id.as_deref(), Some("bob"))
        }
        other => panic!("expected Resolved, got {other:?}"),
    }
}

#[test]
fn wrong_public_key_invalid() {
    let signer = AsymmetricKeyPair::<V4>::generate().unwrap();
    let other = AsymmetricKeyPair::<V4>::generate().unwrap();
    let p = public_plugin(&other); // configured with a DIFFERENT public key
    let token =
        pasetors::public::sign(&signer.secret, &claims(ISS, "mcpg", "alice"), None, None).unwrap();
    assert!(matches!(
        resolve(&p, &token),
        IdentityResolution::Invalid { .. }
    ));
}

#[test]
fn wrong_issuer_invalid() {
    let kp = AsymmetricKeyPair::<V4>::generate().unwrap();
    let p = public_plugin(&kp);
    let token = pasetors::public::sign(
        &kp.secret,
        &claims("https://evil", "mcpg", "alice"),
        None,
        None,
    )
    .unwrap();
    assert!(matches!(
        resolve(&p, &token),
        IdentityResolution::Invalid { .. }
    ));
}

#[test]
fn wrong_audience_invalid() {
    let kp = AsymmetricKeyPair::<V4>::generate().unwrap();
    let p = public_plugin(&kp);
    let token =
        pasetors::public::sign(&kp.secret, &claims(ISS, "other-svc", "alice"), None, None).unwrap();
    assert!(matches!(
        resolve(&p, &token),
        IdentityResolution::Invalid { .. }
    ));
}

#[test]
fn multi_audience_membership_allowed() {
    let kp = AsymmetricKeyPair::<V4>::generate().unwrap();
    let p = build(json!({
        "issuers": [{
            "issuer": ISS,
            "audiences": ["svc-a", "svc-b"],
            "key": { "kind": "public_hex", "hex": hex::encode(kp.public.as_bytes()) }
        }]
    }));
    let ok =
        pasetors::public::sign(&kp.secret, &claims(ISS, "svc-b", "alice"), None, None).unwrap();
    assert!(matches!(
        resolve(&p, &ok),
        IdentityResolution::Resolved { .. }
    ));
    let bad =
        pasetors::public::sign(&kp.secret, &claims(ISS, "svc-c", "alice"), None, None).unwrap();
    assert!(matches!(
        resolve(&p, &bad),
        IdentityResolution::Invalid { .. }
    ));
}

#[test]
fn missing_subject_invalid() {
    let kp = AsymmetricKeyPair::<V4>::generate().unwrap();
    let p = public_plugin(&kp);
    let mut c = Claims::new().unwrap();
    c.issuer(ISS).unwrap();
    c.audience("mcpg").unwrap();
    let token = pasetors::public::sign(&kp.secret, &c, None, None).unwrap();
    match resolve(&p, &token) {
        IdentityResolution::Invalid { reason, .. } => {
            assert!(reason.contains("subject"), "{reason}")
        }
        other => panic!("expected Invalid, got {other:?}"),
    }
}

#[test]
fn expired_token_invalid() {
    let kp = AsymmetricKeyPair::<V4>::generate().unwrap();
    let p = public_plugin(&kp);
    let mut c = claims(ISS, "mcpg", "alice");
    c.expiration("2000-01-01T00:00:00Z").unwrap();
    let token = pasetors::public::sign(&kp.secret, &c, None, None).unwrap();
    assert!(matches!(
        resolve(&p, &token),
        IdentityResolution::Invalid { .. }
    ));
}

#[test]
fn claim_mapping_projects_roles_groups_scopes_attrs() {
    let kp = AsymmetricKeyPair::<V4>::generate().unwrap();
    let p = build(json!({
        "issuers": [{
            "issuer": ISS,
            "audiences": ["mcpg"],
            "key": { "kind": "public_hex", "hex": hex::encode(kp.public.as_bytes()) },
            "claim_mappings": {
                "role_claim_paths": ["realm_access.roles"],
                "group_claim_paths": ["groups"],
                "scope_claim_paths": ["scope"],
                "attribute_claim_mappings": { "tenant": "tenant" }
            }
        }]
    }));
    let mut c = claims(ISS, "mcpg", "alice");
    c.add_additional("realm_access", json!({ "roles": ["admin", "dev"] }))
        .unwrap();
    c.add_additional("groups", json!(["g1", "g2"])).unwrap();
    c.add_additional("scope", "read write").unwrap();
    c.add_additional("tenant", "acme").unwrap();
    let token = pasetors::public::sign(&kp.secret, &c, None, None).unwrap();
    match resolve(&p, &token) {
        IdentityResolution::Resolved { identity } => {
            assert_eq!(identity.roles, vec!["admin", "dev"]);
            assert_eq!(identity.groups, vec!["g1", "g2"]);
            assert_eq!(identity.scopes, vec!["read", "write"]);
            assert_eq!(identity.attributes.get("tenant").unwrap(), "acme");
        }
        other => panic!("expected Resolved, got {other:?}"),
    }
}

#[test]
fn multi_issuer_routes_to_local() {
    let kp = AsymmetricKeyPair::<V4>::generate().unwrap();
    let sk = SymmetricKey::<V4>::generate().unwrap();
    let p = build(json!({
        "issuers": [
            { "issuer": "https://a", "audiences": ["mcpg"],
              "key": { "kind": "public_hex", "hex": hex::encode(kp.public.as_bytes()) } },
            { "issuer": "https://b", "audiences": ["mcpg"],
              "key": { "kind": "local_hex", "hex": hex::encode(sk.as_bytes()) } }
        ]
    }));
    let token =
        pasetors::local::encrypt(&sk, &claims("https://b", "mcpg", "bob"), None, None).unwrap();
    match resolve(&p, &token) {
        IdentityResolution::Resolved { identity } => {
            assert_eq!(identity.issuer.as_deref(), Some("https://b"));
            assert_eq!(identity.subject_id.as_deref(), Some("bob"));
        }
        other => panic!("expected Resolved, got {other:?}"),
    }
}

#[test]
fn local_token_rejected_by_public_issuer() {
    let kp = AsymmetricKeyPair::<V4>::generate().unwrap();
    let sk = SymmetricKey::<V4>::generate().unwrap();
    let p = public_plugin(&kp); // public-only issuer
    let token = pasetors::local::encrypt(&sk, &claims(ISS, "mcpg", "bob"), None, None).unwrap();
    assert!(matches!(
        resolve(&p, &token),
        IdentityResolution::Invalid { .. }
    ));
}

#[test]
fn header_asserted_trust_propagates() {
    let kp = AsymmetricKeyPair::<V4>::generate().unwrap();
    let p = build(json!({
        "issuers": [{
            "issuer": ISS, "audiences": ["mcpg"],
            "key": { "kind": "public_hex", "hex": hex::encode(kp.public.as_bytes()) }
        }],
        "resolution": { "trust_level": "header_asserted" }
    }));
    let token =
        pasetors::public::sign(&kp.secret, &claims(ISS, "mcpg", "alice"), None, None).unwrap();
    match resolve(&p, &token) {
        IdentityResolution::Resolved { identity } => {
            assert_eq!(identity.trust_level, "header_asserted");
            assert_eq!(identity.kind, "header_asserted");
        }
        other => panic!("expected Resolved, got {other:?}"),
    }
}

#[test]
fn custom_header_token_source() {
    let kp = AsymmetricKeyPair::<V4>::generate().unwrap();
    let p = build(json!({
        "token_source": { "kind": "custom_header", "header_name": "X-Token" },
        "issuers": [{
            "issuer": ISS, "audiences": ["mcpg"],
            "key": { "kind": "public_hex", "hex": hex::encode(kp.public.as_bytes()) }
        }]
    }));
    let token =
        pasetors::public::sign(&kp.secret, &claims(ISS, "mcpg", "alice"), None, None).unwrap();
    let headers = vec![("X-Token".to_owned(), token)];
    assert!(matches!(
        p.resolve_identity(&headers, &RequestMetadata::default(), &json!({})),
        IdentityResolution::Resolved { .. }
    ));
}

#[test]
fn no_token_is_none_and_empty_bearer_is_none() {
    let kp = AsymmetricKeyPair::<V4>::generate().unwrap();
    let p = public_plugin(&kp);
    assert!(matches!(
        p.resolve_identity(&[], &RequestMetadata::default(), &json!({})),
        IdentityResolution::None
    ));
    let headers = vec![("Authorization".to_owned(), "Bearer ".to_owned())];
    assert!(matches!(
        p.resolve_identity(&headers, &RequestMetadata::default(), &json!({})),
        IdentityResolution::None
    ));
}

#[test]
fn descriptor_and_manifest_are_well_formed() {
    use mcpg_plugin_protocol::PluginClass;
    assert!(DESCRIPTOR.contains("id: dev.mcpg.identity.paseto"));
    assert!(DESCRIPTOR.contains("class: identity_provider"));
    assert!(DESCRIPTOR.contains("required_capabilities: []"));
    let kp = AsymmetricKeyPair::<V4>::generate().unwrap();
    let p = public_plugin(&kp);
    let m = SyncIdentityResolver::manifest(&p);
    assert_eq!(m.id, PLUGIN_ID);
    assert_eq!(m.plugin_class, PluginClass::IdentityProvider);
    assert!(m.required_capabilities.is_empty());
}

#[test]
#[should_panic(expected = "refusing to load")]
fn factory_panics_on_bad_config() {
    let _ = PasetoIdentityPlugin::from_config_json("not-json");
}
