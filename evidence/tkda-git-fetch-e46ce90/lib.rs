use std::net::IpAddr;

use thiserror::Error;
use url::{Host, Url};

pub const MAX_REMOTE_URL_CHARS: usize = 2_048;
pub const MAX_REF_CHARS: usize = 256;
pub const MAX_PACK_BYTES: u64 = 768 * 1024 * 1024;
pub const MAX_BLOB_BYTES: u64 = 16 * 1024 * 1024;
pub const MAX_TREE_ENTRIES: u64 = 20_000;
pub const MAX_CHECKOUT_BYTES: u64 = 512 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FetchRequest {
    pub repository_url: String,
    pub requested_ref: String,
    pub resolved_commit_oid: String,
    /// Resolver output that the provider adapter must pin for the fetch.
    pub resolved_remote_ips: Vec<IpAddr>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FetchPolicy {
    pub allow_ssh: bool,
    pub allow_submodules: bool,
    pub allow_lfs: bool,
    pub max_pack_bytes: u64,
    pub max_blob_bytes: u64,
    pub max_tree_entries: u64,
    pub max_checkout_bytes: u64,
}

impl Default for FetchPolicy {
    fn default() -> Self {
        return Self {
            allow_ssh: false,
            allow_submodules: false,
            allow_lfs: false,
            max_pack_bytes: MAX_PACK_BYTES,
            max_blob_bytes: MAX_BLOB_BYTES,
            max_tree_entries: MAX_TREE_ENTRIES,
            max_checkout_bytes: MAX_CHECKOUT_BYTES,
        };
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FeaturePolicy {
    Deny,
    Allow,
}

impl FeaturePolicy {
    #[must_use]
    pub fn from_allowed(allowed: bool) -> Self {
        if allowed {
            return Self::Allow;
        }
        return Self::Deny;
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitFetchPlan {
    pub repository_url: String,
    pub requested_ref: String,
    pub commit_oid: String,
    /// Public IPs admitted for this exact fetch. The adapter must connect only
    /// to this set and must not re-resolve the hostname after admission.
    pub connect_ips: Vec<IpAddr>,
    pub hooks: FeaturePolicy,
    pub filters: FeaturePolicy,
    pub credential_helpers: FeaturePolicy,
    pub submodules: FeaturePolicy,
    pub lfs: FeaturePolicy,
    pub max_pack_bytes: u64,
    pub max_blob_bytes: u64,
    pub max_tree_entries: u64,
    pub max_checkout_bytes: u64,
}

impl FetchPolicy {
    /// Admit one resolved Git source and emit the exact side-effect policy that
    /// a provider-specific fetch/materialization adapter must enforce.
    ///
    /// # Errors
    ///
    /// Returns [`FetchPolicyError`] if the remote/ref/OID is unsafe or if the
    /// configured resource ceilings are internally inconsistent.
    pub fn admit(&self, request: &FetchRequest) -> Result<GitFetchPlan, FetchPolicyError> {
        validate_limits(self)?;
        validate_ref(&request.requested_ref)?;
        validate_commit_oid(&request.resolved_commit_oid)?;
        let remote_host = validate_remote(&request.repository_url, self.allow_ssh)?;
        validate_resolved_remote_ips(&remote_host, &request.resolved_remote_ips)?;

        return Ok(GitFetchPlan {
            repository_url: request.repository_url.clone(),
            requested_ref: request.requested_ref.clone(),
            commit_oid: request.resolved_commit_oid.clone(),
            connect_ips: request.resolved_remote_ips.clone(),
            hooks: FeaturePolicy::Deny,
            filters: FeaturePolicy::Deny,
            credential_helpers: FeaturePolicy::Deny,
            submodules: FeaturePolicy::from_allowed(self.allow_submodules),
            lfs: FeaturePolicy::from_allowed(self.allow_lfs),
            max_pack_bytes: self.max_pack_bytes,
            max_blob_bytes: self.max_blob_bytes,
            max_tree_entries: self.max_tree_entries,
            max_checkout_bytes: self.max_checkout_bytes,
        });
    }
}

fn validate_limits(policy: &FetchPolicy) -> Result<(), FetchPolicyError> {
    if policy.max_pack_bytes == 0
        || policy.max_blob_bytes == 0
        || policy.max_tree_entries == 0
        || policy.max_checkout_bytes == 0
        || policy.max_blob_bytes > policy.max_checkout_bytes
        || policy.max_checkout_bytes > policy.max_pack_bytes
    {
        return Err(FetchPolicyError::InvalidLimits);
    }
    return Ok(());
}

fn validate_remote(raw: &str, allow_ssh: bool) -> Result<Host<String>, FetchPolicyError> {
    if raw.is_empty() || raw.chars().count() > MAX_REMOTE_URL_CHARS || raw.trim() != raw {
        return Err(FetchPolicyError::InvalidRemote);
    }

    let url = Url::parse(raw).map_err(|_| FetchPolicyError::InvalidRemote)?;
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(FetchPolicyError::EmbeddedCredentialsOrAmbiguity);
    }

    match url.scheme() {
        "https" => {}
        "ssh" if allow_ssh => {}
        "http" | "file" | "git" | "ftp" => return Err(FetchPolicyError::UnsafeScheme),
        scheme if scheme.contains('+') || scheme.contains("ext") => {
            return Err(FetchPolicyError::UnsafeScheme);
        }
        _ => return Err(FetchPolicyError::UnsafeScheme),
    }

    let host = url
        .host()
        .ok_or(FetchPolicyError::InvalidRemote)?
        .to_owned();
    match &host {
        Host::Ipv4(address) => validate_ip(IpAddr::V4(*address))?,
        Host::Ipv6(address) => validate_ip(IpAddr::V6(*address))?,
        Host::Domain(domain) => {
            let normalized = domain.to_ascii_lowercase();
            let final_label = normalized.rsplit('.').next().unwrap_or_default();
            if normalized.is_empty() || matches!(final_label, "localhost" | "local" | "internal") {
                return Err(FetchPolicyError::PrivateOrLocalHost);
            }
        }
    }

    return Ok(host);
}

fn validate_ip(address: IpAddr) -> Result<(), FetchPolicyError> {
    let unsafe_address = match address {
        IpAddr::V4(address) => {
            address.is_private()
                || address.is_loopback()
                || address.is_link_local()
                || address.is_unspecified()
                || address.is_broadcast()
                || address.is_multicast()
                || address.octets()[0] == 0
                || address.octets()[0] >= 224
        }
        IpAddr::V6(address) => {
            if let Some(mapped) = address.to_ipv4() {
                return validate_ip(IpAddr::V4(mapped));
            }

            address.is_loopback()
                || address.is_unspecified()
                || address.is_multicast()
                || address.is_unique_local()
                || address.is_unicast_link_local()
        }
    };

    if unsafe_address {
        return Err(FetchPolicyError::PrivateOrLocalHost);
    }
    return Ok(());
}

fn validate_resolved_remote_ips(
    host: &Host<String>,
    addresses: &[IpAddr],
) -> Result<(), FetchPolicyError> {
    if addresses.is_empty() || addresses.len() > 16 {
        return Err(FetchPolicyError::UnsafeResolution);
    }
    for address in addresses {
        validate_ip(*address).map_err(|_| FetchPolicyError::UnsafeResolution)?;
    }

    let literal = match host {
        Host::Ipv4(address) => Some(IpAddr::V4(*address)),
        Host::Ipv6(address) => Some(IpAddr::V6(*address)),
        Host::Domain(_) => None,
    };
    if let Some(literal) = literal
        && addresses != [literal]
    {
        return Err(FetchPolicyError::ResolutionMismatch);
    }
    return Ok(());
}

fn validate_ref(value: &str) -> Result<(), FetchPolicyError> {
    if value.is_empty()
        || value.chars().count() > MAX_REF_CHARS
        || value.trim() != value
        || value.starts_with('-')
        || value.contains("..")
        || value.chars().any(char::is_whitespace)
        || value
            .chars()
            .any(|character| matches!(character, '~' | '^' | ':' | '?' | '*' | '[' | '\\'))
    {
        return Err(FetchPolicyError::InvalidRef);
    }
    return Ok(());
}

fn validate_commit_oid(value: &str) -> Result<(), FetchPolicyError> {
    if !matches!(value.len(), 40 | 64)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(FetchPolicyError::InvalidCommitOid);
    }
    return Ok(());
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum FetchPolicyError {
    #[error("repository remote is invalid")]
    InvalidRemote,
    #[error("repository remote embeds credentials or URL ambiguity")]
    EmbeddedCredentialsOrAmbiguity,
    #[error("repository transport scheme is not allowed")]
    UnsafeScheme,
    #[error("repository host is loopback, local, or private")]
    PrivateOrLocalHost,
    #[error("resolved repository addresses are missing, private, local, or excessive")]
    UnsafeResolution,
    #[error("resolved repository address does not match the literal remote host")]
    ResolutionMismatch,
    #[error("requested Git ref is invalid")]
    InvalidRef,
    #[error("resolved commit OID must be canonical lowercase 40- or 64-hex")]
    InvalidCommitOid,
    #[error("fetch resource limits are invalid")]
    InvalidLimits,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(url: &str) -> FetchRequest {
        return FetchRequest {
            repository_url: url.to_owned(),
            requested_ref: "refs/heads/main".to_owned(),
            resolved_commit_oid: "a".repeat(40),
            resolved_remote_ips: vec!["140.82.112.4".parse().expect("public GitHub IP")],
        };
    }

    #[test]
    fn default_plan_is_fail_closed_for_repository_side_effects() {
        let plan = FetchPolicy::default()
            .admit(&request("https://github.com/takoda-automation/example.git"))
            .expect("safe remote");
        assert_eq!(plan.hooks, FeaturePolicy::Deny);
        assert_eq!(plan.filters, FeaturePolicy::Deny);
        assert_eq!(plan.credential_helpers, FeaturePolicy::Deny);
        assert_eq!(plan.submodules, FeaturePolicy::Deny);
        assert_eq!(plan.lfs, FeaturePolicy::Deny);
        assert_eq!(plan.commit_oid, "a".repeat(40));
    }

    #[test]
    fn embedded_credentials_and_ambiguous_urls_are_rejected() {
        for url in [
            "https://token@github.com/org/repo.git",
            "https://github.com/org/repo.git?ref=main",
            "https://github.com/org/repo.git#main",
        ] {
            assert!(
                FetchPolicy::default().admit(&request(url)).is_err(),
                "{url}"
            );
        }
    }

    #[test]
    fn local_and_helper_transports_are_rejected() {
        for url in [
            "file:///tmp/repo",
            "http://127.0.0.1/repo.git",
            "https://localhost/repo.git",
            "https://LOCALHOST/repo.git",
            "https://repo.LOCAL/repo.git",
            "https://repo.Internal/repo.git",
            "https://10.0.0.7/repo.git",
            "https://[::ffff:127.0.0.1]/repo.git",
            "https://[::ffff:10.0.0.7]/repo.git",
            "https://[::127.0.0.1]/repo.git",
            "git://github.com/org/repo.git",
        ] {
            assert!(
                FetchPolicy::default().admit(&request(url)).is_err(),
                "{url}"
            );
        }
    }

    #[test]
    fn dns_resolution_must_be_public_and_pinned() {
        let mut value = request("https://github.com/org/repo.git");
        assert!(FetchPolicy::default().admit(&value).is_ok());

        value.resolved_remote_ips.clear();
        assert_eq!(
            FetchPolicy::default().admit(&value),
            Err(FetchPolicyError::UnsafeResolution)
        );

        value.resolved_remote_ips = vec!["127.0.0.1".parse().expect("loopback")];
        assert_eq!(
            FetchPolicy::default().admit(&value),
            Err(FetchPolicyError::UnsafeResolution)
        );

        value.resolved_remote_ips = vec!["10.0.0.7".parse().expect("private")];
        assert_eq!(
            FetchPolicy::default().admit(&value),
            Err(FetchPolicyError::UnsafeResolution)
        );
    }

    #[test]
    fn literal_remote_must_match_exact_pinned_address() {
        let mut value = request("https://140.82.112.4/org/repo.git");
        value.resolved_remote_ips = vec!["140.82.112.4".parse().expect("literal")];
        assert!(FetchPolicy::default().admit(&value).is_ok());

        value.resolved_remote_ips = vec!["140.82.113.4".parse().expect("different public IP")];
        assert_eq!(
            FetchPolicy::default().admit(&value),
            Err(FetchPolicyError::ResolutionMismatch)
        );

        value.resolved_remote_ips = vec![
            "140.82.112.4".parse().expect("literal"),
            "140.82.113.4".parse().expect("extra"),
        ];
        assert_eq!(
            FetchPolicy::default().admit(&value),
            Err(FetchPolicyError::ResolutionMismatch)
        );
    }

    #[test]
    fn ssh_requires_explicit_policy_opt_in() {
        let value = request("ssh://git@github.com/org/repo.git");
        assert!(FetchPolicy::default().admit(&value).is_err());

        let policy = FetchPolicy {
            allow_ssh: true,
            ..FetchPolicy::default()
        };
        assert!(
            policy.admit(&value).is_err(),
            "embedded ssh username remains forbidden"
        );

        let no_user = request("ssh://github.com/org/repo.git");
        assert!(policy.admit(&no_user).is_ok());
    }

    #[test]
    fn opt_in_features_are_explicit_in_the_admitted_plan() {
        let policy = FetchPolicy {
            allow_submodules: true,
            allow_lfs: true,
            ..FetchPolicy::default()
        };
        let plan = policy
            .admit(&request("https://github.com/org/repo.git"))
            .expect("safe remote");
        assert_eq!(plan.submodules, FeaturePolicy::Allow);
        assert_eq!(plan.lfs, FeaturePolicy::Allow);
        assert_eq!(plan.hooks, FeaturePolicy::Deny);
        assert_eq!(plan.filters, FeaturePolicy::Deny);
        assert_eq!(plan.credential_helpers, FeaturePolicy::Deny);
    }

    #[test]
    fn mutable_ref_is_only_metadata_after_immutable_resolution() {
        let mut value = request("https://github.com/org/repo.git");
        value.requested_ref = "feature/safe-ref".to_owned();
        assert!(FetchPolicy::default().admit(&value).is_ok());

        value.resolved_commit_oid = "main".to_owned();
        assert_eq!(
            FetchPolicy::default().admit(&value),
            Err(FetchPolicyError::InvalidCommitOid)
        );
    }

    #[test]
    fn resource_limits_must_be_monotonic_and_nonzero() {
        let policy = FetchPolicy {
            max_pack_bytes: 10,
            max_checkout_bytes: 20,
            ..FetchPolicy::default()
        };
        assert_eq!(
            policy.admit(&request("https://github.com/org/repo.git")),
            Err(FetchPolicyError::InvalidLimits)
        );
    }
}
