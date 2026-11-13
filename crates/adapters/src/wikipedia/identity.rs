//! Validated Wikipedia-only identity. Secret bytes never enter persisted config.
use devres_domain::{Error, Result};
use reqwest::header::HeaderValue;

#[derive(Default)]
pub struct WikipediaIdentity {
    pub(crate) user_agent: Option<HeaderValue>,
    pub(crate) authorization: Option<HeaderValue>,
}

impl std::fmt::Debug for WikipediaIdentity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WikipediaIdentity")
            .field("user_agent_configured", &self.user_agent.is_some())
            .field("authenticated", &self.authorization.is_some())
            .finish()
    }
}

impl WikipediaIdentity {
    /// Parse only runtime bytes. Token rotation requires constructing a new broker.
    pub fn new(user_agent: Option<&str>, token: Option<&[u8]>) -> Result<Self> {
        let user_agent = user_agent
            .map(|value| {
                devres_application::wikipedia::validate_user_agent(value)?;
                HeaderValue::from_str(value)
                    .map_err(|_| Error::invalid("Invalid Wikipedia User-Agent."))
            })
            .transpose()?;
        let authorization = token
            .map(|bytes| {
                let invalid = || Error::invalid("Invalid Wikipedia OAuth2 token.");
                if bytes.len() > 16 * 1024 {
                    return Err(invalid());
                }
                let value = std::str::from_utf8(bytes)
                    .map_err(|_| invalid())?
                    .trim_end_matches(['\r', '\n']);
                if value.is_empty()
                    || !value
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || b"-._~+/=".contains(&byte))
                {
                    return Err(invalid());
                }
                let mut header =
                    HeaderValue::from_str(&format!("Bearer {value}")).map_err(|_| invalid())?;
                header.set_sensitive(true);
                Ok(header)
            })
            .transpose()?;
        Ok(Self {
            user_agent,
            authorization,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const UA: &str = "ResearchBot/1.0 (https://example.org/bot)";
    #[test]
    fn identities_are_explicit_and_bearer_is_sensitive_and_redacted() {
        let empty = WikipediaIdentity::default();
        assert!(empty.user_agent.is_none());
        assert!(empty.authorization.is_none());
        let identity = WikipediaIdentity::new(Some(UA), Some(b"synthetic-secret\r\n"))
            .expect("valid identity");
        assert_eq!(identity.user_agent.as_ref().expect("UA"), UA);
        let authorization = identity.authorization.as_ref().expect("bearer");
        assert_eq!(authorization, "Bearer synthetic-secret");
        assert!(authorization.is_sensitive());
        assert!(!format!("{identity:?}").contains("synthetic-secret"));
        assert!(!format!("{authorization:?}").contains("synthetic-secret"));
    }
    #[test]
    fn malformed_tokens_fail_without_disclosing_input() {
        let oversized = vec![b'x'; 16 * 1024 + 1];
        for value in [
            b"".as_slice(),
            b" \n",
            b"secret value",
            b" secret",
            b"secret\nInjected",
            b"\xff",
            oversized.as_slice(),
        ] {
            let error = WikipediaIdentity::new(Some(UA), Some(value)).expect_err("invalid token");
            assert_eq!(error.message, "Invalid Wikipedia OAuth2 token.");
            assert!(error.details.is_none());
        }
        assert!(WikipediaIdentity::new(Some("curl"), None).is_err());
        assert!(
            WikipediaIdentity::new(Some(UA), None)
                .expect("anonymous")
                .authorization
                .is_none()
        );
    }
}
