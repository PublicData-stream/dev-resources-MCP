//! Connection-time public-address admission for catalog-qualified W3C destinations.
use devres_domain::{Error, Result};
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use std::{net::IpAddr, sync::Arc, time::Duration};

struct PublicResolver;
impl Resolve for PublicResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let host = name.as_str().to_owned();
        Box::pin(async move {
            let addresses: Vec<_> = tokio::net::lookup_host((host.as_str(), 0)).await?.collect();
            if addresses.is_empty()
                || addresses.len() > 64
                || addresses.iter().any(|a| !public_ip(a.ip()))
            {
                return Err(std::io::Error::other("W3C destination is not public").into());
            }
            Ok(Box::new(addresses.into_iter()) as Addrs)
        })
    }
}

pub(crate) fn public_ip(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(v) => {
            let [a, b, c, _] = v.octets();
            !(matches!(a, 0 | 10 | 127 | 224..=255)
                || a == 100 && (64..=127).contains(&b)
                || a == 169 && b == 254
                || a == 172 && (16..=31).contains(&b)
                || a == 192 && (b == 168 || b == 0 && (c == 0 || c == 2))
                || a == 192 && b == 88 && c == 99
                || a == 198 && (b == 18 || b == 19 || b == 51 && c == 100)
                || a == 203 && b == 0 && c == 113)
        }
        IpAddr::V6(v) => {
            let s = v.segments();
            // Admit ordinary global unicast only. Reject mapped, translation,
            // documentation, tunneling, local, multicast and reserved ranges.
            s[0] & 0xe000 == 0x2000
                && !(s[0] == 0x2001 && (s[1] < 0x0200 || s[1] == 0x0db8))
                && s[0] != 0x2002
                && !(s[0] == 0x3fff && s[1] < 0x1000)
        }
    }
}

pub(crate) fn client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .https_only(true)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .dns_resolver(Arc::new(PublicResolver))
        .connect_timeout(Duration::from_secs(10))
        .user_agent(
            "dev-resources-MCP/0.0.0 (+https://github.com/PublicData-stream/dev-resources-MCP)",
        )
        .build()
        .map_err(|_| Error::unavailable("W3C HTTP initialization failed."))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_local_reserved_and_translation_addresses() {
        for value in [
            "0.0.0.0",
            "10.1.2.3",
            "127.0.0.1",
            "100.64.1.1",
            "169.254.169.254",
            "172.31.0.1",
            "192.168.1.1",
            "192.0.2.1",
            "198.18.0.1",
            "198.51.100.1",
            "203.0.113.1",
            "224.0.0.1",
            "240.0.0.1",
            "::1",
            "::ffff:127.0.0.1",
            "64:ff9b::a00:1",
            "fc00::1",
            "fe80::1",
            "2001:db8::1",
            "2002:7f00:1::",
            "3fff::1",
        ] {
            assert!(
                !public_ip(value.parse().expect("fixture address")),
                "{value}"
            );
        }
        for value in ["1.1.1.1", "8.8.8.8", "140.82.112.3", "2606:4700:4700::1111"] {
            assert!(
                public_ip(value.parse().expect("fixture address")),
                "{value}"
            );
        }
    }
}
