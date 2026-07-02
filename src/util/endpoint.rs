use std::net::{IpAddr, Ipv6Addr, SocketAddr};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    pub host: String,
    pub port: u16,
}

impl Endpoint {
    pub fn normalized(&self) -> String {
        format_host_port(&self.host, self.port)
    }
}

pub fn normalize_endpoint(input: &str) -> Option<String> {
    parse_endpoint(input).map(|endpoint| endpoint.normalized())
}

pub fn format_host_port(host: &str, port: u16) -> String {
    let host = host.trim();
    let host = host
        .strip_prefix('[')
        .and_then(|inner| inner.strip_suffix(']'))
        .unwrap_or(host);

    if host.parse::<Ipv6Addr>().is_ok() {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

pub fn parse_endpoint(input: &str) -> Option<Endpoint> {
    let trimmed = input.trim();
    if trimmed.is_empty() || trimmed.chars().any(char::is_whitespace) {
        return None;
    }

    if let Ok(socket_addr) = trimmed.parse::<SocketAddr>() {
        if socket_addr.port() == 0 {
            return None;
        }
        return Some(Endpoint {
            host: socket_addr.ip().to_string(),
            port: socket_addr.port(),
        });
    }

    let (host, port) = parse_host_port(trimmed)?;
    Some(Endpoint { host, port })
}

fn parse_host_port(input: &str) -> Option<(String, u16)> {
    let (host, port) = input.rsplit_once(':')?;
    if host.is_empty()
        || host.contains(':')
        || host.contains('/')
        || host.contains('&')
        || host.starts_with('[')
        || host.ends_with(']')
    {
        return None;
    }

    let port = parse_valid_port(port)?;
    Some((host.to_string(), port))
}

fn parse_valid_port(port: &str) -> Option<u16> {
    let port = port.parse::<u16>().ok()?;
    (port != 0).then_some(port)
}

pub fn is_advertisable_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            !ip.is_loopback() && !ip.is_link_local() && !ip.is_unspecified() && !ip.is_broadcast()
        }
        IpAddr::V6(ip) => {
            !ip.is_loopback()
                && !ip.is_unspecified()
                && !ip.is_multicast()
                && !is_ipv6_unicast_link_local(ip)
                && !is_ipv6_unique_local(ip)
                && !is_ipv6_site_local(ip)
                && !is_ipv6_documentation(ip)
                && !is_ipv6_mapped_or_compatible(ip)
        }
    }
}

fn is_ipv6_unicast_link_local(ip: &Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xffc0) == 0xfe80
}

fn is_ipv6_unique_local(ip: &Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xfe00) == 0xfc00
}

fn is_ipv6_site_local(ip: &Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xffc0) == 0xfec0
}

fn is_ipv6_documentation(ip: &Ipv6Addr) -> bool {
    let segments = ip.segments();
    segments[0] == 0x2001 && segments[1] == 0x0db8
}

fn is_ipv6_mapped_or_compatible(ip: &Ipv6Addr) -> bool {
    let segments = ip.segments();
    segments[0..5] == [0, 0, 0, 0, 0] && (segments[5] == 0 || segments[5] == 0xffff)
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use super::{format_host_port, is_advertisable_ip, normalize_endpoint, parse_endpoint};

    #[test]
    fn endpoint_parses_ipv4_hostname_and_bracketed_ipv6() {
        assert_eq!(
            normalize_endpoint("127.0.0.1:6655"),
            Some("127.0.0.1:6655".to_string())
        );
        assert_eq!(
            normalize_endpoint("chat.local:6655"),
            Some("chat.local:6655".to_string())
        );
        assert_eq!(
            normalize_endpoint("[::1]:6655"),
            Some("[::1]:6655".to_string())
        );
        assert_eq!(
            normalize_endpoint("[2001:db8::42]:6655"),
            Some("[2001:db8::42]:6655".to_string())
        );

        let endpoint = parse_endpoint("example.com:443").expect("hostname endpoint should parse");
        assert_eq!(endpoint.host, "example.com");
        assert_eq!(endpoint.port, 443);
    }

    #[test]
    fn endpoint_rejects_invalid_or_ambiguous_input() {
        assert!(normalize_endpoint("::1:6655").is_none());
        assert!(normalize_endpoint("[::1]").is_none());
        assert!(normalize_endpoint("host:0").is_none());
        assert!(normalize_endpoint("host:not-a-port").is_none());
        assert!(normalize_endpoint("http://host:6655").is_none());
        assert!(normalize_endpoint("host name:6655").is_none());
    }

    #[test]
    fn host_port_formats_ipv6_with_brackets() {
        assert_eq!(format_host_port("::1", 6655), "[::1]:6655");
        assert_eq!(format_host_port("[::1]", 6655), "[::1]:6655");
        assert_eq!(format_host_port("127.0.0.1", 6655), "127.0.0.1:6655");
        assert_eq!(format_host_port("chat.local", 6655), "chat.local:6655");
    }

    #[test]
    fn advertise_filter_allows_routable_ips_only() {
        assert!(is_advertisable_ip(&IpAddr::V4(Ipv4Addr::new(
            192, 168, 1, 10
        ))));
        assert!(is_advertisable_ip(&IpAddr::V6(
            "2606:4700:4700::1111".parse::<Ipv6Addr>().unwrap()
        )));
        assert!(!is_advertisable_ip(&IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert!(!is_advertisable_ip(&IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert!(!is_advertisable_ip(&IpAddr::V6(
            "fe80::1".parse::<Ipv6Addr>().unwrap()
        )));
        assert!(!is_advertisable_ip(&IpAddr::V6(
            "fd00::1".parse::<Ipv6Addr>().unwrap()
        )));
        assert!(!is_advertisable_ip(&IpAddr::V6(
            "2001:db8::42".parse::<Ipv6Addr>().unwrap()
        )));
    }
}
