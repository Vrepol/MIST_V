use std::{
    env, io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, TcpStream, ToSocketAddrs, UdpSocket},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

#[cfg(any(windows, test))]
use serde::Deserialize;

use crate::util::endpoint::{format_host_port, is_advertisable_ip};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdvertiseAddrCandidate {
    pub label: String,
    pub addr: String,
}

fn server_binary_candidates(current_exe: &Path) -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    if let Some(dir) = current_exe.parent() {
        candidates.push(dir.join("MistV-server.exe"));
        candidates.push(dir.join("MistV-server"));
    }
    candidates
}

fn resolve_server_binary() -> io::Result<PathBuf> {
    let current_exe = env::current_exe()?;
    server_binary_candidates(&current_exe)
        .into_iter()
        .find(|path| path.is_file())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "未找到同目录 MistV-server 可执行文件，请先构建或放置 MistV-server/MistV-server.exe",
            )
        })
}

fn wait_for_any_local_server(addrs: &[String], timeout: Duration) -> io::Result<()> {
    let deadline = Instant::now() + timeout;
    let mut socket_addrs = Vec::new();
    let mut last_resolve_err = None;
    for addr in addrs {
        match addr.to_socket_addrs() {
            Ok(resolved) => socket_addrs.extend(resolved),
            Err(err) => last_resolve_err = Some(err),
        }
    }

    if socket_addrs.is_empty() {
        return Err(last_resolve_err.unwrap_or_else(|| {
            io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "无法解析本地服务端回环地址",
            )
        }));
    }

    while Instant::now() < deadline {
        for socket_addr in &socket_addrs {
            if TcpStream::connect_timeout(socket_addr, Duration::from_millis(200)).is_ok() {
                return Ok(());
            }
        }
        thread::sleep(Duration::from_millis(150));
    }

    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        format!("本地服务端启动超时: {}", addrs.join(", ")),
    ))
}

fn primary_local_ipv4() -> Option<Ipv4Addr> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("8.8.8.8:80").ok()?;
    match socket.local_addr().ok()?.ip() {
        IpAddr::V4(ip) if is_advertisable_ip(&IpAddr::V4(ip)) => Some(ip),
        _ => None,
    }
}

fn primary_local_ipv6() -> Option<Ipv6Addr> {
    let socket = UdpSocket::bind("[::]:0").ok()?;
    socket.connect("[2001:4860:4860::8888]:80").ok()?;
    match socket.local_addr().ok()?.ip() {
        IpAddr::V6(ip) if is_advertisable_ip(&IpAddr::V6(ip)) => Some(ip),
        _ => None,
    }
}

#[cfg(any(windows, test))]
#[derive(Debug, Deserialize)]
struct WindowsIpRow {
    #[serde(rename = "InterfaceAlias")]
    interface_alias: String,
    #[serde(rename = "IPAddress")]
    ip_address: String,
}

#[cfg(windows)]
fn windows_ip_candidates() -> io::Result<Vec<AdvertiseAddrCandidate>> {
    let script = concat!(
        "Get-NetIPAddress | ",
        "Where-Object { $_.AddressState -eq 'Preferred' -and $_.SkipAsSource -eq $false } | ",
        "Select-Object InterfaceAlias,IPAddress | ConvertTo-Json -Compress"
    );

    let output = Command::new("powershell")
        .arg("-NoProfile")
        .arg("-Command")
        .arg(script)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()?;

    if !output.status.success() {
        return Ok(Vec::new());
    }

    parse_windows_ip_candidates(String::from_utf8_lossy(&output.stdout).trim())
}

#[cfg(not(windows))]
fn windows_ip_candidates() -> io::Result<Vec<AdvertiseAddrCandidate>> {
    Ok(Vec::new())
}

#[cfg(unix)]
fn unix_ip_candidates() -> io::Result<Vec<AdvertiseAddrCandidate>> {
    let mut candidates = Vec::new();

    if let Ok(output) = Command::new("ip")
        .args(["-o", "addr", "show", "scope", "global"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
    {
        if output.status.success() {
            candidates.extend(parse_ip_addr_candidates(&String::from_utf8_lossy(
                &output.stdout,
            )));
        }
    }

    if let Ok(output) = Command::new("ifconfig")
        .arg("-a")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
    {
        if output.status.success() {
            candidates.extend(parse_ifconfig_candidates(&String::from_utf8_lossy(
                &output.stdout,
            )));
        }
    }

    candidates.dedup_by(|a, b| a.addr == b.addr);
    Ok(candidates)
}

#[cfg(not(unix))]
fn unix_ip_candidates() -> io::Result<Vec<AdvertiseAddrCandidate>> {
    Ok(Vec::new())
}

#[cfg(any(windows, test))]
fn parse_windows_ip_candidates(json: &str) -> io::Result<Vec<AdvertiseAddrCandidate>> {
    if json.is_empty() || json == "null" {
        return Ok(Vec::new());
    }

    let rows: Vec<WindowsIpRow> = if json.trim_start().starts_with('[') {
        serde_json::from_str(json).map_err(io::Error::other)?
    } else {
        vec![serde_json::from_str(json).map_err(io::Error::other)?]
    };

    let mut candidates = Vec::new();
    for row in rows {
        let Ok(ip) = row.ip_address.parse::<IpAddr>() else {
            continue;
        };
        if !is_advertisable_ip(&ip) {
            continue;
        }
        candidates.push(AdvertiseAddrCandidate {
            label: row.interface_alias,
            addr: ip.to_string(),
        });
    }

    Ok(candidates)
}

#[cfg(any(unix, test))]
fn parse_ip_addr_candidates(output: &str) -> Vec<AdvertiseAddrCandidate> {
    let mut candidates = Vec::new();

    for line in output.lines() {
        let tokens = line.split_whitespace().collect::<Vec<_>>();
        let Some((family_idx, _)) = tokens
            .iter()
            .enumerate()
            .find(|(_, token)| **token == "inet" || **token == "inet6")
        else {
            continue;
        };
        let Some(addr) = tokens.get(family_idx + 1) else {
            continue;
        };
        let label = tokens
            .get(1)
            .map(|iface| format!("Interface {}", iface.trim_end_matches(':')))
            .unwrap_or_else(|| "Interface".to_string());
        push_parsed_ip_candidate(&mut candidates, label, addr);
    }

    candidates
}

#[cfg(any(unix, test))]
fn parse_ifconfig_candidates(output: &str) -> Vec<AdvertiseAddrCandidate> {
    let mut candidates = Vec::new();
    let mut current_interface = "Interface".to_string();

    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let is_interface_header = !line.starts_with(' ') && !line.starts_with('\t');
        if is_interface_header {
            if let Some((iface, _)) = trimmed.split_once(':') {
                current_interface = iface.to_string();
                continue;
            }
        }

        let mut parts = trimmed.split_whitespace();
        let Some(family) = parts.next() else {
            continue;
        };
        if family != "inet" && family != "inet6" {
            continue;
        }
        let Some(addr) = parts.next() else {
            continue;
        };
        push_parsed_ip_candidate(
            &mut candidates,
            format!("Interface {current_interface}"),
            addr,
        );
    }

    candidates
}

#[cfg(any(unix, test))]
fn push_parsed_ip_candidate(
    candidates: &mut Vec<AdvertiseAddrCandidate>,
    label: String,
    raw_addr: &str,
) {
    let without_prefix = raw_addr
        .split_once('/')
        .map(|(addr, _)| addr)
        .unwrap_or(raw_addr);
    let addr = without_prefix
        .split_once('%')
        .map(|(addr, _)| addr)
        .unwrap_or(without_prefix);
    let Ok(ip) = addr.parse::<IpAddr>() else {
        return;
    };
    if !is_advertisable_ip(&ip) {
        return;
    }
    let ip = ip.to_string();
    if candidates.iter().any(|entry| entry.addr == ip) {
        return;
    }
    candidates.push(AdvertiseAddrCandidate { label, addr: ip });
}

pub fn detect_advertise_candidates() -> io::Result<Vec<AdvertiseAddrCandidate>> {
    let mut candidates = windows_ip_candidates()?;
    candidates.extend(unix_ip_candidates()?);

    if let Some(ip) = primary_local_ipv6() {
        let ip_str = ip.to_string();
        if !candidates.iter().any(|entry| entry.addr == ip_str) {
            candidates.insert(
                0,
                AdvertiseAddrCandidate {
                    label: "Primary IPv6 route".to_string(),
                    addr: ip_str,
                },
            );
        }
    }

    if let Some(ip) = primary_local_ipv4() {
        let ip_str = ip.to_string();
        if !candidates.iter().any(|entry| entry.addr == ip_str) {
            candidates.insert(
                0,
                AdvertiseAddrCandidate {
                    label: "Primary route".to_string(),
                    addr: ip_str,
                },
            );
        }
    }

    candidates.sort_by(|a, b| {
        candidate_rank(a)
            .cmp(&candidate_rank(b))
            .then(a.addr.cmp(&b.addr))
            .then(a.label.cmp(&b.label))
    });
    candidates.dedup_by(|a, b| a.addr == b.addr);

    candidates.push(AdvertiseAddrCandidate {
        label: "IPv6 loopback (local only)".to_string(),
        addr: "::1".to_string(),
    });
    candidates.push(AdvertiseAddrCandidate {
        label: "Loopback (local only)".to_string(),
        addr: "127.0.0.1".to_string(),
    });

    Ok(candidates)
}

fn candidate_rank(candidate: &AdvertiseAddrCandidate) -> u8 {
    match candidate.addr.parse::<IpAddr>() {
        Ok(IpAddr::V6(ip)) if !ip.is_loopback() => 0,
        Ok(IpAddr::V4(ip)) if !ip.is_loopback() => 1,
        Ok(IpAddr::V6(_)) => 2,
        Ok(IpAddr::V4(_)) => 3,
        Err(_) => 4,
    }
}

pub fn spawn_local_server(port: u16, password: &str) -> io::Result<()> {
    let local_addrs = [
        format_host_port("::1", port),
        format_host_port("127.0.0.1", port),
    ];

    if wait_for_any_local_server(&local_addrs, Duration::from_millis(250)).is_ok() {
        return Ok(());
    }

    let server_bin = resolve_server_binary()?;
    Command::new(server_bin)
        .arg("--port")
        .arg(port.to_string())
        .arg("-k")
        .arg(password)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;

    wait_for_any_local_server(&local_addrs, Duration::from_secs(3))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        candidate_rank, parse_ifconfig_candidates, parse_ip_addr_candidates,
        parse_windows_ip_candidates, AdvertiseAddrCandidate,
    };

    #[test]
    fn test_parse_windows_ip_candidates_filters_invalid_addrs() {
        let json = r#"[{"InterfaceAlias":"Wi-Fi","IPAddress":"192.168.1.23"},{"InterfaceAlias":"IPv6","IPAddress":"2606:4700:4700::1111"},{"InterfaceAlias":"Loopback","IPAddress":"127.0.0.1"},{"InterfaceAlias":"LinkLocal","IPAddress":"fe80::1"},{"InterfaceAlias":"UniqueLocal","IPAddress":"fd00::1"}]"#;
        let parsed =
            parse_windows_ip_candidates(json).expect("windows candidate json should parse");
        assert_eq!(parsed.len(), 2);
        assert!(parsed.iter().any(|item| item.addr == "192.168.1.23"));
        assert!(parsed
            .iter()
            .any(|item| item.addr == "2606:4700:4700::1111"));
    }

    #[test]
    fn test_candidate_rank_prefers_ipv6_before_ipv4() {
        let ipv6 = AdvertiseAddrCandidate {
            label: "IPv6".to_string(),
            addr: "2606:4700:4700::1111".to_string(),
        };
        let ipv4 = AdvertiseAddrCandidate {
            label: "IPv4".to_string(),
            addr: "192.168.1.23".to_string(),
        };
        assert!(candidate_rank(&ipv6) < candidate_rank(&ipv4));
    }

    #[test]
    fn test_parse_ifconfig_candidates_finds_global_ipv6() {
        let output = r#"lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384
	inet6 ::1 prefixlen 128
en0: flags=8863<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> mtu 1500
	inet6 fe80::1%en0 prefixlen 64 secured scopeid 0xb
	inet6 fd00::1 prefixlen 64 autoconf secured
	inet6 2606:4700:4700::1111 prefixlen 64 autoconf secured
	inet 192.168.1.23 netmask 0xffffff00 broadcast 192.168.1.255
"#;
        let parsed = parse_ifconfig_candidates(output);

        assert!(parsed
            .iter()
            .any(|item| item.addr == "2606:4700:4700::1111"));
        assert!(parsed.iter().any(|item| item.addr == "192.168.1.23"));
        assert!(!parsed.iter().any(|item| item.addr.starts_with("fe80:")));
        assert!(!parsed.iter().any(|item| item.addr.starts_with("fd00:")));
        assert!(!parsed.iter().any(|item| item.addr == "::1"));
    }

    #[test]
    fn test_parse_ip_addr_candidates_finds_global_ipv6() {
        let output = r#"2: eth0    inet 192.168.1.23/24 brd 192.168.1.255 scope global eth0
2: eth0    inet6 2606:4700:4700::1111/64 scope global dynamic
3: wlan0    inet6 fe80::1/64 scope link
4: tun0    inet6 fd00::1/64 scope global
"#;
        let parsed = parse_ip_addr_candidates(output);

        assert!(parsed
            .iter()
            .any(|item| item.addr == "2606:4700:4700::1111"));
        assert!(parsed.iter().any(|item| item.addr == "192.168.1.23"));
        assert!(!parsed.iter().any(|item| item.addr.starts_with("fe80:")));
        assert!(!parsed.iter().any(|item| item.addr.starts_with("fd00:")));
    }
}
