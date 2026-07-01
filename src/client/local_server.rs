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

pub fn detect_advertise_candidates() -> io::Result<Vec<AdvertiseAddrCandidate>> {
    let mut candidates = windows_ip_candidates()?;

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
    use super::{candidate_rank, parse_windows_ip_candidates, AdvertiseAddrCandidate};

    #[test]
    fn test_parse_windows_ip_candidates_filters_invalid_addrs() {
        let json = r#"[{"InterfaceAlias":"Wi-Fi","IPAddress":"192.168.1.23"},{"InterfaceAlias":"IPv6","IPAddress":"2001:db8::42"},{"InterfaceAlias":"Loopback","IPAddress":"127.0.0.1"},{"InterfaceAlias":"LinkLocal","IPAddress":"fe80::1"}]"#;
        let parsed =
            parse_windows_ip_candidates(json).expect("windows candidate json should parse");
        assert_eq!(parsed.len(), 2);
        assert!(parsed.iter().any(|item| item.addr == "192.168.1.23"));
        assert!(parsed.iter().any(|item| item.addr == "2001:db8::42"));
    }

    #[test]
    fn test_candidate_rank_prefers_ipv6_before_ipv4() {
        let ipv6 = AdvertiseAddrCandidate {
            label: "IPv6".to_string(),
            addr: "2001:db8::42".to_string(),
        };
        let ipv4 = AdvertiseAddrCandidate {
            label: "IPv4".to_string(),
            addr: "192.168.1.23".to_string(),
        };
        assert!(candidate_rank(&ipv6) < candidate_rank(&ipv4));
    }
}
