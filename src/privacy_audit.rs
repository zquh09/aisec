use std::net::{IpAddr, Ipv6Addr, UdpSocket, ToSocketAddrs};

#[derive(Debug, Clone)]
pub struct PrivacyReport {
    pub dns_leak: bool,
    pub ipv6_active: bool,
    pub webrtc_leak: bool,
    pub warnings: Vec<String>,
}

fn is_private_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private() || v4.is_loopback() || v4.is_link_local() || v4.is_unspecified(),
        IpAddr::V6(v6) => v6.is_loopback() || v6.is_unspecified() || is_ipv6_unique_local(v6) || is_ipv6_link_local(v6),
    }
}

fn is_ipv6_link_local(v6: &Ipv6Addr) -> bool {
    (v6.segments()[0] & 0xffc0) == 0xfe80
}

fn is_ipv6_unique_local(v6: &Ipv6Addr) -> bool {
    (v6.segments()[0] & 0xfe00) == 0xfc00
}

pub fn run_privacy_audit() -> PrivacyReport {
    let mut warnings = Vec::new();
    let mut dns_leak = false;
    let mut ipv6_active = false;
    let mut webrtc_leak = false;

    // 1. Проверка IPv6
    if let Ok(socket) = UdpSocket::bind("[::]:0") {
        if socket.connect("[2001:4860:4860::8888]:53").is_ok() {
            ipv6_active = true;
            warnings.push("Внимание: IPv6 активен в системе. Некоторые VPN не туннелируют IPv6, что может выдать ваш реальный IP.".to_string());
        }
    }

    // 2. Проверка локального IP
    if let Ok(socket) = UdpSocket::bind("0.0.0.0:0") {
        if socket.connect("8.8.8.8:80").is_ok() {
            if let Ok(local_addr) = socket.local_addr() {
                let local_ip = local_addr.ip();
                if is_private_ip(&local_ip) {
                    // 172.16.x.x, 192.168.x.x, 10.x.x.x - это нормальные локальные IP.
                    // Они не являются "утечкой", но их видно в локальной сети.
                    warnings.push(format!("Ваш локальный IP: {}. Это стандартный адрес для домашней сети (не является утечкой).", local_ip));
                } else {
                    // Если IP публичный, значит VPN выключен, и провайдер видит твой реальный IP.
                    webrtc_leak = true;
                    warnings.push(format!("Ваш публичный IP: {}. Сайты видят этот адрес.", local_ip));
                }
            }
        }
    }

    // 3. Проверка DNS (без использования 1.1.1.1, так как он блокируется в РФ)
    // Проверяем, может ли система разрешить доменное имя.
    if "google.com:80".to_socket_addrs().is_err() {
        dns_leak = true;
        warnings.push("Не удалось разрешить доменное имя (DNS). Возможно, DNS заблокирован провайдером или нет доступа в интернет.".to_string());
    }

    PrivacyReport {
        dns_leak,
        ipv6_active,
        webrtc_leak,
        warnings,
    }
}