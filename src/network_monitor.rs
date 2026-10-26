use netstat2::{get_sockets_info, AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo, TcpState};
use sysinfo::{Pid, System};

pub fn get_connections() -> String {
    let af_flags = AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6;
    let proto_flags = ProtocolFlags::TCP;

    let sockets_info = match get_sockets_info(af_flags, proto_flags) {
        Ok(info) => info,
        Err(e) => return format!("[-] Ошибка получения сетевых сокетов: {}", e),
    };

    let mut sys = System::new_all();
    sys.refresh_all();

    let mut output = String::new();
    output.push_str(&format!(
        "{:<8} | {:<25} | {:<25} | {:<12} | {:<8} | {:<20}\n",
        "Протокол", "Локальный IP:Порт", "Удаленный IP:Порт", "Статус", "PID", "Процесс"
    ));
    output.push_str(&format!("{:-<112}\n", ""));

    for socket in sockets_info {
        if let ProtocolSocketInfo::Tcp(tcp) = socket.protocol_socket_info {
            let local = format!("{}:{}", tcp.local_addr, tcp.local_port);
            let remote = format!("{}:{}", tcp.remote_addr, tcp.remote_port);

            let state = match tcp.state {
                TcpState::Listen => "LISTEN", TcpState::Established => "ESTABLISHED",
                TcpState::SynSent => "SYN_SENT", TcpState::SynReceived => "SYN_RECV",
                TcpState::FinWait1 => "FIN_WAIT_1", TcpState::FinWait2 => "FIN_WAIT_2",
                TcpState::TimeWait => "TIME_WAIT", TcpState::Closed => "CLOSED",
                TcpState::CloseWait => "CLOSE_WAIT", TcpState::LastAck => "LAST_ACK",
                TcpState::Closing => "CLOSING", _ => "UNKNOWN",
            };

            let pids = socket.associated_pids;
            if pids.is_empty() {
                output.push_str(&format!("{:<8} | {:<25} | {:<25} | {:<12} | {:<8} | {:<20}\n", "TCP", local, remote, state, "-", "N/A"));
            } else {
                for pid in pids {
                    let pid_usize = pid as usize;
                    // В sysinfo 0.30 name() возвращает &str
                    let process_name = if let Some(process) = sys.process(Pid::from(pid_usize)) {
                        process.name().to_string()
                    } else {
                        "Unknown".to_string()
                    };
                    output.push_str(&format!("{:<8} | {:<25} | {:<25} | {:<12} | {:<8} | {:<20}\n", "TCP", local, remote, state, pid_usize, process_name));
                }
            }
        }
    }
    output
}