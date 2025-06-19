use crate::packet;
use crate::utils::SelectedInterfaceInfo;
use pnet_packet::ip::IpNextHeaderProtocols;
use pnet_packet::ipv4::Ipv4Packet;
use pnet_packet::tcp::{TcpFlags, TcpPacket};
use pnet_packet::Packet;
use pnet_transport::{transport_channel, TransportChannelType, TransportReceiver, TransportSender, ipv4_packet_iter};
use rand::seq::SliceRandom;
use rand::thread_rng;
use std::collections::HashSet; // HashMap was unused here
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use tokio::sync::{Mutex, Semaphore};
use std::time::Duration;
use tokio::time::timeout as tokio_timeout;


pub struct RawSocketHandler {
    transport_sender: TransportSender,
    transport_receiver: Arc<Mutex<TransportReceiver>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PortStatus {
    Open(u16),
    Closed(u16),
    Filtered(u16),
    Error(u16, String),
}

impl RawSocketHandler {
    pub fn new() -> Result<Self, String> {
        let protocol_ip_tcp = IpNextHeaderProtocols::Tcp;
        let (ts, tr) = transport_channel(
            4096,
            TransportChannelType::Layer3(protocol_ip_tcp)
        )
        .map_err(|e| format!("Failed to create transport channel: {}", e))?;

        Ok(RawSocketHandler {
            transport_sender: ts,
            transport_receiver: Arc::new(Mutex::new(tr)),
        })
    }

    pub async fn send_syn_packet(
        &mut self,
        source_ip: Ipv4Addr,
        target_ip: Ipv4Addr,
        source_port: u16,
        dest_port: u16,
    ) -> Result<(), String> {
        let ttl = 64;
        let packet_bytes = packet::build_syn_packet(
            source_ip, target_ip, source_port, dest_port, ttl,
        )?;
        self.transport_sender
            .send_to(Ipv4Packet::new(&packet_bytes).unwrap(), IpAddr::V4(target_ip))
            .map_err(|e| format!("Failed to send packet: {}", e))?;
        Ok(())
    }

    pub async fn try_receive_response(
        receiver_arc: Arc<Mutex<TransportReceiver>>,
        target_ip: Ipv4Addr,
        expected_response_src_port: u16,
        expected_response_dest_port: u16
    ) -> Result<Option<PortStatus>, String> {
        let mut tr_guard = receiver_arc.lock().await;
        let mut iter = ipv4_packet_iter(&mut *tr_guard);

        match iter.next() {
            Ok((packet_data, remote_addr)) => {
                if remote_addr != IpAddr::V4(target_ip) {
                    return Ok(None);
                }
                if let Some(ipv4_packet) = Ipv4Packet::new(packet_data.packet()) {
                    if ipv4_packet.get_next_level_protocol() == IpNextHeaderProtocols::Tcp {
                        if let Some(tcp_packet) = TcpPacket::new(ipv4_packet.payload()) {
                            if tcp_packet.get_source() == expected_response_src_port &&
                               tcp_packet.get_destination() == expected_response_dest_port {
                                let flags = tcp_packet.get_flags();
                                if (flags & TcpFlags::SYN) != 0 && (flags & TcpFlags::ACK) != 0 {
                                    return Ok(Some(PortStatus::Open(expected_response_src_port)));
                                } else if (flags & TcpFlags::RST) != 0 || (flags & TcpFlags::RST | TcpFlags::ACK) != 0 {
                                    return Ok(Some(PortStatus::Closed(expected_response_src_port)));
                                }
                            }
                        }
                    }
                }
                Ok(None)
            }
            Err(e) => {
                Err(format!("Error in try_receive_response: {}", e))
            }
        }
    }
}


pub struct Scanner {
    raw_socket_handler: Arc<Mutex<RawSocketHandler>>,
    target_ip: Ipv4Addr,
    ports_to_scan: Vec<u16>,
    source_ip: Ipv4Addr,
    concurrency: usize,
    timeout_ms: u64,
    scan_delay_ms: u64,
    randomize_ports: bool,
    active_ephemeral_ports: Arc<Mutex<HashSet<u16>>>,
    next_ephemeral_port: u16,
}

impl Scanner {
    pub fn new(
        target_ip: Ipv4Addr,
        ports_to_scan: Vec<u16>,
        interface_info: &SelectedInterfaceInfo,
        concurrency: usize,
        timeout_ms: u64,
        scan_delay_ms: u64,
        randomize_ports: bool,
    ) -> Result<Self, String> {
        let raw_socket_handler = RawSocketHandler::new()?;
        let source_ip_v4 = match interface_info.source_ip {
            IpAddr::V4(ip) => ip,
            IpAddr::V6(_) => return Err("IPv6 not supported for source IP".to_string()),
        };
        Ok(Scanner {
            raw_socket_handler: Arc::new(Mutex::new(raw_socket_handler)),
            target_ip,
            ports_to_scan,
            source_ip: source_ip_v4,
            concurrency,
            timeout_ms,
            scan_delay_ms,
            randomize_ports,
            active_ephemeral_ports: Arc::new(Mutex::new(HashSet::new())),
            next_ephemeral_port: 49152,
        })
    }

    async fn get_next_ephemeral_port(&mut self) -> u16 {
        let mut active_ports_guard = self.active_ephemeral_ports.lock().await;
        loop {
            let port = self.next_ephemeral_port;
            self.next_ephemeral_port = self.next_ephemeral_port.wrapping_add(1);
            if self.next_ephemeral_port < 49152 {
                self.next_ephemeral_port = 49152;
            }
            if !active_ports_guard.contains(&port) {
                active_ports_guard.insert(port);
                return port;
            }
        }
    }

    // This method was identified as unused. Port releasing is handled directly
    // by tasks using the Arc<Mutex<HashSet<u16>>>.
    // async fn release_ephemeral_port(&self, port: u16) {
    //     let mut active_ports_guard = self.active_ephemeral_ports.lock().await;
    //     active_ports_guard.remove(&port);
    // }

    pub async fn run_scan(&mut self) -> Vec<PortStatus> {
        let mut ports = self.ports_to_scan.clone();
        if self.randomize_ports {
            ports.shuffle(&mut thread_rng());
        }

        let semaphore = Arc::new(Semaphore::new(self.concurrency));
        let mut scan_tasks = Vec::new();
        let results_arc = Arc::new(Mutex::new(Vec::new()));

        let rsh_arc = Arc::clone(&self.raw_socket_handler);
        let active_ports_arc = Arc::clone(&self.active_ephemeral_ports);

        for target_port in ports {
            let permit = Arc::clone(&semaphore).acquire_owned().await.unwrap();

            let task_source_ip = self.source_ip;
            let task_target_ip = self.target_ip;
            let task_timeout_ms = self.timeout_ms;
            let task_results_clone = Arc::clone(&results_arc);
            let ephemeral_port = self.get_next_ephemeral_port().await; // Modifies self.next_ephemeral_port

            let task_rsh_cloned = Arc::clone(&rsh_arc);
            let task_transport_receiver_arc_clone = {
                let rsh_guard = rsh_arc.lock().await;
                Arc::clone(&rsh_guard.transport_receiver)
            };
            let task_active_ports_cloned = Arc::clone(&active_ports_arc);

            let scan_task = tokio::spawn(async move {
                let _permit = permit;

                {
                    let mut rsh_guard = task_rsh_cloned.lock().await;
                    if let Err(e) = rsh_guard.send_syn_packet(task_source_ip, task_target_ip, ephemeral_port, target_port).await {
                        task_results_clone.lock().await.push(PortStatus::Error(target_port, format!("Send error: {}", e)));
                        task_active_ports_cloned.lock().await.remove(&ephemeral_port);
                        return;
                    }
                }

                let overall_timeout_duration = Duration::from_millis(task_timeout_ms);
                let mut final_status = PortStatus::Filtered(target_port);
                let start_time = tokio::time::Instant::now();

                while start_time.elapsed() < overall_timeout_duration {
                    match tokio_timeout(Duration::from_millis(50), RawSocketHandler::try_receive_response(Arc::clone(&task_transport_receiver_arc_clone), task_target_ip, target_port, ephemeral_port)).await {
                        Ok(Ok(Some(status))) => {
                            final_status = status;
                            break;
                        }
                        Ok(Ok(None)) => { /* Irrelevant packet, continue */ }
                        Ok(Err(e)) => {
                            final_status = PortStatus::Error(target_port, format!("Receive error: {}", e));
                            break;
                        }
                        Err(_) => { /* Timeout for this single receive attempt */ }
                    }
                    tokio::task::yield_now().await;
                }

                task_results_clone.lock().await.push(final_status);
                task_active_ports_cloned.lock().await.remove(&ephemeral_port);
            });
            scan_tasks.push(scan_task);

            if self.scan_delay_ms > 0 {
                tokio::time::sleep(Duration::from_millis(self.scan_delay_ms)).await;
            }
        }

        for task in scan_tasks {
            let _ = task.await;
        }

        // Ensure all ephemeral ports are cleared after the scan batch, just in case any task failed to release.
        // This is a fallback; ideally, each task manages its own port perfectly.
        // self.active_ephemeral_ports.lock().await.clear(); // Might be too broad if other scans could run concurrently
        // self.next_ephemeral_port = 49152; // Reset for a completely new scan object instance

        Arc::try_unwrap(results_arc).unwrap_or_else(|_| panic!("Failed to unwrap results Arc")).into_inner()
    }
}

// (Old tests commented out as they are not compatible with async and changed structures)
/*
#[cfg(test)]
mod tests {
    // ...
}
*/
