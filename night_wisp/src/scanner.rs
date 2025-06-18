use crate::packet; // To use build_syn_packet
use crate::utils::SelectedInterfaceInfo;
use pnet_packet::ip::IpNextHeaderProtocols;
use pnet_packet::ipv4::Ipv4Packet;
use pnet_packet::tcp::{TcpFlags, TcpPacket};
use pnet_packet::Packet; // Trait for packet parsing
use pnet_transport::{transport_channel, TransportChannelType, TransportReceiver, TransportSender}; // Added TransportReceiver
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;


// Renaming RawSender to RawSocketHandler as it will manage both sending and receiving.
pub struct RawSocketHandler {
    transport_sender: TransportSender,
    transport_receiver: TransportReceiver, // Added receiver
    target_ip: Ipv4Addr, // To filter incoming packets
    ephemeral_source_ports: HashSet<u16>, // To track source ports we used for probes
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PortStatus {
    Open(u16),      // Port is open
    Closed(u16),    // Port is closed (got RST-ACK)
    Filtered(u16),  // No response / Timeout
    Error(u16, String), // Error during scan for this port
}


impl RawSocketHandler {
    pub fn new(target_ip: Ipv4Addr) -> Result<Self, String> {
        // For sending IP packets, we use Layer3 with TCP protocol specified.
        let protocol_ip_tcp = IpNextHeaderProtocols::Tcp;
        let (ts, tr) = transport_channel( // Corrected: tr was not mutable here before, now it is by default from the tuple
            4096, // Buffer size
            TransportChannelType::Layer3(protocol_ip_tcp)
        )
        .map_err(|e| format!("Failed to create transport channel: {}", e))?;

        Ok(RawSocketHandler {
            transport_sender: ts,
            transport_receiver: tr,
            target_ip,
            ephemeral_source_ports: HashSet::new(),
        })
    }

    /// Sends a raw IP packet.
    pub fn send_syn_packet(
        &mut self,
        source_ip: Ipv4Addr,
        dest_ip: Ipv4Addr, // Should be self.target_ip for consistency
        source_port: u16,
        dest_port: u16,
    ) -> Result<(), String> {
        if dest_ip != self.target_ip {
            return Err("Destination IP in send_syn_packet does not match RawSocketHandler's target_ip".to_string());
        }
        let ttl = 64; // Default TTL

        let packet_bytes = packet::build_syn_packet(
            source_ip,
            dest_ip,
            source_port,
            dest_port,
            ttl,
        )?;

        // Register the source port as one we're using for a probe
        self.ephemeral_source_ports.insert(source_port);

        self.transport_sender
            .send_to(Ipv4Packet::new(&packet_bytes).unwrap(), IpAddr::V4(dest_ip))
            .map_err(|e| format!("Failed to send packet: {}", e))?;
        Ok(())
    }

    /// Receives and processes one packet from the channel.
    /// This is a simplified version; a real implementation needs to run this in a loop
    /// and correlate responses.
    /// This function would typically be called repeatedly by a dedicated listening task.
    pub fn receive_and_process_packet(&mut self) -> Result<Option<PortStatus>, String> {
        // Create an iterator from the transport receiver.
        // next() will block until a packet arrives or an error occurs.
        // We need a timeout mechanism here for practical use, which will be added
        // when integrating with Tokio tasks. For now, this is a conceptual blocking receive.

        // For non-blocking with timeout, one would typically use tokio::select! with
        // a future from the receiver and a timeout future.
        // Or, use a raw socket with `set_read_timeout`. `pnet_transport` receiver
        // itself doesn't directly expose timeouts on `next()`.
        // For now, we'll simulate a single blocking receive attempt.

        // Use the pnet_transport::ipv4_packet_iter helper function.
        // This function takes &mut TransportReceiver and returns Box<dyn Ipv4PacketIterator>
        // or panics if the receiver is not the Ipv4 variant.
        // Given we created the channel for IPv4, this should be safe.
        let mut iter = pnet_transport::ipv4_packet_iter(&mut self.transport_receiver);

        match iter.next() {
            Ok((packet, remote_addr)) => {
                // Ensure the packet is from our target IP
                if remote_addr != IpAddr::V4(self.target_ip) {
                    return Ok(None); // Not from target, ignore
                }

                // Parse as IPv4 packet
                let ipv4_packet = match Ipv4Packet::new(packet.packet()) {
                    Some(pkt) => pkt,
                    None => return Ok(None), // Not an IPv4 packet or too short
                };

                // Check if it's a TCP packet
                if ipv4_packet.get_next_level_protocol() == IpNextHeaderProtocols::Tcp {
                    let tcp_packet = match TcpPacket::new(ipv4_packet.payload()) {
                        Some(pkt) => pkt,
                        None => return Ok(None), // Not a TCP packet or too short
                    };

                    // Is the packet destined for one of our ephemeral source ports?
                    let dest_port_of_response = tcp_packet.get_destination();
                    if !self.ephemeral_source_ports.contains(&dest_port_of_response) {
                        return Ok(None); // Not for one of our probes
                    }

                    // We should remove the port from ephemeral_source_ports once a definitive response is received for it.
                    // self.ephemeral_source_ports.remove(&dest_port_of_response); // Do this when scan for this port is conclusive

                    let flags = tcp_packet.get_flags();
                    let original_probe_dest_port = tcp_packet.get_source(); // The port we originally probed on the target

                    if (flags & TcpFlags::SYN) != 0 && (flags & TcpFlags::ACK) != 0 {
                        // SYN-ACK: Port is Open
                        // Mark this ephemeral port as handled (it might be reused later, but this specific probe is done)
                        // self.ephemeral_source_ports.remove(&dest_port_of_response);
                        return Ok(Some(PortStatus::Open(original_probe_dest_port)));
                    } else if (flags & TcpFlags::RST) != 0 || (flags & TcpFlags::RST | TcpFlags::ACK) != 0 {
                        // RST or RST-ACK: Port is Closed
                        // self.ephemeral_source_ports.remove(&dest_port_of_response);
                        return Ok(Some(PortStatus::Closed(original_probe_dest_port)));
                    }
                }
                Ok(None) // Not a TCP packet we care about
            }
            Err(e) => {
                // This error means the transport channel is broken or encountered a problem.
                Err(format!("Error receiving packet: {}", e))
            }
        }
    }

    // Method to remove a source port from tracking once its scan is conclusive
    pub fn mark_port_scan_conclusive(&mut self, source_port: u16) {
        self.ephemeral_source_ports.remove(&source_port);
    }
}


// Placeholder scanner function - this will be the main entry point for scanning later.
pub fn placeholder_scanner() {
    println!("Scanner module placeholder. Testing receive logic (requires privileges and a target sending responses).");

    let target_test_ip = Ipv4Addr::new(127, 0, 0, 1); // Example: loopback

    match RawSocketHandler::new(target_test_ip) {
        Ok(mut handler) => {
            println!("RawSocketHandler created. Listening for packets...");
            println!("To test, send a TCP packet to this machine on an ephemeral port from {}", target_test_ip);
            println!("This basic test will only attempt to receive one packet and then exit.");

            // Simulate sending a probe so a source port is registered
            // In a real scan, this would be coordinated.
            let test_source_ip = Ipv4Addr::new(127,0,0,1); // Needs to be a local IP on the machine running this
            let test_source_port = 55555;
            let test_target_port = 80; // Port we are "pretending" to probe on target

            // Manually add a port to listen for, as if we sent a probe
            handler.ephemeral_source_ports.insert(test_source_port);
            println!("Test: Registered source port {} for listening.", test_source_port);


            // This is a blocking call for one packet.
            // In a real scenario, this needs to be in a loop, likely in a separate Tokio task,
            // and use timeouts (e.g. tokio::time::timeout around the receive logic,
            // or use a non-blocking socket if pnet_transport doesn't offer async directly).
            match handler.receive_and_process_packet() {
                Ok(Some(status)) => {
                    println!("Received and processed packet. Status: {:?}", status);
                     if let PortStatus::Open(port) | PortStatus::Closed(port) = status {
                        // This logic isn't quite right, it should be dest_port_of_response which is our source_port for the probe
                        // handler.mark_port_scan_conclusive(port);
                        handler.mark_port_scan_conclusive(test_source_port); // Corrected: use the source port we registered
                    }
                }
                Ok(None) => {
                    println!("Received a packet, but it was not relevant to our probes or was malformed.");
                }
                Err(e) => {
                    eprintln!("Error during receive_and_process_packet: {}", e);
                }
            }
        }
        Err(e) => {
            eprintln!("Failed to initialize RawSocketHandler: {}", e);
        }
    }
}
// (tests for receive logic are hard to automate without a complex setup, will be deferred or done manually)
