use pnet_packet::ip::IpNextHeaderProtocols;
use pnet_packet::ipv4::{self, MutableIpv4Packet};
use pnet_packet::tcp::{self, MutableTcpPacket, TcpFlags};
use pnet_packet::Packet; // Needed for .packet() method to get byte slice
use std::net::Ipv4Addr;


// Define a constant for typical TCP header length in 32-bit words for offset calculation
const TCP_HEADER_LEN_WORDS: u8 = 5; // Minimum TCP header length (20 bytes / 4 bytes per word)
const IPV4_HEADER_LEN_BYTES: usize = 20; // Standard IPv4 header length
const TCP_HEADER_LEN_BYTES: usize = 20; // Standard TCP header length (no options)


/// Builds a TCP SYN packet.
///
/// # Arguments
/// * `source_ip` - The source IPv4 address.
/// * `dest_ip` - The destination IPv4 address.
/// * `source_port` - The source TCP port.
/// * `dest_port` - The destination TCP port.
/// * `ttl` - Time To Live for the IP packet.
///
/// # Returns
/// A `Vec<u8>` containing the raw bytes of the TCP SYN packet, ready for sending.
/// Returns an Error string if packet construction fails.
pub fn build_syn_packet(
    source_ip: Ipv4Addr,
    dest_ip: Ipv4Addr,
    source_port: u16,
    dest_port: u16,
    ttl: u8,
    // seq_num: u32, // Sequence number can be randomized or start from a fixed point
) -> Result<Vec<u8>, String> {
    // --- Create IPv4 Packet ---
    let mut ip_header_buffer = vec![0u8; IPV4_HEADER_LEN_BYTES];
    let mut new_ipv4_packet = MutableIpv4Packet::new(&mut ip_header_buffer).ok_or("Failed to create IPv4 packet")?;

    new_ipv4_packet.set_version(4);
    new_ipv4_packet.set_header_length(5); // 5 * 4 = 20 bytes
    new_ipv4_packet.set_total_length((IPV4_HEADER_LEN_BYTES + TCP_HEADER_LEN_BYTES) as u16);
    new_ipv4_packet.set_identification(rand::random::<u16>()); // Random ID
    new_ipv4_packet.set_flags(ipv4::Ipv4Flags::DontFragment);
    new_ipv4_packet.set_ttl(ttl);
    new_ipv4_packet.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
    new_ipv4_packet.set_source(source_ip);
    new_ipv4_packet.set_destination(dest_ip);

    let ipv4_checksum = ipv4::checksum(&new_ipv4_packet.to_immutable());
    new_ipv4_packet.set_checksum(ipv4_checksum);

    // --- Create TCP Packet ---
    let mut tcp_header_buffer = vec![0u8; TCP_HEADER_LEN_BYTES];
    let mut new_tcp_packet = MutableTcpPacket::new(&mut tcp_header_buffer).ok_or("Failed to create TCP packet")?;

    new_tcp_packet.set_source(source_port);
    new_tcp_packet.set_destination(dest_port);
    new_tcp_packet.set_sequence(rand::random::<u32>()); // Random sequence number
    new_tcp_packet.set_acknowledgement(0);
    new_tcp_packet.set_data_offset(TCP_HEADER_LEN_WORDS);
    new_tcp_packet.set_reserved(0);
    new_tcp_packet.set_flags(TcpFlags::SYN);
    new_tcp_packet.set_window(65535);
    new_tcp_packet.set_urgent_ptr(0);

    let tcp_checksum = tcp::ipv4_checksum(&new_tcp_packet.to_immutable(), &source_ip, &dest_ip);
    new_tcp_packet.set_checksum(tcp_checksum);

    // Combine headers
    let mut final_packet_buffer = Vec::with_capacity(IPV4_HEADER_LEN_BYTES + TCP_HEADER_LEN_BYTES);
    final_packet_buffer.extend_from_slice(new_ipv4_packet.packet());
    final_packet_buffer.extend_from_slice(new_tcp_packet.packet());

    Ok(final_packet_buffer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use pnet_packet::ipv4::Ipv4Packet;
    use pnet_packet::tcp::TcpPacket;

    #[test]
    fn test_build_syn_packet() {
        let source_ip = Ipv4Addr::new(192, 168, 1, 100);
        let dest_ip = Ipv4Addr::new(192, 168, 1, 1);
        let source_port = 12345;
        let dest_port = 80;
        let ttl = 64;

        match build_syn_packet(source_ip, dest_ip, source_port, dest_port, ttl) {
            Ok(packet_bytes) => {
                assert_eq!(packet_bytes.len(), IPV4_HEADER_LEN_BYTES + TCP_HEADER_LEN_BYTES);

                let parsed_ip_packet = Ipv4Packet::new(&packet_bytes[..IPV4_HEADER_LEN_BYTES]).expect("Failed to parse IP packet");
                assert_eq!(parsed_ip_packet.get_version(), 4);
                assert_eq!(parsed_ip_packet.get_destination(), dest_ip);
                assert_eq!(parsed_ip_packet.get_source(), source_ip);
                assert_eq!(parsed_ip_packet.get_next_level_protocol(), IpNextHeaderProtocols::Tcp);
                assert_eq!(parsed_ip_packet.get_total_length() as usize, IPV4_HEADER_LEN_BYTES + TCP_HEADER_LEN_BYTES);

                let tcp_packet_slice = &packet_bytes[IPV4_HEADER_LEN_BYTES..];
                let parsed_tcp_packet = TcpPacket::new(tcp_packet_slice).expect("Failed to parse TCP packet");
                assert_eq!(parsed_tcp_packet.get_destination(), dest_port);
                assert_eq!(parsed_tcp_packet.get_source(), source_port);
                assert_eq!(parsed_tcp_packet.get_flags() & TcpFlags::SYN, TcpFlags::SYN);
                assert_eq!(parsed_tcp_packet.get_flags() & TcpFlags::ACK, 0); // Ensure ACK is not set
                assert_eq!(parsed_tcp_packet.get_data_offset(), TCP_HEADER_LEN_WORDS);
            }
            Err(e) => {
                panic!("Failed to build SYN packet: {}", e);
            }
        }
    }
}
