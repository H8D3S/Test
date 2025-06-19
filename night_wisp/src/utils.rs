use pnet_datalink::{interfaces, NetworkInterface};
use std::net::IpAddr;
use std::collections::HashSet; // For unique ports

#[derive(Debug, Clone)]
pub struct SelectedInterfaceInfo {
    pub interface: NetworkInterface,
    pub source_ip: IpAddr,
    // MAC address can be added later if needed for Layer 2 sending
    // pub source_mac: Option<MacAddr>,
}

/// Lists all available network interfaces.
pub fn list_available_interfaces() {
    println!("Available network interfaces:");
    for interface in interfaces() {
        println!("  Name: {}", interface.name);
        println!("    Index: {}", interface.index);
        println!("    Flags: {:?}", interface.flags);
        println!("    MAC: {:?}", interface.mac);
        println!("    IPs:");
        for ip_network in &interface.ips {
            println!("      - {}", ip_network);
        }
        println!("-------------------------------");
    }
}

/// Selects a network interface based on the provided name or attempts to find a suitable default.
/// Returns the chosen interface and its primary IPv4 address if found.
pub fn select_interface(name_opt: Option<&String>) -> Result<SelectedInterfaceInfo, String> {
    let all_interfaces = interfaces();

    let candidate_interface = match name_opt {
        Some(name) => {
            all_interfaces
                .into_iter()
                .find(|iface| iface.name == *name)
                .ok_or_else(|| format!("Interface '{}' not found.", name))?
        }
        None => {
            // Attempt to find a suitable default interface
            // Criteria: Up, not loopback, has an IPv4 address
            all_interfaces
                .into_iter()
                .filter(|iface| {
                    iface.is_up() && !iface.is_loopback() && iface.ips.iter().any(|ip| ip.is_ipv4())
                })
                .min_by_key(|iface| iface.index) // Prefer lower index interface if multiple candidates
                .ok_or_else(|| "No suitable default interface found. Please specify one.".to_string())?
        }
    };

    // Find a source IPv4 address for the selected interface
    let source_ip = candidate_interface
        .ips
        .iter()
        .find_map(|ip_net| {
            if ip_net.is_ipv4() {
                Some(ip_net.ip())
            } else {
                None
            }
        })
        .ok_or_else(|| format!("Interface '{}' does not have an IPv4 address.", candidate_interface.name))?;

    Ok(SelectedInterfaceInfo {
        interface: candidate_interface,
        source_ip,
    })
}

// --- New Port Parsing Logic ---
/// Parses a port string (e.g., "80", "22,80,443", "1-1024", "22,80-85,443") into a sorted Vec of unique u16 port numbers.
pub fn parse_ports(ports_str: &str) -> Result<Vec<u16>, String> {
    let mut unique_ports: HashSet<u16> = HashSet::new();

    for part in ports_str.split(',') {
        let trimmed_part = part.trim();
        if trimmed_part.is_empty() {
            continue;
        }

        if trimmed_part.contains('-') {
            // Range
            let range_parts: Vec<&str> = trimmed_part.splitn(2, '-').collect();
            if range_parts.len() != 2 {
                return Err(format!("Invalid port range format: '{}'", trimmed_part));
            }

            let start_port_str = range_parts[0].trim();
            let end_port_str = range_parts[1].trim();

            let start_port: u16 = start_port_str.parse().map_err(|_| {
                format!("Invalid start port number: '{}' in range '{}'", start_port_str, trimmed_part)
            })?;
            let end_port: u16 = end_port_str.parse().map_err(|_| {
                format!("Invalid end port number: '{}' in range '{}'", end_port_str, trimmed_part)
            })?;

            if start_port == 0 || end_port == 0 {
                return Err(format!("Port number 0 is invalid in range '{}'", trimmed_part));
            }
            if start_port > end_port {
                return Err(format!(
                    "Start port {} cannot be greater than end port {} in range '{}'",
                    start_port, end_port, trimmed_part
                ));
            }

            for port in start_port..=end_port {
                unique_ports.insert(port);
            }
        } else {
            // Single port
            let port: u16 = trimmed_part.parse().map_err(|_| {
                format!("Invalid port number: '{}'", trimmed_part)
            })?;
            if port == 0 {
                return Err(format!("Port number 0 is invalid: '{}'", trimmed_part));
            }
            unique_ports.insert(port);
        }
    }

    if unique_ports.is_empty() {
        return Err("No ports specified or parsed.".to_string());
    }

    let mut sorted_ports: Vec<u16> = unique_ports.into_iter().collect();
    sorted_ports.sort_unstable();
    Ok(sorted_ports)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ports_single() {
        assert_eq!(parse_ports("80"), Ok(vec![80]));
    }

    #[test]
    fn test_parse_ports_list() {
        assert_eq!(parse_ports("80,443,22"), Ok(vec![22, 80, 443]));
    }

    #[test]
    fn test_parse_ports_range() {
        assert_eq!(parse_ports("1-5"), Ok(vec![1, 2, 3, 4, 5]));
    }

    #[test]
    fn test_parse_ports_range_single_val() {
        assert_eq!(parse_ports("80-80"), Ok(vec![80]));
    }

    #[test]
    fn test_parse_ports_combined() {
        assert_eq!(parse_ports("443,22,80-82,10"), Ok(vec![10, 22, 80, 81, 82, 443]));
    }

    #[test]
    fn test_parse_ports_with_whitespace() {
        assert_eq!(parse_ports(" 80 , 443 , 1-5 "), Ok(vec![1, 2, 3, 4, 5, 80, 443]));
    }

    #[test]
    fn test_parse_ports_duplicates() {
        assert_eq!(parse_ports("80,80,1-3,2"), Ok(vec![1, 2, 3, 80]));
    }

    #[test]
    fn test_parse_ports_empty_part() {
        assert_eq!(parse_ports("80,,443"), Ok(vec![80, 443]));
    }

    #[test]
    fn test_parse_ports_empty_string() {
        assert!(parse_ports("").is_err());
    }

    #[test]
    fn test_parse_ports_just_comma() {
        assert!(parse_ports(",").is_err());
    }

    #[test]
    fn test_parse_ports_invalid_number() {
        assert!(parse_ports("80,abc").is_err());
    }

    #[test]
    fn test_parse_ports_invalid_range_format() {
        assert!(parse_ports("80-").is_err());
        assert!(parse_ports("-80").is_err());
        assert!(parse_ports("80-90-100").is_err());
    }

    #[test]
    fn test_parse_ports_invalid_range_numbers() {
        assert!(parse_ports("abc-90").is_err());
        assert!(parse_ports("80-xyz").is_err());
    }

    #[test]
    fn test_parse_ports_range_start_greater_than_end() {
        assert!(parse_ports("90-80").is_err());
    }

    #[test]
    fn test_parse_ports_port_zero() {
        assert!(parse_ports("0").is_err());
        assert!(parse_ports("0-10").is_err());
        assert!(parse_ports("10-0").is_err()); // This will be caught by start > end or by parse error for 0 if start==0
        assert!(parse_ports("80,0").is_err());
    }
}
