use pnet_datalink::{interfaces, NetworkInterface};
use std::net::IpAddr;

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

// Placeholder for testing, remove or comment out later
pub fn some_utility_function() {
    println!("Utils module placeholder function called.");
    list_available_interfaces();
    match select_interface(None) {
        Ok(selected_iface_info) => {
            println!("Selected interface (auto): {} with IP {}", selected_iface_info.interface.name, selected_iface_info.source_ip);
        }
        Err(e) => eprintln!("Error selecting interface: {}", e),
    }
     match select_interface(Some(&"eth0".to_string())) { // Example, this might fail if eth0 doesn't exist
        Ok(selected_iface_info) => {
            println!("Selected interface (eth0): {} with IP {}", selected_iface_info.interface.name, selected_iface_info.source_ip);
        }
        Err(e) => eprintln!("Error selecting eth0 interface: {}", e),
    }
}
