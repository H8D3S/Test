use clap::Parser;
use std::net::IpAddr;
// HashMap usage is fully qualified, so direct import is not strictly needed.

mod packet;
mod scanner;
mod utils;

// Cli struct remains the same as defined in step 3 of the previous plan (before README)
// (target, ports, concurrency, timeout, scan_delay, randomize_ports, interface, verbose)
/// NIGHT WISP: A fast and stealthy port scanner.
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    /// Target host IP address
    #[clap(required = true)]
    target: IpAddr,

    /// Ports to scan. Can be a single port, a comma-separated list (e.g., 80,443),
    /// or a range (e.g., 1-1024).
    #[clap(short, long, default_value = "1-1024")]
    ports: String,

    /// Number of concurrent scanning tasks
    #[clap(short, long, default_value_t = 100)]
    concurrency: usize,

    /// Timeout in milliseconds for each port scan attempt
    #[clap(long, default_value_t = 1000)]
    timeout: u64,

    /// Scan delay in milliseconds between sending packets (more accurately, between spawning scan tasks)
    #[clap(long, default_value_t = 0)]
    scan_delay: u64,

    /// Randomize port scanning order
    #[clap(long)]
    randomize_ports: bool,

    /// Network interface to use for scanning
    #[clap(long)]
    interface: Option<String>,

    /// Verbose output
    #[clap(short, long)]
    verbose: bool,
}


#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    if !cli.target.is_ipv4() {
        eprintln!("Error: NIGHT WISP currently only supports IPv4 targets.");
        std::process::exit(1);
    }
    let target_ipv4 = match cli.target {
        IpAddr::V4(ip4) => ip4,
        IpAddr::V6(_) => {
            eprintln!("Error: IPv6 target specified, but only IPv4 is supported.");
            std::process::exit(1);
        }
    };

    if cli.verbose {
        println!("NIGHT WISP - Fast & Stealthy Port Scanner");
        println!("==========================================");
        println!("Configuration:");
        println!("  Target IP: {}", target_ipv4);
        println!("  Ports: {}", cli.ports);
        println!("  Concurrency: {}", cli.concurrency);
        println!("  Timeout (ms): {}", cli.timeout);
        println!("  Scan Delay (ms): {}", cli.scan_delay);
        println!("  Randomize Ports: {}", cli.randomize_ports);
    }

    let selected_iface_info = match utils::select_interface(cli.interface.as_ref()) {
        Ok(info) => {
            if !info.source_ip.is_ipv4(){
                eprintln!("Error: Selected interface {} does not have an IPv4 source address. NIGHT WISP currently requires IPv4.", info.interface.name);
                std::process::exit(1);
            }
            if cli.verbose {
                println!("  Interface: {} (Source IP: {})", info.interface.name, info.source_ip);
            }
            info
        }
        Err(e) => {
            eprintln!("Error selecting network interface: {}", e);
            if cli.verbose {
                 utils::list_available_interfaces();
            } else {
                eprintln!("Hint: Try running with -v to see available interfaces or specify one with --interface <name>.");
            }
            std::process::exit(1);
        }
    };

    let ports_to_scan = match utils::parse_ports(&cli.ports) {
        Ok(ports_vec) => {
            if ports_vec.is_empty() {
                eprintln!("Error: No valid ports found in specification: '{}'", cli.ports);
                std::process::exit(1);
            }
            if cli.verbose {
                println!("  Effective Ports ({}): {:?}", ports_vec.len(), ports_vec);
            }
            ports_vec
        }
        Err(e) => {
            eprintln!("Error parsing port specification '{}': {}", cli.ports, e);
            std::process::exit(1);
        }
    };

    if cli.verbose {
        println!("==========================================");
        println!("Starting scan...");
    } else {
        println!("Scanning {} on ports [{}]...", target_ipv4, cli.ports);
    }


    let mut night_wisp_scanner = match scanner::Scanner::new(
        target_ipv4,
        ports_to_scan.clone(),
        &selected_iface_info,
        cli.concurrency,
        cli.timeout,
        cli.scan_delay,
        cli.randomize_ports,
    ) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Error initializing scanner: {}", e);
            eprintln!("Hint: This might be due to issues creating raw sockets. Ensure you have root/administrator privileges.");
            std::process::exit(1);
        }
    };

    let start_time = std::time::Instant::now();
    let scan_results = night_wisp_scanner.run_scan().await;
    let scan_duration = start_time.elapsed();

    if cli.verbose {
        println!("Scan completed in {:.2?}.", scan_duration);
        println!("==========================================");
        println!("Results ({} ports scanned):", scan_results.len());
    }


    let mut open_ports = Vec::new();
    let mut closed_ports = Vec::new();
    let mut filtered_ports = Vec::new();
    let mut error_ports_map = std::collections::HashMap::new(); // Ensure HashMap is imported

    for status in scan_results {
        match status {
            scanner::PortStatus::Open(port) => open_ports.push(port),
            scanner::PortStatus::Closed(port) => closed_ports.push(port),
            scanner::PortStatus::Filtered(port) => filtered_ports.push(port),
            scanner::PortStatus::Error(port, err_msg) => {
                error_ports_map.insert(port, err_msg);
            }
        }
    }
    open_ports.sort_unstable();
    closed_ports.sort_unstable();
    filtered_ports.sort_unstable();

    println!("\n--- Open Ports on {} ---", target_ipv4);
    if open_ports.is_empty() {
        println!("No open ports found.");
    } else {
        for port in open_ports {
            // Could add service name resolution here in the future based on common ports
            println!("  Port {:<5} : Open", port);
        }
    }

    if cli.verbose {
        if !closed_ports.is_empty() {
            println!("\n--- Closed Ports ({}) ---", closed_ports.len());
            // Simplified: if verbose, print all. Truncation can be added back if needed for extreme cases.
            println!("  {:?}", closed_ports);
        }
        if !filtered_ports.is_empty() {
            println!("\n--- Filtered Ports (No Response/Timeout) ({}) ---", filtered_ports.len());
            println!("  {:?}", filtered_ports);
        }
        if !error_ports_map.is_empty() {
            println!("\n--- Ports with Errors ({}) ---", error_ports_map.len());
            let mut sorted_error_ports: Vec<_> = error_ports_map.iter().collect();
            sorted_error_ports.sort_by_key(|&(port, _)| port);
            for (port, err_msg) in sorted_error_ports {
                 println!("  Port {:<5} : Error - {}", port, err_msg);
            }
        }
    }

    println!("==========================================");
    if cli.verbose {
        println!("NIGHT WISP scan finished in {:.2?}.", scan_duration);
    } else {
        println!("Scan finished in {:.2?}.", scan_duration);
    }
}
