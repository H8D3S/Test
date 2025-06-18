use clap::Parser;
use std::net::IpAddr;
use std::time::Duration;

mod packet;
mod scanner;
mod utils;

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

    /// Scan delay in milliseconds between sending packets
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

    if cli.verbose {
        println!("NIGHT WISP activated. Target: {}", cli.target);
        println!("Ports: {}", cli.ports);
        println!("Concurrency: {}", cli.concurrency);
        println!("Timeout: {}ms", cli.timeout);
        println!("Scan Delay: {}ms", cli.scan_delay);
        println!("Randomize Ports: {}", cli.randomize_ports);
        if let Some(iface) = &cli.interface {
            println!("Interface: {}", iface);
        }
    }

    if cli.verbose {
        // List all interfaces if verbose, for debugging/user info
        utils::list_available_interfaces();
    }

    let selected_iface_info = match utils::select_interface(cli.interface.as_ref()) {
        Ok(info) => {
            if cli.verbose {
                println!(
                    "Using interface: {} with IP: {}",
                    info.interface.name, info.source_ip
                );
            }
            info
        }
        Err(e) => {
            eprintln!("Error selecting network interface: {}", e);
            // Attempt to list interfaces to help the user, then exit.
            println!("Please try specifying an interface with --interface <name>.");
            utils::list_available_interfaces();
            std::process::exit(1);
        }
    };

    // Placeholder for future logic
    // 1. Parse ports string
    // 2. Initialize scanner (scanner::Scanner::new with selected_iface_info)
    // 3. Run scan (scanner.scan().await)

    println!("Scan logic not yet implemented.");
    println!("Parsed arguments: {:#?}", cli);
    println!("Selected interface details: {:#?}", selected_iface_info);

    // utils::some_utility_function(); // Keep this commented unless testing utils directly
}
