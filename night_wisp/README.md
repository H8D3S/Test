# NIGHT WISP Port Scanner

NIGHT WISP is a port scanner written in Rust, designed with a focus on speed and stealth. It utilizes SYN scanning (half-open scanning) techniques to identify open ports on a target host while minimizing the chances of detection.

## Prerequisites

Before you can build and run NIGHT WISP, you'll need the following:

1.  **Rust:** Ensure you have a recent version of Rust installed. You can get it from [rust-lang.org](https://www.rust-lang.org/).
2.  **Root/Administrator Privileges:** NIGHT WISP uses raw sockets to perform SYN scans. Creating raw sockets typically requires elevated privileges. Therefore, you **must run NIGHT WISP as root (on Linux/macOS) or as an Administrator (on Windows)**.

## Building NIGHT WISP

To build NIGHT WISP, navigate to the project's root directory (`night_wisp`) and run the following Cargo command:

```bash
cargo build --release
```

This will compile the scanner in release mode, optimizing for performance. The executable will be located at `target/release/night_wisp`.

## Usage

NIGHT WISP is controlled via command-line arguments. Remember to run it with root/administrator privileges.

```bash
sudo ./target/release/night_wisp [OPTIONS] <TARGET_IP>
```

Or on Windows (as Administrator):

```powershell
./target/release/night_wisp.exe [OPTIONS] <TARGET_IP>
```

### Arguments and Options

*   **`<TARGET_IP>`** (Required)
    *   The IP address of the host you want to scan.
    *   Example: `192.168.1.1`

*   **`-p, --ports <PORTS_SPECIFICATION>`**
    *   Specifies the ports to scan.
    *   Default: `1-1024`
    *   Formats:
        *   Single port: `80`
        *   Comma-separated list: `22,80,443`
        *   Range: `1-100`
        *   Combined: `22,80,443,1000-2000`

*   **`-c, --concurrency <NUMBER>`**
    *   Sets the number of concurrent scanning tasks. Higher values can speed up scans but might overwhelm the network or the target.
    *   Default: `100`

*   **`--timeout <MILLISECONDS>`**
    *   Specifies the timeout in milliseconds to wait for a response for each port. If no response is received within this time, the port might be marked as filtered or timed out.
    *   Default: `1000` (1 second)

*   **`--scan-delay <MILLISECONDS>`**
    *   Adds a delay in milliseconds between sending packets. This can be used to slow down the scan rate, potentially making it less detectable or less resource-intensive on the network.
    *   Default: `0` (no delay)

*   **`--randomize-ports`**
    *   A flag that, when present, tells the scanner to scan ports in a random order instead of sequentially. This can help in evading simple detection systems that look for sequential scans.

*   **`--interface <INTERFACE_NAME>`**
    *   Allows you to specify the network interface (e.g., `eth0`, `en0`, `Ethernet 2`) to use for sending and receiving raw packets.
    *   If not specified, NIGHT WISP will attempt to select a suitable default interface. It's recommended to specify this if you have multiple active interfaces or if the default selection is not working correctly.

*   **`-v, --verbose`**
    *   Enables verbose output. This will provide more detailed information about the scanning process, including selected interface details, and potentially information about closed or filtered ports (once fully implemented).

### Example Commands

1.  **Scan common ports on a target:**
    ```bash
    sudo ./target/release/night_wisp 192.168.1.100
    ```

2.  **Scan specific ports (HTTP, HTTPS, SSH) with higher concurrency:**
    ```bash
    sudo ./target/release/night_wisp -p 22,80,443 -c 200 192.168.1.100
    ```

3.  **Scan a full range of ports with a longer timeout and verbose output, on a specific interface:**
    ```bash
    sudo ./target/release/night_wisp -p 1-65535 --timeout 2000 --interface eth0 -v 10.0.0.5
    ```

4.  **Scan ports in random order with a slight delay between probes:**
    ```bash
    sudo ./target/release/night_wisp --randomize-ports --scan-delay 10 192.168.1.100
    ```

## Current Status

**NIGHT WISP is now a functional SYN port scanner!**

The core features have been implemented, including:
*   Asynchronous SYN scanning using raw sockets.
*   User-configurable target IP and port specifications (single, list, range).
*   Adjustable concurrency to control scan speed.
*   Customizable timeouts for port responses.
*   Optional delay between scan probes.
*   Ability to randomize the order of scanned ports.
*   Network interface selection.
*   Verbose mode for detailed output.

While the core functionality is operational, future enhancements could include:
*   Service version detection.
*   OS fingerprinting (more advanced).
*   Different scan types (e.g., TCP Connect, UDP, FIN, Xmas - though SYN is the primary focus).
*   Output to different formats (e.g., JSON, XML).
