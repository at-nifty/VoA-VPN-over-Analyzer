# VoA (VPN over Analyzer): DPI Validation Scripts

This repository contains Python scripts and configurations designed for **VoA (VPN over Analyzer)** – a framework to systematically validate the Deep Packet Inspection (DPI) capabilities of network security tools like Zeek and Suricata. The core objective is to rigorously test how effectively these tools can identify and differentiate between various types of network traffic, especially when common protocols are intentionally obfuscated within VPN tunnels (e.g., SoftEther VPN TCP 443, TCP 53, VPN over DNS and VPN over ICMP).

---

## Project Overview

This project simulates a controlled network environment to assess DPI tool performance. It involves three key virtual machines: a client (TX VM), a central gateway/DPI server (MX VM), and a VPN server (RX VM). The scripts generate a dynamic mix of "normal" network traffic (standard HTTPS, DNS, ICMP) and "obfuscated" VPN traffic (SoftEther VPN configured to run over TCP 443, TCP 53, or ICMP).

A critical feature of this framework is the embedding of a **unique Packet ID** within each generated packet's payload (e.g., HTTP User-Agent string, ICMP data payload, or DNS query name). This allows for precise "answer matching" during the DPI analysis on the MX VM, enabling a quantitative and verifiable evaluation of the DPI tools' accuracy in real-time traffic scenarios.

---

## Key Components

* **TX VM (Traffic Generator / VPN Client)**:
    * Generates diverse network traffic patterns.
    * Hosts the **SoftEther VPN client**, establishing a VPN tunnel to the RX VM.
    * Intelligently routes specific test traffic through the VPN tunnel while other traffic utilizes the normal gateway path.
    * Maintains comprehensive logs of all sent traffic, including timestamps and packet IDs, for post-analysis comparison.

* **MX VM (Gateway / DPI Server)**:
    * Serves as the central network **gateway**, routing both normal and VPN-encapsulated traffic.
    * Runs **Zeek** and **Suricata**, configured for Deep Packet Inspection on all relevant network interfaces (`ens19` for TX-facing traffic, `ens20` for RX-facing traffic).
    * Its primary role is to accurately identify the true nature of the traffic, even when protocols are intentionally disguised.
    * Additionally functions as a **DNS server**, forwarding queries upstream from both normal and VPN-tunneled clients.

* **RX VM (SoftEther VPN Server)**:
    * Hosts the **SoftEther VPN server**, acting as the termination point for the VPN tunnel initiated by the TX VM.
    * Serves as the destination for VPN-tunneled traffic (e.g., a simple HTTP server for encapsulated web requests or a DNS resolver for tunneled DNS queries).

---

## Getting Started

### Prerequisites

Recommended Virtualization Platform
For setting up the virtual machine environment (TX, MX, RX VMs), Proxmox Virtual Environment is highly recommended. Proxmox offers a robust, open-source platform that is excellent for managing virtual machines and containers, making it ideal for this DPI validation setup. Its web-based management interface simplifies VM creation, network configuration, and snapshot management, which are crucial for this kind of experimental network environment.

Before you begin, ensure the following components are set up and configured:

* **Virtual Machines**: Properly configured TX, MX, and RX VMs with their respective network interfaces (e.g., `ens18` on TX; `ens18`, `ens19`, `ens20` on MX; `ens18` on RX).
* **Operating System**: Linux (e.g., Ubuntu/Debian) installed on all VMs.
* **SoftEther VPN**: SoftEther VPN Client installed on the **TX VM** and SoftEther VPN Server installed on the **RX VM**.
* **DPI Tools**: **Zeek** and **Suricata** installed and configured on the **MX VM** to monitor `ens19` and `ens20` interfaces.
* **Python 3**: Installed on both **TX** and **MX** VMs.
* **Scapy**: The Python packet manipulation library (`pip install scapy`) installed in the Python environment on both TX and MX.
* **Git**: Installed on both **TX** and **MX** VMs for seamless script management and synchronization.

### Setup Instructions

1.  **Clone this Repository**:
    On both your **TX VM** and **MX VM**, navigate to your desired working directory (e.g., `/home/user/`) and clone this repository.
    ```bash
    cd /home/user/
    git clone [https://github.com/YourUsername/VoA-VPN-over-Analyzer.git](https://github.com/YourUsername/VoA-VPN-over-Analyzer.git) # IMPORTANT: Replace with your actual repository URL
    cd VoA-VPN-over-Analyzer
    ```
    * **Note**: If you created an empty repository on GitHub, ensure you add at least a `README.md` file (e.g., directly on GitHub) before attempting to clone, as `vscode.dev` cannot open completely empty repositories.

2.  **Set Up Python Virtual Environment**:
    Inside the `VoA-VPN-over-Analyzer` directory on both the **TX VM** and **MX VM**, create and activate a Python virtual environment, then install necessary libraries:
    ```bash
    python3 -m venv venv_voa
    source venv_voa/bin/activate
    pip install scapy
    # Install any other Python libraries as required by your scripts
    deactivate # Exit virtual environment when done
    ```
    * Remember to `source venv_voa/bin/activate` each time you open a new terminal session where you intend to run the Python scripts.

3.  **Configure Network Routing on TX VM**:
    On your **TX VM**, ensure that its default network route correctly points to the MX VM (`192.168.41.99`). Additionally, you **must** set up a static route to direct all traffic destined for the **RX VM's IP address** (`192.168.42.12`) through the SoftEther VPN virtual interface (`vpn_vpn01`).
    ```bash
    # Example route command (adjust IP addresses as per your setup)
    sudo ip route add 192.168.42.12 via 192.168.42.1 dev vpn_vpn01
    ```
    * Confirm your SoftEther VPN client is connected and the `vpn_vpn01` interface is active and has an IP address (e.g., `192.168.42.111`).

4.  **Prepare RX VM for Traffic Reception**:
    If your `traffic_generator.py` script includes tests for HTTP over VPN, ensure a simple web server is running on your **RX VM** (e.g., `python3 -m http.server 80` for HTTP).

---

## Usage

### Developing Scripts with VS Code (Recommended)

* **VS Code Desktop with Remote - SSH**: For the most seamless development experience, use VS Code on your local machine with the Remote - SSH extension. This allows you to directly open and edit files on your MX (or TX) VM as if they were local, with full debugging capabilities.
* **VS Code.dev with Git Sync**: If you prefer a browser-based workflow, edit scripts via `vscode.dev` by opening this GitHub repository. After making changes, `git push` from `vscode.dev`, then `git pull` on your MX/TX VM to update the scripts before execution.

### Running the Traffic Generator (on TX VM)

1.  Navigate to the cloned repository directory: `cd /home/user/VoA-VPN-over-Analyzer`
2.  Activate the Python virtual environment: `source venv_voa/bin/activate`
3.  Execute the traffic generation script: `python3 traffic_generator.py`
    * The script will prompt you to press Enter before starting traffic generation.

### Analyzing DPI Logs (on MX VM)

After running the traffic generator, analyze the logs generated by Zeek and Suricata on your MX VM.

1.  **Collect TX Logs**: Transfer `tx_traffic_log.csv` from the TX VM to the MX VM (e.g., using `scp`).
2.  **Analyze Zeek Logs**: Examine `conn.log`, `ssl.log`, `dns.log`, `icmp.log`, and any custom logs for protocol identification. Look for the embedded Packet IDs (`NORMAL_ID_XXXXX`, `VPN_ID_XXXXX`) to match with your TX logs.
3.  **Analyze Suricata Logs**: Review `eve.json` or `fast.log` for alerts and protocol classifications. Custom Suricata rules may be needed to specifically identify VPN obfuscation techniques (e.g., TLS on non-standard ports).
4.  **Compare and Validate**: Use a Python script (or spreadsheet software) to compare the `tx_traffic_log.csv` (the "ground truth") with the DPI tool outputs to assess:
    * Detection rate of different traffic types.
    * Accuracy of protocol identification (e.g., did Zeek correctly classify TCP 443 traffic as SoftEther VPN or merely as SSL?).
    * Effectiveness in detecting protocol obfuscation.

---

## Contributing

Feel free to contribute to this project by opening issues or submitting pull requests.

---

## License

This project is open-source and available under the [MIT License](LICENSE).

---