# PCAP Network Traffic Analyzer

## Overview
The **PCAP Network Traffic Analyzer** is a powerful, Streamlit-based web application designed for Security Operations Center (SOC) analysts, threat hunters, and incident response (IR) teams to analyze network traffic captured in PCAP files. Built with Python, this tool provides deep insights into network activity by parsing PCAP files, extracting detailed statistics, generating security alerts, and visualizing traffic patterns. It leverages libraries like Scapy for packet parsing, Plotly for interactive visualizations, and scikit-learn for machine learning-based anomaly detection.

This tool is invaluable for SOC analysts and threat hunters because it:
- **Automates Traffic Analysis**: Quickly processes large PCAP files to identify patterns, anomalies, and potential threats.
- **Supports Threat Hunting**: Maps findings to MITRE ATT&CK tactics, enabling analysts to align detected behaviors with known adversary techniques.
- **Enhances Incident Response**: Provides detailed packet, conversation, and endpoint analysis to accelerate root cause identification and response.
- **Offers Extensibility**: Modular design allows for easy addition of new detection rules and integration with threat intelligence or ML models.

## Features
- **PCAP Parsing & Packet Analysis**:
  - Parses PCAP files using Scapy, extracting detailed packet attributes (source/destination IPs, ports, protocols, TCP flags, TTL, payload size, etc.).
  - Supports TCP, UDP, ICMP, ARP, and DNS protocols with deep packet inspection.
  - Filters packets by protocol, IP, port, TCP flags, and size for targeted analysis.
- **Comprehensive Metrics**:
  - Total packets, bytes, unique IPs, and capture duration.
  - Conversation metrics (packet count, bytes, duration, throughput, bidirectional ratio, risk score).
  - Endpoint profiling (transmit/receive packets, bytes, protocols, ports, connections).
- **Security Alerts & Threat Detection**:
  - Detects multiple threat patterns, including:
    - **Port Scanning** (MITRE TA0007 - Discovery): Identifies hosts scanning multiple ports or IPs.
    - **High Packet Rate** (MITRE TA0008 - Lateral Movement): Flags excessive traffic from a single source.
    - **Large Data Transfers** (MITRE TA0010 - Exfiltration): Detects potential data exfiltration.
    - **C2 Beaconing** (MITRE TA0011 - Command and Control): Identifies periodic traffic patterns suggestive of malware callbacks.
    - **Long-lived Sessions** (MITRE TA0003 - Persistence): Flags low-traffic, long-duration TCP sessions.
    - **Brute-Force Attempts** (MITRE TA0006 - Credential Access): Detects repeated connection attempts to sensitive ports.
    - **Lateral Movement** (MITRE TA0008 - Lateral Movement): Identifies connections to multiple internal hosts on admin ports.
    - **DNS Tunneling** (MITRE TA0010 - Exfiltration): Detects high-entropy DNS queries indicative of data exfiltration.
    - **Persistence Traffic** (MITRE TA0003 - Persistence): Flags repeated connections to administrative ports.
  - ML-based anomaly detection using Isolation Forest to identify unusual traffic patterns.
- **Interactive Visualizations**:
  - **Conversation Heatmap**: Visualizes packet or byte flows between IPs.
  - **Network Graph**: Displays host connections with node sizes based on activity.
  - **Protocol Hierarchy**: Shows protocol distribution via pie charts and time-based trends.
  - **I/O Graphs**: Plots packet and byte rates over time for performance analysis.
  - **TCP Window Size & Packet Size Distributions**: Analyzes network performance metrics.
- **Conversation & Endpoint Analysis**:
  - Detailed conversation statistics (packet sizes, throughput, risk scores, likely services).
  - Endpoint profiling with geolocation hints (private, public, localhost).
  - Risk scoring based on traffic patterns (e.g., high packet rates, unusual ports).
- **Reports & Exports**:
  - Technical summary for analysts with packet, conversation, and alert details.
  - Executive summary with risk levels and recommended actions.
  - Exportable reports in Markdown, JSON, and CSV formats.
- **Modular Design**:
  - Extensible detection framework for adding new rules (e.g., custom anomaly thresholds).
  - Supports future integration with threat intelligence feeds and advanced ML models.

## Installation & Requirements
### Prerequisites
- **Python**: Version 3.8 or higher (tested with Python 3.12).
- **Virtual Environment**: Recommended to isolate dependencies.
- **PCAP Files**: Obtain PCAP files from your network or public sources like [Wireshark Sample Captures](https://wiki.wireshark.org/SampleCaptures), [Malware-Traffic-Analysis.net](https://www.malware-traffic-analysis.net/), [NETRESEC PCAP Files](https://www.netresec.com/?page=PcapFiles), or [Stratosphere IPS Dataset](https://www.stratosphereips.org/datasets-malware/).

### Setup Instructions
1. **Clone the Repository**:
   ```bash
   git clone https://github.com/your-repo/pcap-network-analyzer.git
   cd pcap-network-analyzer
   ```

2. **Create a Virtual Environment**:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Verify Installation**:
   Ensure all required libraries (listed in `requirements.txt`) are installed correctly:
   ```bash
   pip list
   ```

## Usage Instructions
1. **Run the Application**:
   Launch the Streamlit app from the project directory:
   ```bash
   streamlit run pcap-analyzer.py
   ```
   This opens the web interface in your default browser (typically at `http://localhost:8501`).

2. **Upload a PCAP File**:
   - In the sidebar, use the file uploader to select a `.pcap` or `.pcapng` file.
   - Optionally, set the maximum number of packets to load (default: 100,000) to optimize performance for large files.
   - Sample PCAP files can be downloaded from the sidebar links (Wireshark, Malware-Traffic-Analysis, etc.).

3. **Interact with the UI**:
   - **Overview**: View high-level metrics (total packets, bytes, unique IPs, duration).
   - **Packet List**: Filter and analyze individual packets by protocol, IP, port, or TCP flags.
   - **Conversations**: Explore bidirectional traffic flows, risk scores, and services.
   - **Endpoints**: Profile hosts with transmit/receive stats and geolocation hints.
   - **Protocol Hierarchy**: Analyze protocol distribution and trends over time.
   - **I/O Graphs**: Visualize packet and byte rates with time range filtering.
   - **Network Graph**: Explore host connections with customizable layouts.
   - **Performance**: Review bandwidth, fragmentation, and retransmission metrics.
   - **Security Analysis**: Investigate alerts, anomalies, and suspicious patterns.
   - **Reports**: Download technical and executive summaries in Markdown, JSON, or CSV.

4. **Expected Output**:
   - **Dashboard**: A responsive Streamlit interface with tabs for different analyses.
   - **Visualizations**: Interactive Plotly charts (heatmaps, graphs, histograms).
   - **Alerts**: Highlighted security findings with MITRE ATT&CK mappings.
   - **Example Screenshot** (placeholder):
     ```
     [Insert screenshot of dashboard showing packet list, network graph, and alerts]
     ```

## Alert Types & Security Analysis
The analyzer includes a robust set of detection rules mapped to MITRE ATT&CK tactics, designed to support SOC workflows:
- **Port Scanning (TA0007 - Discovery)**: Detects hosts scanning multiple ports/IPs, indicating reconnaissance.
- **High Packet Rate (TA0008 - Lateral Movement)**: Flags dominant traffic from a single source, suggesting DoS or spreading.
- **Large Data Transfers (TA0010 - Exfiltration)**: Identifies potential data exfiltration based on byte thresholds.
- **C2 Beaconing (TA0011 - Command and Control)**: Detects periodic traffic with low interval variance, indicative of malware callbacks.
- **Long-lived Sessions (TA0003 - Persistence)**: Flags low-traffic, long-duration sessions that may indicate backdoors.
- **Brute-Force Attempts (TA0006 - Credential Access)**: Identifies repeated connection attempts to sensitive ports (e.g., SSH, RDP).
- **Lateral Movement (TA0008 - Lateral Movement)**: Detects connections to multiple internal hosts on admin ports.
- **DNS Tunneling (TA0010 - Exfiltration)**: Flags high-entropy DNS queries suggestive of data exfiltration.
- **Persistence Traffic (TA0003 - Persistence)**: Identifies repeated connections to administrative ports.

### Analyst Workflow Integration
- **Alert Review**: Alerts are prioritized by severity (High, Medium, Low) with detailed descriptions, MITRE mappings, and reasoning.
- **Timeline Analysis**: Each alert links to a packet-level timeline for chain-of-events investigation.
- **Exportable Reports**: Technical summaries provide raw data for SIEM integration, while executive summaries guide decision-makers.
- **Visualization Support**: Heatmaps and network graphs help analysts visualize attack patterns and pivot to related hosts.

## Contributing
Contributions are welcome to enhance the analyzer's capabilities! To contribute:
1. **Fork the Repository**: Create a fork on GitHub and clone it locally.
2. **Add Detection Rules**:
   - Extend the `_generate_alerts` method in `PCAPAnalyzer` to include new detection logic.
   - Example: Add rules for specific protocols or IoC-based detection.
   - Update the `alerts` list with new entries, including MITRE ATT&CK mappings.
3. **Enhance ML Features**:
   - Improve the `_detect_anomalies` method by experimenting with other algorithms (e.g., DBSCAN, Autoencoders).
   - Integrate external threat intelligence feeds in the `_check_threat_intel` placeholder.
4. **Submit a Pull Request**:
   - Include clear descriptions of changes and test results with sample PCAPs.
   - Ensure code follows PEP 8 style guidelines and includes comments for new features.
5. **Future Ideas**:
   - Add support for real-time PCAP streaming.
   - Integrate with external threat intelligence APIs.
   - Enhance ML models with labeled datasets for supervised learning.

## License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.