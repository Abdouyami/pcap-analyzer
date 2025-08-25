# Enhanced PCAP Network Analyzer

## Overview

This is a comprehensive network traffic analysis tool built with Streamlit that enables security analysts to perform deep packet inspection, threat intelligence enrichment, and security analytics on PCAP files. The application combines traditional network analysis with modern threat intelligence integration, providing real-time IoC lookups, advanced threat detection, MITRE ATT&CK mapping, and interactive visualizations for SOC analysts and threat hunters.

## User Preferences

Preferred communication style: Simple, everyday language.

## System Architecture

### Frontend Architecture
- **Framework**: Streamlit web application with custom CSS styling
- **UI Structure**: Modular tab-based interface organized in separate UI components (`ui/` module)
- **Visualization**: Plotly for interactive charts and graphs, NetworkX for network topology visualization
- **State Management**: Streamlit session state for maintaining application state across interactions

### Backend Architecture
- **Core Engine**: `EnhancedPCAPAnalyzer` class serves as the main analysis engine
- **Packet Processing**: Scapy library for low-level packet parsing and protocol analysis
- **Asynchronous Operations**: asyncio for concurrent threat intelligence API calls and enrichment operations
- **Protocol Parsers**: Dedicated parsers for HTTP, TLS/SSL, and DNS protocols with deep inspection capabilities
- **Detection Engine**: Multi-stage correlation engine with configurable detection rules and MITRE ATT&CK mapping

### Data Processing Pipeline
- **Input**: PCAP/PCAPNG files processed through Scapy
- **Analysis Layers**: 
  - Basic packet analysis (IPs, ports, protocols)
  - Conversation analysis (bidirectional flows)
  - Endpoint profiling (activity patterns)
  - Protocol-specific deep inspection
  - Threat intelligence enrichment
  - Security detection correlation
- **Output**: Structured DataFrames, enrichment results, and detection objects

### Security Analytics Framework
- **Detection Engine**: Rule-based detection system with support for port scanning, C2 beaconing, data exfiltration, and lateral movement patterns
- **MITRE ATT&CK Integration**: Automatic mapping of detected behaviors to MITRE ATT&CK tactics and techniques
- **Risk Scoring**: Comprehensive risk assessment engine combining multiple factors (reputation, traffic patterns, geographic risk)
- **Machine Learning**: Optional Isolation Forest anomaly detection for identifying unusual traffic patterns

### Data Storage Strategy
- **Cache Layer**: Disk-based caching using diskcache for threat intelligence results with configurable TTL
- **In-Memory Processing**: Pandas DataFrames for packet data and analysis results
- **Persistent Storage**: SQLite-based caching for threat intelligence data to reduce API calls

### Configuration Management
- **Settings**: YAML-based configuration with environment variable support
- **API Keys**: Secure handling of threat intelligence API credentials
- **Feature Toggles**: Conditional feature enabling based on API availability and configuration

## External Dependencies

### Threat Intelligence APIs
- **VirusTotal API v3**: IP, domain, and file hash reputation lookups with rate limiting (4 requests/minute free tier)
- **AbuseIPDB API v2**: IP abuse reputation and reporting data (1000 requests/day free tier)
- **MISP Platform**: Optional integration for custom threat intelligence feeds and IoC sharing

### Geolocation Services
- **MaxMind GeoLite2**: Local database for IP geolocation without API dependencies
- **IPinfo API**: Enhanced geolocation data with ASN and organization information (optional)

### Core Libraries
- **Scapy**: Packet parsing and network protocol analysis
- **Streamlit**: Web application framework and UI components
- **Plotly**: Interactive visualizations and charts
- **NetworkX**: Network graph analysis and visualization
- **Pandas/NumPy**: Data manipulation and numerical computations
- **scikit-learn**: Machine learning algorithms for anomaly detection (optional)

### HTTP and Networking
- **httpx**: Asynchronous HTTP client for API calls with retry logic
- **tenacity**: Retry mechanism for resilient API interactions

### Data Processing
- **Pydantic**: Data validation and serialization for enrichment results and detection models
- **diskcache**: Persistent caching for threat intelligence data
- **PyYAML**: Configuration file parsing

### Optional Dependencies
- **MaxMind GeoIP2**: Geographic IP database reader
- **cryptography**: TLS/SSL certificate analysis and fingerprinting

### Development and Deployment
- **pathlib**: Cross-platform file system operations
- **asyncio**: Asynchronous programming support
- **typing**: Type hints and annotations for better code maintainability