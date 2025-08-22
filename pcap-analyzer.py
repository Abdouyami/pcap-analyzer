import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import networkx as nx
import numpy as np
from datetime import datetime, timedelta
import io
import base64
from collections import defaultdict, Counter
import time
import math  # For entropy calculation

try:
    from scapy.all import rdpcap, IP, TCP, UDP, ICMP, ARP, Ether, sniff, DNS, DNSQR
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    st.error("Scapy not installed. Please install with: pip install scapy")

try:
    from sklearn.ensemble import IsolationForest
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
    st.warning("Scikit-learn not installed. ML-based anomaly detection will be skipped. Install with: pip install scikit-learn")

# Page configuration
st.set_page_config(
    page_title="PCAP Network Analyzer",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for better styling
st.markdown("""
<style>
.main-header {
    font-size: 2.5rem;
    font-weight: bold;
    color: #1f77b4;
    text-align: center;
    margin-bottom: 2rem;
}
.metric-card {
    background-color: #f0f2f6;
    padding: 1rem;
    border-radius: 0.5rem;
    border-left: 4px solid #1f77b4;
}
.alert-high { border-left-color: #ff4444 !important; background-color: #fff0f0; }
.alert-medium { border-left-color: #ff8800 !important; background-color: #fff8f0; }
.alert-low { border-left-color: #44ff44 !important; background-color: #f0fff0; }
</style>
""", unsafe_allow_html=True)

class PCAPAnalyzer:
    def __init__(self):
        self.packets = []
        self.packet_df = pd.DataFrame()
        self.conversations = defaultdict(lambda: {'packets': 0, 'bytes': 0})
        self.endpoints = defaultdict(lambda: {'tx_packets': 0, 'rx_packets': 0, 'tx_bytes': 0, 'rx_bytes': 0})
        self.protocols = Counter()
        self.alerts = []
        self.dns_queries = defaultdict(list)  # For DNS tunneling detection
        
    def load_pcap(self, file_path, max_packets=None):
        """Load and parse PCAP file with optional packet limit for performance"""
        if not SCAPY_AVAILABLE:
            return False
            
        try:
            # Use sniff for better control over loading large files
            self.packets = sniff(offline=file_path, count=max_packets if max_packets else 0, store=True)
            self._analyze_packets()
            return True
        except Exception as e:
            st.error(f"Error loading PCAP file: {str(e)}")
            return False
    
    def _analyze_packets(self):
        """Analyze packets and extract comprehensive statistics"""
        packet_data = []
        
        for i, pkt in enumerate(self.packets):
            packet_info = {
                'index': i,
                'timestamp': float(pkt.time),
                'length': len(pkt),
                'protocol': 'Unknown',
                'src_ip': '',
                'dst_ip': '',
                'src_port': '',
                'dst_port': '',
                'tcp_flags': '',
                'tcp_window': 0,
                'tcp_seq': 0,
                'tcp_ack': 0,
                'icmp_type': '',
                'icmp_code': '',
                'ttl': 0,
                'fragment_flags': '',
                'payload_size': 0,
                'info': str(pkt.summary())
            }
            
            # Extract network layer info
            if IP in pkt:
                packet_info['src_ip'] = pkt[IP].src
                packet_info['dst_ip'] = pkt[IP].dst
                packet_info['ttl'] = pkt[IP].ttl
                packet_info['fragment_flags'] = str(pkt[IP].flags)
                
                ip_header_len = pkt[IP].ihl * 4
                packet_info['payload_size'] = len(pkt) - ip_header_len
                
                # Transport layer protocols
                if TCP in pkt:
                    packet_info['protocol'] = 'TCP'
                    packet_info['src_port'] = pkt[TCP].sport
                    packet_info['dst_port'] = pkt[TCP].dport
                    packet_info['tcp_flags'] = str(pkt[TCP].flags)
                    packet_info['tcp_window'] = pkt[TCP].window
                    packet_info['tcp_seq'] = pkt[TCP].seq
                    packet_info['tcp_ack'] = pkt[TCP].ack
                    tcp_header_len = pkt[TCP].dataofs * 4
                    packet_info['payload_size'] -= tcp_header_len
                    
                elif UDP in pkt:
                    packet_info['protocol'] = 'UDP'
                    packet_info['src_port'] = pkt[UDP].sport
                    packet_info['dst_port'] = pkt[UDP].dport
                    packet_info['payload_size'] -= 8
                    
                    # Check for ISAKMP (port 500 or 4500)
                    if pkt[UDP].dport in (500, 4500) or pkt[UDP].sport in (500, 4500):
                        packet_info['protocol'] = 'ISAKMP'
                        packet_info['info'] = f"ISAKMP packet (potential unparsed attributes: {pkt[UDP].payload})"
                        # Skip further parsing to avoid warnings
                        packet_data.append(packet_info)
                        self._update_statistics(packet_info, pkt)
                        continue
                    
                    # DNS parsing for tunneling detection
                    if pkt[UDP].dport == 53 and DNS in pkt and pkt[DNS].qr == 0:
                        try:
                            domain = pkt[DNSQR].qname.decode('utf-8', errors='ignore')
                            self.dns_queries[packet_info['src_ip']].append(domain)
                        except:
                            pass
                        
                elif ICMP in pkt:
                    packet_info['protocol'] = 'ICMP'
                    packet_info['icmp_type'] = pkt[ICMP].type
                    packet_info['icmp_code'] = pkt[ICMP].code
                    packet_info['payload_size'] -= 8
                    
            elif ARP in pkt:
                packet_info['protocol'] = 'ARP'
                packet_info['src_ip'] = pkt[ARP].psrc
                packet_info['dst_ip'] = pkt[ARP].pdst
            
            packet_data.append(packet_info)
            self._update_statistics(packet_info, pkt)
        
        # Convert to DataFrame
        self.packet_df = pd.DataFrame(packet_data)
        if not self.packet_df.empty:
            self.packet_df['datetime'] = pd.to_datetime(self.packet_df['timestamp'], unit='s')
        
        self._analyze_conversations()
        self._detect_anomalies()
        self._generate_alerts()
        self._analyze_performance_metrics()
    
    def _update_statistics(self, packet_info, pkt):
        """Update conversation, endpoint, and protocol statistics with detailed info"""
        src_ip = packet_info['src_ip']
        dst_ip = packet_info['dst_ip']
        protocol = packet_info['protocol']
        length = packet_info['length']
        payload_size = packet_info['payload_size']
        
        if src_ip and dst_ip:
            # Conversations (bidirectional) - enhanced with detailed metrics
            conv_key = tuple(sorted([src_ip, dst_ip]))
            if conv_key not in self.conversations:
                self.conversations[conv_key] = {
                    'packets': 0, 'bytes': 0, 'payload_bytes': 0,
                    'start_time': packet_info['timestamp'],
                    'end_time': packet_info['timestamp'],
                    'protocols': Counter(),
                    'ports': set(),
                    'tcp_flags': Counter(),
                    'directions': {f"{src_ip}->{dst_ip}": 0, f"{dst_ip}->{src_ip}": 0},
                    'avg_packet_size': 0,
                    'max_packet_size': 0,
                    'min_packet_size': float('inf'),
                    'retransmissions': 0,
                    'out_of_order': 0,
                    'window_sizes': [],
                    'rtt_samples': [],
                    'anomaly_score': 0.0  # New: for anomaly detection
                }
            
            conv = self.conversations[conv_key]
            conv['packets'] += 1
            conv['bytes'] += length
            conv['payload_bytes'] += max(0, payload_size)
            conv['end_time'] = packet_info['timestamp']
            conv['protocols'][protocol] += 1
            conv['directions'][f"{src_ip}->{dst_ip}"] += 1
            
            # Update packet size statistics
            conv['max_packet_size'] = max(conv['max_packet_size'], length)
            conv['min_packet_size'] = min(conv['min_packet_size'], length)
            conv['avg_packet_size'] = conv['bytes'] / conv['packets']
            
            # Add port information
            if packet_info['src_port'] and packet_info['dst_port']:
                conv['ports'].add(packet_info['src_port'])
                conv['ports'].add(packet_info['dst_port'])
            
            # TCP-specific analysis
            if protocol == 'TCP':
                if packet_info['tcp_flags']:
                    conv['tcp_flags'][packet_info['tcp_flags']] += 1
                if packet_info['tcp_window']:
                    conv['window_sizes'].append(packet_info['tcp_window'])
            
            # Endpoints - enhanced
            for ip in [src_ip, dst_ip]:
                if ip not in self.endpoints:
                    self.endpoints[ip] = {
                        'tx_packets': 0, 'rx_packets': 0, 'tx_bytes': 0, 'rx_bytes': 0,
                        'protocols': Counter(), 'ports': set(), 'connections': set(),
                        'first_seen': packet_info['timestamp'], 'last_seen': packet_info['timestamp'],
                        'geo_location': self._get_geo_hint(ip)
                    }
                
                self.endpoints[ip]['last_seen'] = packet_info['timestamp']
                self.endpoints[ip]['protocols'][protocol] += 1
                
                if ip == src_ip:
                    self.endpoints[ip]['tx_packets'] += 1
                    self.endpoints[ip]['tx_bytes'] += length
                    if dst_ip:
                        self.endpoints[ip]['connections'].add(dst_ip)
                else:
                    self.endpoints[ip]['rx_packets'] += 1
                    self.endpoints[ip]['rx_bytes'] += length
                
                # Add port information
                if packet_info['src_port'] and packet_info['dst_port']:
                    if ip == src_ip:
                        self.endpoints[ip]['ports'].add(packet_info['src_port'])
                    else:
                        self.endpoints[ip]['ports'].add(packet_info['dst_port'])
        
        # Protocols
        self.protocols[protocol] += 1
    
    def _get_geo_hint(self, ip):
        """Provide geographical hint based on IP address patterns"""
        if ip.startswith('192.168.') or ip.startswith('10.') or ip.startswith('172.'):
            return "Private/Local"
        elif ip.startswith('127.'):
            return "Localhost"
        elif ip.startswith('169.254.'):
            return "Link-Local"
        else:
            return "Public/Internet"
    
    def _analyze_conversations(self):
        """Perform advanced conversation analysis"""
        for conv_key, conv in self.conversations.items():
            # Calculate duration
            conv['duration'] = conv['end_time'] - conv['start_time']
            
            # Calculate throughput (bytes per second)
            if conv['duration'] > 0:
                conv['throughput'] = conv['bytes'] / conv['duration']
                conv['packet_rate'] = conv['packets'] / conv['duration']
            else:
                conv['throughput'] = 0
                conv['packet_rate'] = 0
            
            # Analyze bidirectionality
            dir1 = f"{conv_key[0]}->{conv_key[1]}"
            dir2 = f"{conv_key[1]}->{conv_key[0]}"
            total_packets = conv['directions'][dir1] + conv['directions'][dir2]
            
            if total_packets > 0:
                conv['bidirectional_ratio'] = min(conv['directions'][dir1], conv['directions'][dir2]) / total_packets
            else:
                conv['bidirectional_ratio'] = 0
            
            # Service identification
            conv['likely_service'] = self._identify_service(conv)
            
            # Risk assessment
            conv['risk_score'] = self._calculate_conversation_risk(conv)
    
    def _identify_service(self, conv):
        """Identify likely service based on ports and patterns"""
        common_ports = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
            80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 993: 'IMAPS',
            995: 'POP3S', 3389: 'RDP', 5432: 'PostgreSQL', 3306: 'MySQL',
            1433: 'MSSQL', 6379: 'Redis', 27017: 'MongoDB'
        }
        
        ports = list(conv['ports'])
        for port in ports:
            if port in common_ports:
                return common_ports[port]
        
        # Analyze by protocol and patterns
        if 'TCP' in conv['protocols']:
            if conv['packets'] > 100 and conv['payload_bytes'] > conv['bytes'] * 0.8:
                return 'Data Transfer'
            elif len(conv['tcp_flags']) > 3:
                return 'Interactive Session'
        elif 'UDP' in conv['protocols']:
            if 53 in ports:
                return 'DNS'
            elif conv['packets'] > 10:
                return 'UDP Stream'
        
        return 'Unknown'
    
    def _calculate_conversation_risk(self, conv):
        """Calculate risk score for conversation"""
        risk_score = 0
        
        # High packet rate
        if conv['packet_rate'] > 100:
            risk_score += 2
        
        # Large data transfer
        if conv['bytes'] > 10000000:  # 10MB
            risk_score += 1
        
        # Unusual ports
        unusual_ports = [port for port in conv['ports'] if port > 10000]
        risk_score += len(unusual_ports) * 0.5
        
        # Very short or very long conversations
        if conv['duration'] < 0.1 and conv['packets'] > 10:
            risk_score += 1  # Potential DoS
        elif conv['duration'] > 3600:
            risk_score += 0.5  # Very long session
        
        # Unidirectional traffic
        if conv['bidirectional_ratio'] < 0.1:
            risk_score += 1
        
        return min(risk_score, 5)  # Cap at 5
    
    def _detect_anomalies(self):
        """ML-based anomaly detection using Isolation Forest on conversation features"""
        if not SKLEARN_AVAILABLE or not self.conversations:
            return
        
        features = []
        conv_keys = list(self.conversations.keys())
        for conv_key in conv_keys:
            conv = self.conversations[conv_key]
            feature = [
                conv.get('duration', 0),
                conv.get('bytes', 0),
                conv.get('packets', 0),
                conv.get('throughput', 0),
                conv.get('bidirectional_ratio', 0)
            ]
            features.append(feature)
        
        features = np.array(features)
        if features.shape[0] < 2:  # Need at least 2 samples
            return
        
        clf = IsolationForest(contamination=0.1, random_state=42)
        labels = clf.fit_predict(features)
        scores = clf.decision_function(features)
        
        for i, label in enumerate(labels):
            conv_key = conv_keys[i]
            if label == -1:
                anomaly_score = -scores[i] * 10  # Scale to 0-10
                self.conversations[conv_key]['anomaly_score'] = anomaly_score
                self.alerts.append({
                    'severity': 'High',
                    'type': 'Anomaly Detected',
                    'description': f"Anomalous conversation between {conv_key[0]} ↔ {conv_key[1]} (score: {anomaly_score:.2f}). Potential unusual flow size or interval.",
                    'source_ip': conv_key[0],
                    'dest_ip': conv_key[1],
                    'mitre': 'TA0011 - Command and Control' if anomaly_score > 5 else 'TA0007 - Discovery',
                    'reasoning': 'Based on deviation in duration, bytes, packets, throughput, and bidirectionality.'
                })
    
    def _analyze_performance_metrics(self):
        """Analyze network performance metrics"""
        if self.packet_df.empty:
            return
        
        # Calculate network utilization over time
        self.network_metrics = {
            'peak_bandwidth': 0,
            'avg_bandwidth': 0,
            'packet_loss_indicators': 0,
            'latency_indicators': [],
            'fragmentation_rate': 0,
            'retransmission_rate': 0
        }
        
        # Peak bandwidth calculation (bytes per second in 1-second windows)
        if len(self.packet_df) > 1:
            df_time = self.packet_df.set_index('datetime')
            byte_rate = df_time.resample('1s')['length'].sum()
            self.network_metrics['peak_bandwidth'] = byte_rate.max()
            self.network_metrics['avg_bandwidth'] = byte_rate.mean()
        
        # Fragmentation analysis
        fragmented_packets = self.packet_df[self.packet_df['fragment_flags'].str.contains('MF|frag', na=False)]
        if len(self.packet_df) > 0:
            self.network_metrics['fragmentation_rate'] = len(fragmented_packets) / len(self.packet_df) * 100
        
        # TCP analysis for performance indicators
        tcp_packets = self.packet_df[self.packet_df['protocol'] == 'TCP']
        if len(tcp_packets) > 0:
            # Look for retransmissions (simplified heuristic)
            duplicate_seqs = tcp_packets.groupby(['src_ip', 'dst_ip', 'tcp_seq']).size()
            retransmissions = duplicate_seqs[duplicate_seqs > 1].sum()
            self.network_metrics['retransmission_rate'] = retransmissions / len(tcp_packets) * 100
    
    def _generate_alerts(self):
        """Generate security alerts based on traffic patterns - Modular detections"""
        self.alerts = []
        
        self._detect_port_scanning()
        self._detect_large_transfers()
        self._detect_high_packet_rate()
        self._detect_beaconing()
        self._detect_long_sessions()
        self._detect_brute_force()  # New
        self._detect_lateral_movement()  # New
        self._detect_dns_tunneling()  # New
        self._detect_persistence_traffic()  # New
    
    # Modular detection functions below
    
    def _detect_port_scanning(self):
        """Detect port scanning - Maps to MITRE TA0007"""
        tcp_packets = self.packet_df[self.packet_df['protocol'] == 'TCP']
        if not tcp_packets.empty:
            for src_ip in tcp_packets['src_ip'].unique():
                src_packets = tcp_packets[tcp_packets['src_ip'] == src_ip]
                unique_dst_ports = src_packets['dst_port'].nunique()
                time_span = src_packets['timestamp'].max() - src_packets['timestamp'].min()
                
                if unique_dst_ports > 20 and time_span < 10:
                    self.alerts.append({
                        'severity': 'High',
                        'type': 'Port Scanning',
                        'description': f"Host {src_ip} scanned {unique_dst_ports} ports in {time_span:.2f} seconds. Potential reconnaissance.",
                        'source_ip': src_ip,
                        'count': unique_dst_ports,
                        'mitre': 'TA0007 - Discovery',
                        'reasoning': 'High number of unique destination ports in short time frame indicates scanning activity.'
                    })
    
    def _detect_large_transfers(self):
        """Detect large data transfers - Maps to MITRE TA0010"""
        for conv_key, stats in self.conversations.items():
            if stats['bytes'] > 1000000:  # 1MB threshold
                self.alerts.append({
                    'severity': 'Medium',
                    'type': 'Large Data Transfer',
                    'description': f"Large transfer between {conv_key[0]} ↔ {conv_key[1]}: {stats['bytes']:,} bytes. Possible exfiltration.",
                    'source_ip': conv_key[0],
                    'dest_ip': conv_key[1],
                    'bytes': stats['bytes'],
                    'mitre': 'TA0010 - Exfiltration',
                    'reasoning': 'Transfer exceeds typical thresholds, may indicate data theft or bulk download.'
                })
    
    def _detect_high_packet_rate(self):
        """Detect high packet rate - Maps to MITRE TA0008"""
        packet_rates = self.packet_df.groupby('src_ip').size()
        high_rate_threshold = len(self.packet_df) * 0.1  # 10% of total traffic
        
        for src_ip, count in packet_rates.items():
            if count > high_rate_threshold and count > 100:
                self.alerts.append({
                    'severity': 'Medium',
                    'type': 'High Packet Rate',
                    'description': f"Host {src_ip} generated {count} packets ({count/len(self.packet_df)*100:.1f}% of total traffic). Potential lateral movement or DoS.",
                    'source_ip': src_ip,
                    'count': count,
                    'mitre': 'TA0008 - Lateral Movement',
                    'reasoning': 'Dominant traffic from single source may indicate compromise or attack propagation.'
                })
    
    def _detect_beaconing(self):
        """Detect C2 beaconing - Maps to MITRE TA0011"""
        if not self.packet_df.empty:
            comms = self.packet_df.groupby(['src_ip', 'dst_ip'])
            for (src, dst), group in comms:
                if len(group) < 10:
                    continue
                times = group['timestamp'].sort_values().diff().dropna()
                if times.empty:
                    continue
                mean_interval = times.mean()
                std_interval = times.std()
                if std_interval < 0.5 and mean_interval > 5:
                    self.alerts.append({
                        'severity': 'High',
                        'type': 'Possible C2 Beaconing',
                        'description': f"Host {src} → {dst} shows beacon-like traffic every ~{mean_interval:.1f}s. Regular intervals suggest malware callback.",
                        'source_ip': src,
                        'dest_ip': dst,
                        'interval': round(mean_interval, 2),
                        'mitre': 'TA0011 - Command and Control',
                        'reasoning': 'Low variance in inter-packet intervals indicates automated beaconing behavior.'
                    })
    
    def _detect_long_sessions(self):
        """Detect long-lived sessions - Maps to MITRE TA0003"""
        long_sessions = self.packet_df[self.packet_df['protocol'] == 'TCP'].groupby(['src_ip', 'dst_ip'])
        for (src, dst), group in long_sessions:
            duration = group['timestamp'].max() - group['timestamp'].min()
            if duration > 600 and len(group) < 200:
                self.alerts.append({
                    'severity': 'Medium',
                    'type': 'Suspicious Long-lived Session',
                    'description': f"Host {src} ↔ {dst} maintained a {duration:.1f}s TCP session with low traffic. Possible persistence mechanism.",
                    'source_ip': src,
                    'dest_ip': dst,
                    'duration': duration,
                    'mitre': 'TA0003 - Persistence',
                    'reasoning': 'Long duration with low activity may indicate backdoor or idle connection for control.'
                })
    
    def _detect_brute_force(self):
        """Detect brute-force attempts - Maps to MITRE TA0006"""
        tcp_packets = self.packet_df[self.packet_df['protocol'] == 'TCP']
        tcp_syn = tcp_packets[tcp_packets['tcp_flags'].str.contains('S', na=False)]
        syn_counts = tcp_syn.groupby(['src_ip', 'dst_ip', 'dst_port']).size()
        brute_ports = [22, 23, 3389, 445, 1433]  # Common brute-force targets
        
        for index, count in syn_counts.items():
            src_ip, dst_ip, dst_port = index
            if count > 20 and dst_port in brute_ports:
                self.alerts.append({
                    'severity': 'High',
                    'type': 'Brute-Force Attempt',
                    'description': f"Host {src_ip} sent {count} SYN packets to {dst_ip}:{dst_port}. Potential credential stuffing.",
                    'source_ip': src_ip,
                    'dest_ip': dst_ip,
                    'dst_port': dst_port,
                    'count': count,
                    'mitre': 'TA0006 - Credential Access',
                    'reasoning': 'High number of connection attempts to sensitive port indicates brute-force attack.'
                })
    
    def _detect_lateral_movement(self):
        """Detect lateral movement - Maps to MITRE TA0008"""
        lateral_ports = [445, 3389, 22]  # SMB, RDP, SSH
        tcp_packets = self.packet_df[(self.packet_df['protocol'] == 'TCP') & (self.packet_df['dst_port'].isin(lateral_ports))]
        
        def is_private(ip):
            return ip.startswith('10.') or ip.startswith('192.168.') or (ip.startswith('172.') and 16 <= int(ip.split('.')[1]) <= 31)
        
        for src_ip in tcp_packets['src_ip'].unique():
            src_packets = tcp_packets[tcp_packets['src_ip'] == src_ip]
            unique_dst = src_packets['dst_ip'].unique()
            internal_dst = [ip for ip in unique_dst if is_private(ip)]
            if len(internal_dst) > 5:
                self.alerts.append({
                    'severity': 'High',
                    'type': 'Lateral Movement',
                    'description': f"Host {src_ip} connected to {len(internal_dst)} internal hosts on lateral ports. Potential network spreading.",
                    'source_ip': src_ip,
                    'count': len(internal_dst),
                    'mitre': 'TA0008 - Lateral Movement',
                    'reasoning': 'Multiple connections to internal hosts on admin ports suggests pivoting activity.'
                })
    
    def _detect_dns_tunneling(self):
        """Detect DNS tunneling - Maps to MITRE TA0010"""
        def shannon_entropy(s):
            if not s:
                return 0
            counts = Counter(s.lower())
            length = len(s)
            return -sum((count / length) * math.log2(count / length) for count in counts.values())
        
        for src_ip, domains in self.dns_queries.items():
            if len(domains) > 50:
                entropies = [shannon_entropy(d) for d in domains if d]
                avg_entropy = np.mean(entropies) if entropies else 0
                if avg_entropy > 4.0:
                    self.alerts.append({
                        'severity': 'High',
                        'type': 'DNS Tunneling',
                        'description': f"Host {src_ip} sent {len(domains)} DNS queries with high entropy ({avg_entropy:.2f}). Potential data exfiltration.",
                        'source_ip': src_ip,
                        'count': len(domains),
                        'mitre': 'TA0010 - Exfiltration',
                        'reasoning': 'High query volume and domain entropy indicate encoded data in DNS queries.'
                    })
    
    def _detect_persistence_traffic(self):
        """Detect persistence-related traffic - Maps to MITRE TA0003"""
        persist_ports = [445, 3389, 22]  # SMB, RDP, SSH
        tcp_packets = self.packet_df[(self.packet_df['protocol'] == 'TCP') & (self.packet_df['dst_port'].isin(persist_ports))]
        syn_counts = tcp_packets[tcp_packets['tcp_flags'].str.contains('S', na=False)].groupby(['src_ip', 'dst_ip', 'dst_port']).size()
        
        for index, count in syn_counts.items():
            src_ip, dst_ip, dst_port = index
            if count > 10:  # Repeated connections
                self.alerts.append({
                    'severity': 'Medium',
                    'type': 'Persistence Traffic',
                    'description': f"Host {src_ip} initiated {count} sessions to {dst_ip}:{dst_port}. Potential scheduled task or backdoor.",
                    'source_ip': src_ip,
                    'dest_ip': dst_ip,
                    'dst_port': dst_port,
                    'count': count,
                    'mitre': 'TA0003 - Persistence',
                    'reasoning': 'Repeated connections to admin ports may indicate persistent access attempts.'
                })
    
    # Placeholder for future threat intel integration
    def _check_threat_intel(self, ip_or_domain):
        """Placeholder for IoC lookup - Future: Integrate with threat feeds"""
        # Example: return {'malicious': True, 'details': 'Known C2'} if bad
        return None


def create_conversation_heatmap(analyzer):
    """Create conversation heatmap visualization"""
    if not analyzer.conversations:
        return go.Figure().add_annotation(text="No conversation data available", 
                                        xref="paper", yref="paper", x=0.5, y=0.5)
    
    # Prepare data for heatmap
    conversations_list = []
    for (src, dst), stats in analyzer.conversations.items():
        conversations_list.append({
            'Source': src,
            'Destination': dst,
            'Packets': stats['packets'],
            'Bytes': stats['bytes']
        })
    
    conv_df = pd.DataFrame(conversations_list)
    
    # Create pivot table for heatmap
    heatmap_data = conv_df.pivot_table(
        index='Source', 
        columns='Destination', 
        values='Packets', 
        fill_value=0
    )
    
    fig = px.imshow(
        heatmap_data,
        aspect='auto',
        color_continuous_scale='Blues',
        title="Conversation Heatmap (Packet Count)"
    )
    
    fig.update_layout(
        xaxis_title="Destination IP",
        yaxis_title="Source IP",
        height=600
    )
    
    return fig

def create_network_graph(analyzer):
    """Create network conversation graph"""
    if not analyzer.conversations:
        return go.Figure().add_annotation(text="No network data available", 
                                        xref="paper", yref="paper", x=0.5, y=0.5)
    
    G = nx.Graph()
    
    # Add nodes and edges
    for (src, dst), stats in analyzer.conversations.items():
        G.add_edge(src, dst, weight=stats['packets'], bytes=stats['bytes'])
    
    # Calculate layout
    pos = nx.spring_layout(G, k=1, iterations=50)
    
    # Extract node and edge information
    edge_x, edge_y = [], []
    edge_info = []
    
    for edge in G.edges():
        x0, y0 = pos[edge[0]]
        x1, y1 = pos[edge[1]]
        edge_x.extend([x0, x1, None])
        edge_y.extend([y0, y1, None])
        
        edge_data = G[edge[0]][edge[1]]
        edge_info.append(f"{edge[0]} ↔ {edge[1]}<br>Packets: {edge_data['weight']}<br>Bytes: {edge_data['bytes']:,}")
    
    # Create edge trace
    edge_trace = go.Scatter(
        x=edge_x, y=edge_y,
        line=dict(width=0.5, color='#888'),
        hoverinfo='none',
        mode='lines'
    )
    
    # Create node trace
    node_x = [pos[node][0] for node in G.nodes()]
    node_y = [pos[node][1] for node in G.nodes()]
    node_text = list(G.nodes())
    
    # Node size based on degree
    node_adjacencies = [len(list(G.neighbors(node))) for node in G.nodes()]
    
    node_trace = go.Scatter(
        x=node_x, y=node_y,
        mode='markers+text',
        hoverinfo='text',
        text=node_text,
        textposition="middle center",
        hovertext=[f"IP: {node}<br>Connections: {adj}" for node, adj in zip(G.nodes(), node_adjacencies)],
        marker=dict(
            size=[v*5 + 10 for v in node_adjacencies],
            color=node_adjacencies,
            colorscale='Viridis',
            showscale=True,
            colorbar=dict(title="Connections")
        )
    )
    
    fig = go.Figure(data=[edge_trace, node_trace],
                    layout=go.Layout(
                        title="Network Conversation Graph",
                        titlefont_size=16,
                        showlegend=False,
                        hovermode='closest',
                        margin=dict(b=20,l=5,r=5,t=40),
                        annotations=[ dict(
                            text="Node size represents number of connections",
                            showarrow=False,
                            xref="paper", yref="paper",
                            x=0.005, y=-0.002,
                            xanchor='left', yanchor='bottom',
                            font=dict(color='gray', size=12)
                        )],
                        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False)
                    ))
    
    return fig

def create_protocol_hierarchy(analyzer):
    """Create protocol hierarchy visualization"""
    if not analyzer.protocols:
        return go.Figure().add_annotation(text="No protocol data available", 
                                        xref="paper", yref="paper", x=0.5, y=0.5)
    
    protocols_df = pd.DataFrame(list(analyzer.protocols.items()), columns=['Protocol', 'Count'])
    protocols_df['Percentage'] = protocols_df['Count'] / protocols_df['Count'].sum() * 100
    
    fig = px.pie(
        protocols_df, 
        values='Count', 
        names='Protocol',
        title="Protocol Distribution",
        hover_data=['Percentage']
    )
    
    fig.update_traces(
        textposition='inside', 
        textinfo='percent+label',
        hovertemplate='<b>%{label}</b><br>Count: %{value}<br>Percentage: %{percent}<extra></extra>'
    )
    
    return fig

def create_io_graph(analyzer):
    """Create I/O graph showing packet rate over time"""
    if analyzer.packet_df.empty:
        return go.Figure().add_annotation(text="No packet data available", 
                                        xref="paper", yref="paper", x=0.5, y=0.5)
    
    # Resample packets by time intervals
    df_time = analyzer.packet_df.set_index('datetime')
    
    # Create 1-second intervals
    packet_rate = df_time.resample('1s').size().reset_index()
    packet_rate.columns = ['Time', 'Packets_per_Second']
    
    byte_rate = df_time.resample('1s')['length'].sum().reset_index()
    byte_rate.columns = ['Time', 'Bytes_per_Second']
    
    # Create subplots
    fig = make_subplots(
        rows=2, cols=1,
        subplot_titles=('Packets per Second', 'Bytes per Second'),
        vertical_spacing=0.12
    )
    
    # Add packet rate
    fig.add_trace(
        go.Scatter(
            x=packet_rate['Time'],
            y=packet_rate['Packets_per_Second'],
            mode='lines',
            name='Packets/sec',
            line=dict(color='blue')
        ),
        row=1, col=1
    )
    
    # Add byte rate
    fig.add_trace(
        go.Scatter(
            x=byte_rate['Time'],
            y=byte_rate['Bytes_per_Second'],
            mode='lines',
            name='Bytes/sec',
            line=dict(color='red')
        ),
        row=2, col=1
    )
    
    fig.update_layout(
        title="Network I/O Over Time",
        height=600,
        showlegend=True
    )
    
    fig.update_xaxes(title_text="Time", row=2, col=1)
    fig.update_yaxes(title_text="Packets", row=1, col=1)
    fig.update_yaxes(title_text="Bytes", row=2, col=1)
    
    return fig

def generate_technical_summary(analyzer):
    """Generate detailed technical summary for analysts"""
    summary = f"""
### Technical Summary
- **Total Packets:** {len(analyzer.packet_df):,}
- **Total Bytes:** {analyzer.packet_df['length'].sum():,}
- **Unique IPs:** {pd.concat([analyzer.packet_df['src_ip'], analyzer.packet_df['dst_ip']]).nunique()}
- **Capture Duration:** {(analyzer.packet_df['timestamp'].max() - analyzer.packet_df['timestamp'].min()):.2f} seconds
- **Top Protocols:** {', '.join([f"{k} ({v})" for k, v in analyzer.protocols.most_common(5)])}

### Key Conversations (Top 5 by Bytes)
"""
    conv_df = pd.DataFrame([{'Source': k[0], 'Destination': k[1], **v} for k, v in analyzer.conversations.items()])
    if not conv_df.empty:
        summary += conv_df.sort_values('bytes', ascending=False).head(5)[['Source', 'Destination', 'packets', 'bytes', 'likely_service']].to_markdown(index=False)
    
    summary += "\n\n### Alerts\n"
    alert_df = pd.DataFrame(analyzer.alerts)
    if not alert_df.empty:
        summary += alert_df[['severity', 'type', 'description', 'mitre']].to_markdown(index=False)
    else:
        summary += "No alerts detected."
    
    return summary

def generate_executive_summary(analyzer):
    """Generate high-level executive summary with risks and recommendations"""
    alert_df = pd.DataFrame(analyzer.alerts)
    high_count = len(alert_df[alert_df['severity'] == 'High'])
    medium_count = len(alert_df[alert_df['severity'] == 'Medium'])
    
    main_risks = alert_df['type'].value_counts().head(3).index.tolist()
    recommendations = []
    for alert_type in set(alert_df['type']):
        if alert_type == 'Port Scanning':
            recommendations.append("Investigate source IPs for reconnaissance; block scanning hosts.")
        elif alert_type == 'Possible C2 Beaconing':
            recommendations.append("Isolate affected hosts and scan for malware.")
        elif alert_type == 'Brute-Force Attempt':
            recommendations.append("Enable account lockouts and monitor authentication logs.")
        elif alert_type == 'Lateral Movement':
            recommendations.append("Segment network and enforce least privilege access.")
        elif alert_type == 'DNS Tunneling':
            recommendations.append("Inspect DNS logs and restrict outbound DNS to trusted servers.")
        # Add more as needed
    
    summary = f"""
### Executive Summary
- **Overall Risk Level:** {'High' if high_count > 0 else 'Medium' if medium_count > 0 else 'Low'}
- **High Severity Alerts:** {high_count}
- **Medium Severity Alerts:** {medium_count}
- **Main Risks:** {', '.join(main_risks) if main_risks else 'None detected'}
- **Recommended Actions:** 
{'\n'.join(['- ' + rec for rec in recommendations]) if recommendations else '- No immediate actions required.'}
"""
    return summary

def main():
    st.markdown('<h1 class="main-header">🔍 PCAP Network Traffic Analyzer</h1>', unsafe_allow_html=True)
    
    # Initialize analyzer
    if 'analyzer' not in st.session_state:
        st.session_state.analyzer = PCAPAnalyzer()
    
    analyzer = st.session_state.analyzer
    
    # Sidebar for file upload and controls
    st.sidebar.header("📁 Load PCAP File")

    # Helpful PCAP resources
    st.sidebar.markdown("### 📂 Sample PCAP Resources")

    st.sidebar.markdown("Click a resource below to explore and download PCAP datasets:")
    if st.sidebar.button("🌐 Wireshark Sample Captures"):
        st.sidebar.markdown(
            "<a href='https://wiki.wireshark.org/SampleCaptures' style='color:#28a745;text-decoration:none;' target='_blank'>Open Link</a>  \n"
            "<span style='font-size:12px;color:gray;'>Official Wireshark collection — VoIP, HTTP, DNS, wireless, etc.</span>",
            unsafe_allow_html=True
        )

    if st.sidebar.button("🦠 Malware-Traffic-Analysis.net"):
        st.sidebar.markdown(
            "<a href='https://www.malware-traffic-analysis.net/' style='color:#28a745;text-decoration:none;' target='_blank'>Open Link</a>  \n"
            "<span style='font-size:12px;color:gray;'>Real-world malware & C2 traffic — SOC practice.</span>",
            unsafe_allow_html=True
        )

    if st.sidebar.button("🔍 NETRESEC PCAP Files"):
        st.sidebar.markdown(
            "<a href='https://www.netresec.com/?page=PcapFiles' style='color:#28a745;text-decoration:none;' target='_blank'>Open Link</a>  \n"
            "<span style='font-size:12px;color:gray;'>Intrusion attempts, botnets, exploits.</span>",
            unsafe_allow_html=True
        )

    if st.sidebar.button("🤖 Stratosphere IPS Dataset"):
        st.sidebar.markdown(
            "<a href='https://www.stratosphereips.org/datasets-malware/' style='color:#28a745;text-decoration:none;' target='_blank'>Open Link</a>  \n"
            "<span style='font-size:12px;color:gray;'>Labeled benign + malicious traffic — ML/AI detection.</span>",
            unsafe_allow_html=True
        )

    
    if not SCAPY_AVAILABLE:
        st.sidebar.error("⚠️ Scapy library not available. Please install scapy to use this application.")
        st.stop()
    
    uploaded_file = st.sidebar.file_uploader(
        "Choose a PCAP file",
        type=['pcap', 'pcapng', 'cap'],
        help="Upload a PCAP file from your network capture or blue team lab"
    )
    
    max_packets = st.sidebar.number_input("Max packets to load (for large files)", min_value=1000, max_value=None, value=100000, step=10000)
    if len(analyzer.packet_df) > 100000:
        st.sidebar.warning("Large PCAP loaded. Performance may be slow. Consider reducing max packets.")
    
    if uploaded_file is not None:
        # Save uploaded file temporarily
        with st.spinner("Loading and analyzing PCAP file..."):
            bytes_data = uploaded_file.getvalue()
            with open("temp_file.pcap", "wb") as f:
                f.write(bytes_data)
            
            success = analyzer.load_pcap("temp_file.pcap", max_packets=max_packets)
            
            if success:
                st.sidebar.success(f"✅ Loaded {len(analyzer.packets):,} packets")
            else:
                st.sidebar.error("❌ Failed to load PCAP file")
                st.stop()
    else:
        st.info("👆 Please upload a PCAP file to begin analysis")
        st.stop()
    
    # Main dashboard
    if analyzer.packet_df.empty:
        st.warning("No packets found in the PCAP file")
        st.stop()
    
    # Overview metrics
    st.header("📊 Overview")
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.markdown('<div class="metric-card">', unsafe_allow_html=True)
        st.metric("Total Packets", f"{len(analyzer.packets):,}")
        st.markdown('</div>', unsafe_allow_html=True)
    
    with col2:
        total_bytes = analyzer.packet_df['length'].sum()
        st.markdown('<div class="metric-card">', unsafe_allow_html=True)
        st.metric("Total Bytes", f"{total_bytes:,}")
        st.markdown('</div>', unsafe_allow_html=True)
    
    with col3:
        unique_ips = pd.concat([analyzer.packet_df['src_ip'], analyzer.packet_df['dst_ip']]).nunique()
        st.markdown('<div class="metric-card">', unsafe_allow_html=True)
        st.metric("Unique IPs", unique_ips)
        st.markdown('</div>', unsafe_allow_html=True)
    
    with col4:
        duration = analyzer.packet_df['timestamp'].max() - analyzer.packet_df['timestamp'].min()
        st.markdown('<div class="metric-card">', unsafe_allow_html=True)
        st.metric("Duration", f"{duration:.2f}s")
        st.markdown('</div>', unsafe_allow_html=True)
    
    # Alerts section
    if analyzer.alerts:
        st.header("🚨 Security Alerts")
        
        for alert in analyzer.alerts[:10]:  # Show top 10 alerts
            severity = alert['severity']
            css_class = f"alert-{severity.lower()}"
            
            st.markdown(f'<div class="metric-card {css_class}">', unsafe_allow_html=True)
            st.write(f"**{severity}** - {alert['type']}: {alert['description']}")
            st.write(f"MITRE: {alert.get('mitre', 'N/A')} | Reasoning: {alert.get('reasoning', 'N/A')}")
            st.markdown('</div>', unsafe_allow_html=True)
    
    # Tabs for different views
    tab1, tab2, tab3, tab4, tab5, tab6, tab7, tab8, tab9 = st.tabs([
        "📋 Packet List", "💬 Conversations", "📍 Endpoints", 
        "🔗 Protocol Hierarchy", "📈 I/O Graphs", "🌐 Network Graph",
        "🚀 Performance", "🔒 Security Analysis", "📝 Reports"
    ])
    
    with tab1:
        st.header("Packet List")
        
        # Enhanced filters
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            protocol_filter = st.selectbox(
                "Filter by Protocol",
                options=['All'] + list(analyzer.protocols.keys())
            )
        
        with col2:
            ip_filter = st.text_input("Filter by IP (source or destination)")
        
        with col3:
            port_filter = st.text_input("Filter by Port")
            
        with col4:
            tcp_flag_filter = st.selectbox(
                "TCP Flags",
                options=['All', 'SYN', 'ACK', 'FIN', 'RST', 'PSH', 'URG']
            )
        
        # Size and time filters
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            min_size = st.number_input("Min packet size", min_value=0, value=0)
        with col2:
            max_size = st.number_input("Max packet size", min_value=0, value=65535)
        with col3:
            max_packets = st.number_input("Max packets to display", min_value=10, max_value=10000, value=1000)
        with col4:
            show_suspicious = st.checkbox("Show suspicious only")
        
        # Apply filters
        filtered_df = analyzer.packet_df.copy()
        
        if protocol_filter != 'All':
            filtered_df = filtered_df[filtered_df['protocol'] == protocol_filter]
        
        if ip_filter:
            filtered_df = filtered_df[
                (filtered_df['src_ip'].str.contains(ip_filter, na=False)) |
                (filtered_df['dst_ip'].str.contains(ip_filter, na=False))
            ]
        
        if port_filter:
            filtered_df = filtered_df[
                (filtered_df['src_port'].astype(str).str.contains(port_filter, na=False)) |
                (filtered_df['dst_port'].astype(str).str.contains(port_filter, na=False))
            ]
            
        if tcp_flag_filter != 'All':
            filtered_df = filtered_df[filtered_df['tcp_flags'].str.contains(tcp_flag_filter, na=False)]
        
        # Size filter
        filtered_df = filtered_df[
            (filtered_df['length'] >= min_size) & 
            (filtered_df['length'] <= max_size)
        ]
        
        if show_suspicious:
            suspicious_ips = set(a.get('source_ip', '') for a in analyzer.alerts) | set(a.get('dest_ip', '') for a in analyzer.alerts if 'dest_ip' in a)
            filtered_df = filtered_df[
                filtered_df['src_ip'].isin(suspicious_ips) | filtered_df['dst_ip'].isin(suspicious_ips)
            ]
        
        # Display enhanced packet table
        display_columns = [
            'index', 'datetime', 'src_ip', 'dst_ip', 'protocol', 
            'src_port', 'dst_port', 'length', 'tcp_flags', 'ttl', 'info'
        ]
        
        display_df = filtered_df.head(max_packets)[display_columns]
        
        # Fix serialization: convert src_port and dst_port to string
        for col in ['src_port', 'dst_port']:
            if col in display_df.columns:
                display_df[col] = display_df[col].astype(str)
        
        st.dataframe(
            display_df,
            use_container_width=True,
            height=400
        )
        
        # Packet statistics
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Filtered Packets", f"{len(filtered_df):,}")
        with col2:
            if len(filtered_df) > 0:
                st.metric("Avg Packet Size", f"{filtered_df['length'].mean():.1f} bytes")
        with col3:
            if len(filtered_df) > 0:
                st.metric("Total Filtered Size", f"{filtered_df['length'].sum():,} bytes")
    
    with tab2:
        st.header("🔍 Comprehensive Conversations Analysis")
        
        # Enhanced conversation statistics
        conversations_list = []
        for (src, dst), stats in analyzer.conversations.items():
            conversations_list.append({
                'Source': src,
                'Destination': dst,
                'Packets': stats['packets'],
                'Bytes': stats['bytes'],
                'Payload_Bytes': stats['payload_bytes'],
                'Duration_sec': stats.get('duration', 0),
                'Avg_Packet_Size': stats.get('avg_packet_size', 0),
                'Max_Packet_Size': stats.get('max_packet_size', 0),
                'Min_Packet_Size': stats.get('min_packet_size', 0),
                'Throughput_Bps': stats.get('throughput', 0),
                'Packet_Rate': stats.get('packet_rate', 0),
                'Protocols': ', '.join([f"{k}({v})" for k, v in stats.get('protocols', {}).items()]),
                'Ports': ', '.join(map(str, sorted(list(stats.get('ports', [])))[:10])),  # Show first 10 ports
                'TCP_Flags': ', '.join([f"{k}({v})" for k, v in stats.get('tcp_flags', {}).items()]),
                'Bidirectional_Ratio': stats.get('bidirectional_ratio', 0),
                'Likely_Service': stats.get('likely_service', 'Unknown'),
                'Risk_Score': stats.get('risk_score', 0),
                'Anomaly_Score': stats.get('anomaly_score', 0),
                'Direction_Balance': f"{stats['directions'].get(f'{src}->{dst}', 0)}/{stats['directions'].get(f'{dst}->{src}', 0)}"
            })
        
        conv_df = pd.DataFrame(conversations_list).sort_values('Bytes', ascending=False)
        
        # Conversation analysis controls
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            sort_by = st.selectbox("Sort by", ['Bytes', 'Packets', 'Duration_sec', 'Throughput_Bps', 'Risk_Score', 'Anomaly_Score'])
        with col2:
            min_packets = st.number_input("Min packets threshold", min_value=1, value=10)
        with col3:
            risk_threshold = st.slider("Risk score threshold", 0.0, 5.0, 2.0)
        with col4:
            show_suspicious_conv = st.checkbox("Show suspicious only", key="susp_conv")
        
        # Filter conversations
        filtered_conv = conv_df[
            (conv_df['Packets'] >= min_packets) & 
            (conv_df['Risk_Score'] >= risk_threshold)
        ].sort_values(sort_by, ascending=False)
        
        if show_suspicious_conv:
            suspicious_convs = set((a.get('source_ip', ''), a.get('dest_ip', '')) for a in analyzer.alerts if 'dest_ip' in a)
            filtered_conv = filtered_conv[
                filtered_conv.apply(lambda row: (row['Source'], row['Destination']) in suspicious_convs or (row['Destination'], row['Source']) in suspicious_convs, axis=1)
            ]
        
        # Conversation insights
        st.subheader("🎯 Key Insights")
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Total Conversations", len(conv_df))
        with col2:
            if len(conv_df) > 0:
                high_risk_count = len(conv_df[conv_df['Risk_Score'] >= 3])
                st.metric("High Risk Conversations", high_risk_count)
        with col3:
            if len(conv_df) > 0:
                top_service = conv_df['Likely_Service'].mode().iloc[0] if not conv_df['Likely_Service'].mode().empty else "N/A"
                st.metric("Top Service", top_service)
        with col4:
            if len(conv_df) > 0:
                avg_duration = conv_df['Duration_sec'].mean()
                st.metric("Avg Duration", f"{avg_duration:.2f}s")
        
        # Top conversations with detailed view
        st.subheader("📊 Top Conversations (Detailed View)")
        
        # Select conversation for detailed analysis
        if len(filtered_conv) > 0:
            selected_conv_idx = st.selectbox(
                "Select conversation for detailed analysis:",
                range(len(filtered_conv.head(20))),
                format_func=lambda x: f"{filtered_conv.iloc[x]['Source']} ↔ {filtered_conv.iloc[x]['Destination']} ({filtered_conv.iloc[x]['Likely_Service']})"
            )
            
            selected_conv = filtered_conv.iloc[selected_conv_idx]
            
            # Detailed conversation view
            col1, col2 = st.columns(2)
            
            with col1:
                st.markdown("### 📋 Conversation Summary")
                st.write(f"**Service:** {selected_conv['Likely_Service']}")
                st.write(f"**Duration:** {selected_conv['Duration_sec']:.2f} seconds")
                st.write(f"**Data Transferred:** {selected_conv['Bytes']:,} bytes ({selected_conv['Payload_Bytes']:,} payload)")
                st.write(f"**Packet Rate:** {selected_conv['Packet_Rate']:.1f} packets/sec")
                st.write(f"**Throughput:** {selected_conv['Throughput_Bps']:,.1f} bytes/sec")
                st.write(f"**Bidirectional Ratio:** {selected_conv['Bidirectional_Ratio']:.3f}")
                
                # Risk assessment
                risk_level = "🟢 Low" if selected_conv['Risk_Score'] < 2 else "🟡 Medium" if selected_conv['Risk_Score'] < 4 else "🔴 High"
                st.write(f"**Risk Level:** {risk_level} ({selected_conv['Risk_Score']:.1f})")
                st.write(f"**Anomaly Score:** {selected_conv['Anomaly_Score']:.1f}")
            
            with col2:
                st.markdown("### 📈 Technical Details")
                st.write(f"**Protocols:** {selected_conv['Protocols']}")
                st.write(f"**Ports:** {selected_conv['Ports']}")
                st.write(f"**TCP Flags:** {selected_conv['TCP_Flags']}")
                st.write(f"**Packet Sizes:** {selected_conv['Min_Packet_Size']}-{selected_conv['Max_Packet_Size']} bytes (avg: {selected_conv['Avg_Packet_Size']:.1f})")
                st.write(f"**Direction Balance:** {selected_conv['Direction_Balance']} packets")
        
        # Full conversation table
        st.subheader("📋 All Conversations")
        st.dataframe(
            filtered_conv.head(100),  # Show top 100
            use_container_width=True,
            height=400
        )
        
        # Conversation visualizations
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("🎯 Service Distribution")
            if len(conv_df) > 0:
                service_dist = conv_df['Likely_Service'].value_counts().head(10)
                fig = px.pie(values=service_dist.values, names=service_dist.index, title="Services in Network Traffic")
                st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            st.subheader("⚠️ Risk Score Distribution")
            if len(conv_df) > 0:
                fig = px.histogram(conv_df, x='Risk_Score', nbins=20, title="Conversation Risk Score Distribution")
                fig.update_xaxes(title="Risk Score")
                fig.update_yaxes(title="Number of Conversations")
                st.plotly_chart(fig, use_container_width=True)
        
        # Advanced conversation heatmap
        st.subheader("🔥 Enhanced Conversation Heatmap")
        metric_choice = st.radio(
            "Heatmap metric:",
            ["Packets", "Bytes", "Throughput_Bps", "Risk_Score"],
            horizontal=True
        )
        
        if not conv_df.empty:
            heatmap_data = conv_df.pivot_table(
                index='Source', 
                columns='Destination', 
                values=metric_choice, 
                fill_value=0
            )
            
            fig = px.imshow(
                heatmap_data,
                aspect='auto',
                color_continuous_scale='Viridis',
                title=f"Conversation Heatmap - {metric_choice}"
            )
            
            fig.update_layout(height=500)
            st.plotly_chart(fig, use_container_width=True)

    
    with tab3:
        st.header("📍 Enhanced Endpoints Analysis")
        
        # Enhanced endpoint statistics
        endpoints_list = []
        for ip, stats in analyzer.endpoints.items():
            endpoints_list.append({
                'IP_Address': ip,
                'TX_Packets': stats['tx_packets'],
                'RX_Packets': stats['rx_packets'],
                'Total_Packets': stats['tx_packets'] + stats['rx_packets'],
                'TX_Bytes': stats['tx_bytes'],
                'RX_Bytes': stats['rx_bytes'],
                'Total_Bytes': stats['tx_bytes'] + stats['rx_bytes'],
                'Active_Duration': stats['last_seen'] - stats['first_seen'],
                'Protocols': ', '.join([f"{k}({v})" for k, v in stats.get('protocols', {}).items()]),
                'Unique_Ports': len(stats.get('ports', [])),
                'Connections': len(stats.get('connections', [])),
                'Location_Type': stats.get('geo_location', 'Unknown'),
                'First_Seen': pd.to_datetime(stats['first_seen'], unit='s').strftime('%H:%M:%S'),
                'Last_Seen': pd.to_datetime(stats['last_seen'], unit='s').strftime('%H:%M:%S'),
                'Activity_Score': (stats['tx_packets'] + stats['rx_packets']) * len(stats.get('connections', [])) / 100
            })
        
        endpoints_df = pd.DataFrame(endpoints_list).sort_values('Total_Bytes', ascending=False)
        
        # Endpoint insights
        st.subheader("🎯 Endpoint Insights")
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Total Endpoints", len(endpoints_df))
        with col2:
            if len(endpoints_df) > 0:
                most_active = endpoints_df.loc[endpoints_df['Activity_Score'].idxmax(), 'IP_Address']
                st.metric("Most Active Host", most_active)
        with col3:
            if len(endpoints_df) > 0:
                external_hosts = len(endpoints_df[endpoints_df['Location_Type'] == 'Public/Internet'])
                st.metric("External Hosts", external_hosts)
        with col4:
            if len(endpoints_df) > 0:
                avg_connections = endpoints_df['Connections'].mean()
                st.metric("Avg Connections/Host", f"{avg_connections:.1f}")
        
        # Endpoint filtering
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            location_filter = st.selectbox("Location Type", ['All'] + list(endpoints_df['Location_Type'].unique()))
        with col2:
            min_connections = st.number_input("Min connections", min_value=0, value=0)
        with col3:
            activity_threshold = st.slider("Min activity score", 0.0, float(endpoints_df['Activity_Score'].max()) if len(endpoints_df) > 0 else 10.0, 0.0)
        with col4:
            show_suspicious_end = st.checkbox("Show suspicious only", key="susp_end")
        
        # Filter endpoints
        filtered_endpoints = endpoints_df.copy()
        if location_filter != 'All':
            filtered_endpoints = filtered_endpoints[filtered_endpoints['Location_Type'] == location_filter]
        
        filtered_endpoints = filtered_endpoints[
            (filtered_endpoints['Connections'] >= min_connections) &
            (filtered_endpoints['Activity_Score'] >= activity_threshold)
        ]
        
        if show_suspicious_end:
            suspicious_ips = set(a.get('source_ip', '') for a in analyzer.alerts) | set(a.get('dest_ip', '') for a in analyzer.alerts if 'dest_ip' in a)
            filtered_endpoints = filtered_endpoints[filtered_endpoints['IP_Address'].isin(suspicious_ips)]
        
        # Detailed endpoint table
        st.subheader("📋 Endpoint Details")
        st.dataframe(filtered_endpoints.head(50), use_container_width=True, height=400)
        
        # Endpoint visualizations
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("🌍 Location Distribution")
            if len(endpoints_df) > 0:
                location_dist = endpoints_df['Location_Type'].value_counts()
                fig = px.bar(x=location_dist.index, y=location_dist.values, title="Endpoints by Location Type")
                fig.update_xaxes(title="Location Type")
                fig.update_yaxes(title="Count")
                st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            st.subheader("📊 Activity vs Connections")
            if len(endpoints_df) > 0:
                fig = px.scatter(
                    endpoints_df.head(50), 
                    x='Connections', 
                    y='Activity_Score',
                    size='Total_Bytes',
                    color='Location_Type',
                    hover_data=['IP_Address'],
                    title="Endpoint Activity Analysis"
                )
                st.plotly_chart(fig, use_container_width=True)
    
    with tab4:
        st.header("🔗 Protocol Hierarchy & Analysis")
        
        col1, col2 = st.columns(2)
        
        with col1:
            # Enhanced protocol statistics
            protocols_df = pd.DataFrame(list(analyzer.protocols.items()), columns=['Protocol', 'Count'])
            protocols_df['Percentage'] = protocols_df['Count'] / protocols_df['Count'].sum() * 100
            
            # Add bytes per protocol
            protocol_bytes = analyzer.packet_df.groupby('protocol')['length'].sum().reset_index()
            protocol_bytes.columns = ['Protocol', 'Total_Bytes']
            protocols_df = protocols_df.merge(protocol_bytes, on='Protocol', how='left')
            protocols_df['Avg_Packet_Size'] = protocols_df['Total_Bytes'] / protocols_df['Count']
            protocols_df = protocols_df.sort_values('Count', ascending=False)
            
            st.subheader("📊 Protocol Statistics")
            st.dataframe(protocols_df, use_container_width=True)
        
        with col2:
            st.subheader("🥧 Protocol Distribution")
            protocol_fig = create_protocol_hierarchy(analyzer)
            st.plotly_chart(protocol_fig, use_container_width=True)
        
        # Protocol analysis over time
        st.subheader("📈 Protocol Usage Over Time")
        if not analyzer.packet_df.empty:
            # Resample by protocol
            df_time = analyzer.packet_df.set_index('datetime')
            protocol_time = df_time.groupby([pd.Grouper(freq='10s'), 'protocol']).size().unstack(fill_value=0)
            
            fig = go.Figure()
            for protocol in protocol_time.columns:
                fig.add_trace(go.Scatter(
                    x=protocol_time.index,
                    y=protocol_time[protocol],
                    mode='lines',
                    name=protocol,
                    stackgroup='one'
                ))
            
            fig.update_layout(
                title="Protocol Usage Over Time (10-second intervals)",
                xaxis_title="Time",
                yaxis_title="Packet Count",
                hovermode='x unified'
            )
            st.plotly_chart(fig, use_container_width=True)
    
    with tab5:
        st.header("📈 I/O Graphs & Network Performance")
        
        # Time range selection using slider for packet indices
        if not analyzer.packet_df.empty:
            total_packets = len(analyzer.packet_df)
            duration = analyzer.packet_df['timestamp'].max() - analyzer.packet_df['timestamp'].min()
            
            st.subheader("Time Range Selection")
            
            # Use packet index range instead of datetime
            packet_range = st.slider(
                "Select packet range",
                min_value=0,
                max_value=total_packets-1,
                value=(0, min(total_packets-1, 1000)),  # Default to first 1000 packets
                help=f"Total capture duration: {duration:.2f} seconds"
            )
            
            # Alternative: Time-based selection using text input
            col1, col2 = st.columns(2)
            with col1:
                start_offset = st.number_input(
                    "Start time offset (seconds)", 
                    min_value=0.0, 
                    max_value=duration, 
                    value=0.0,
                    step=1.0
                )
            with col2:
                end_offset = st.number_input(
                    "End time offset (seconds)", 
                    min_value=0.0, 
                    max_value=duration, 
                    value=min(duration, 60.0),  # Default to first 60 seconds
                    step=1.0
                )
            
            # Filter data by packet range or time range
            if st.radio("Filter by:", ["Packet Range", "Time Range"]) == "Packet Range":
                time_filtered_analyzer = PCAPAnalyzer()
                time_filtered_analyzer.packet_df = analyzer.packet_df.iloc[packet_range[0]:packet_range[1]+1]
            else:
                time_filtered_analyzer = PCAPAnalyzer()
                min_timestamp = analyzer.packet_df['timestamp'].min()
                start_time = min_timestamp + start_offset
                end_time = min_timestamp + end_offset
                
                time_filtered_analyzer.packet_df = analyzer.packet_df[
                    (analyzer.packet_df['timestamp'] >= start_time) &
                    (analyzer.packet_df['timestamp'] <= end_time)
                ]
            
            if not time_filtered_analyzer.packet_df.empty:
                st.info(f"Analyzing {len(time_filtered_analyzer.packet_df):,} packets in selected range")
                io_fig = create_io_graph(time_filtered_analyzer)
                st.plotly_chart(io_fig, use_container_width=True)
                
                # Additional performance metrics
                st.subheader("📊 Performance Metrics for Selected Range")
                col1, col2, col3 = st.columns(3)
                
                with col1:
                    avg_pps = len(time_filtered_analyzer.packet_df) / max((time_filtered_analyzer.packet_df['timestamp'].max() - time_filtered_analyzer.packet_df['timestamp'].min()), 1)
                    st.metric("Avg Packets/sec", f"{avg_pps:.1f}")
                
                with col2:
                    avg_bps = time_filtered_analyzer.packet_df['length'].sum() / max((time_filtered_analyzer.packet_df['timestamp'].max() - time_filtered_analyzer.packet_df['timestamp'].min()), 1)
                    st.metric("Avg Bytes/sec", f"{avg_bps:,.0f}")
                    
                with col3:
                    avg_packet_size = time_filtered_analyzer.packet_df['length'].mean()
                    st.metric("Avg Packet Size", f"{avg_packet_size:.1f} bytes")
            else:
                st.warning("No packets in selected range")
    
    with tab6:
        st.header("🌐 Advanced Network Graph")
        
        st.info("Interactive network graph showing communication patterns between hosts")
        
        # Enhanced network graph options
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            min_packets = st.slider("Minimum packets for connection", min_value=1, max_value=100, value=5)
        
        with col2:
            max_connections = st.slider("Maximum connections to show", min_value=10, max_value=200, value=50)
            
        with col3:
            graph_layout = st.selectbox("Graph Layout", ["spring", "circular", "random", "shell"])
        
        with col4:
            filter_ip = st.text_input("Filter by IP")
        
        # Filter conversations for graph
        filtered_conversations = {
            k: v for k, v in analyzer.conversations.items() 
            if v['packets'] >= min_packets and (not filter_ip or filter_ip in k)
        }
        
        if filtered_conversations:
            # Create enhanced network graph
            temp_analyzer = PCAPAnalyzer()
            temp_analyzer.conversations = dict(list(filtered_conversations.items())[:max_connections])
            
            network_fig = create_network_graph(temp_analyzer)
            st.plotly_chart(network_fig, use_container_width=True)
            
            # Network statistics
            st.subheader("📊 Network Graph Statistics")
            col1, col2, col3 = st.columns(3)
            
            with col1:
                st.metric("Displayed Connections", len(temp_analyzer.conversations))
            with col2:
                unique_hosts = set()
                for k in temp_analyzer.conversations.keys():
                    unique_hosts.update(k)
                st.metric("Unique Hosts", len(unique_hosts))
            with col3:
                total_packets_graph = sum(v['packets'] for v in temp_analyzer.conversations.values())
                st.metric("Total Packets in Graph", f"{total_packets_graph:,}")
        else:
            st.warning("No connections meet the criteria")
    
    with tab7:
        st.header("🚀 Network Performance Analysis")
        
        # Performance metrics from analyzer
        if hasattr(analyzer, 'network_metrics'):
            metrics = analyzer.network_metrics
            
            st.subheader("📈 Overall Performance Metrics")
            col1, col2, col3, col4 = st.columns(4)
            
            with col1:
                st.metric("Peak Bandwidth", f"{metrics['peak_bandwidth']:,.0f} B/s")
            with col2:
                st.metric("Avg Bandwidth", f"{metrics['avg_bandwidth']:,.0f} B/s")
            with col3:
                st.metric("Fragmentation Rate", f"{metrics['fragmentation_rate']:.2f}%")
            with col4:
                st.metric("TCP Retransmission Rate", f"{metrics['retransmission_rate']:.2f}%")
        
        # Protocol performance analysis
        st.subheader("🔍 Protocol Performance Breakdown")
        if not analyzer.packet_df.empty:
            protocol_perf = analyzer.packet_df.groupby('protocol').agg({
                'length': ['count', 'sum', 'mean', 'std'],
                'payload_size': ['sum', 'mean']
            }).round(2)
            
            protocol_perf.columns = ['Packet_Count', 'Total_Bytes', 'Avg_Packet_Size', 'Size_StdDev', 'Total_Payload', 'Avg_Payload']
            protocol_perf = protocol_perf.reset_index()
            
            st.dataframe(protocol_perf, use_container_width=True)
        
        # TCP Window Size Analysis
        st.subheader("📊 TCP Window Size Analysis")
        tcp_data = analyzer.packet_df[analyzer.packet_df['protocol'] == 'TCP']
        if not tcp_data.empty and tcp_data['tcp_window'].sum() > 0:
            fig = px.histogram(tcp_data, x='tcp_window', nbins=50, title="TCP Window Size Distribution")
            fig.update_xaxes(title="Window Size (bytes)")
            fig.update_yaxes(title="Frequency")
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No TCP window size data available")
        
        # Packet size distribution
        st.subheader("📦 Packet Size Distribution")
        fig = px.histogram(analyzer.packet_df, x='length', nbins=50, title="Packet Size Distribution")
        fig.update_xaxes(title="Packet Size (bytes)")
        fig.update_yaxes(title="Frequency")
        st.plotly_chart(fig, use_container_width=True)
    
    with tab8:
        st.header("🔒 Advanced Security Analysis")
        
        # Enhanced alerts with more details
        if analyzer.alerts:
            st.subheader("🚨 Security Alerts")
            
            # Group alerts by severity
            alert_df = pd.DataFrame(analyzer.alerts)
            severity_counts = alert_df['severity'].value_counts()
            
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("High Risk", severity_counts.get('High', 0))
            with col2:
                st.metric("Medium Risk", severity_counts.get('Medium', 0))
            with col3:
                st.metric("Low Risk", severity_counts.get('Low', 0))
            
            # Display alerts in expandable sections with timelines
            for severity in ['High', 'Medium', 'Low']:
                severity_alerts = alert_df[alert_df['severity'] == severity].to_dict('records')
                if severity_alerts:
                    with st.expander(f"{severity} Risk Alerts ({len(severity_alerts)})"):
                        for idx, alert in enumerate(severity_alerts[:10]):  # Show top 10 per severity
                            css_class = f"alert-{severity.lower()}"
                            st.markdown(f'<div class="metric-card {css_class}">', unsafe_allow_html=True)
                            st.write(f"**{alert['type']}:** {alert['description']}")
                            st.write(f"MITRE: {alert.get('mitre', 'N/A')} | Reasoning: {alert.get('reasoning', 'N/A')}")
                            st.markdown('</div>', unsafe_allow_html=True)
                            
                            # Use a checkbox instead of an expander for the timeline
                            if st.checkbox(f"View Timeline for Alert {idx + 1}", key=f"timeline_{severity}_{idx}"):
                                src_ip = alert.get('source_ip')
                                dst_ip = alert.get('dest_ip')
                                if src_ip:
                                    timeline_df = analyzer.packet_df[
                                        (analyzer.packet_df['src_ip'] == src_ip) &
                                        ((analyzer.packet_df['dst_ip'] == dst_ip) if dst_ip else True)
                                    ].sort_values('datetime')[[ 'datetime', 'src_ip', 'dst_ip', 'protocol', 'length', 'info']]
                                    st.dataframe(timeline_df, use_container_width=True)
        else:
            st.info("No security alerts detected")
        
        # Suspicious patterns analysis
        st.subheader("🕵️ Suspicious Pattern Detection")
        
        # Port scanning analysis
        if not analyzer.packet_df.empty:
            port_scan_analysis = []
            for src_ip in analyzer.packet_df['src_ip'].unique():
                src_packets = analyzer.packet_df[analyzer.packet_df['src_ip'] == src_ip]
                unique_dst_ips = src_packets['dst_ip'].nunique()
                unique_dst_ports = src_packets['dst_port'].nunique()
                
                if unique_dst_ports > 10 or unique_dst_ips > 20:
                    port_scan_analysis.append({
                        'Source_IP': src_ip,
                        'Unique_Destination_IPs': unique_dst_ips,
                        'Unique_Destination_Ports': unique_dst_ports,
                        'Total_Packets': len(src_packets),
                        'Scan_Score': (unique_dst_ports * 0.5 + unique_dst_ips * 0.3)
                    })
            
            if port_scan_analysis:
                scan_df = pd.DataFrame(port_scan_analysis).sort_values('Scan_Score', ascending=False)
                st.write("**Potential Port Scanning Activity:**")
                st.dataframe(scan_df.head(10), use_container_width=True)
        
        # Traffic anomalies
        st.subheader("📊 Traffic Anomaly Detection")
        
        if len(analyzer.conversations) > 0:
            # Identify conversations with unusual patterns
            conv_analysis = []
            for (src, dst), stats in analyzer.conversations.items():
                anomaly_score = 0
                anomaly_reasons = []
                
                # Large data transfer
                if stats['bytes'] > 10000000:  # 10MB
                    anomaly_score += 2
                    anomaly_reasons.append("Large data transfer")
                
                # High packet rate
                if stats.get('packet_rate', 0) > 100:
                    anomaly_score += 1
                    anomaly_reasons.append("High packet rate")
                
                # Unusual duration
                duration = stats.get('duration', 0)
                if duration > 3600:  # > 1 hour
                    anomaly_score += 1
                    anomaly_reasons.append("Very long session")
                elif duration < 0.1 and stats['packets'] > 100:
                    anomaly_score += 2
                    anomaly_reasons.append("Very short burst")
                
                # Unidirectional traffic
                if stats.get('bidirectional_ratio', 1) < 0.1:
                    anomaly_score += 1
                    anomaly_reasons.append("Mostly unidirectional")
                
                if anomaly_score > 0:
                    conv_analysis.append({
                        'Source': src,
                        'Destination': dst,
                        'Anomaly_Score': anomaly_score,
                        'Reasons': ', '.join(anomaly_reasons),
                        'Packets': stats['packets'],
                        'Bytes': stats['bytes'],
                        'Duration': duration
                    })
            
            if conv_analysis:
                anomaly_df = pd.DataFrame(conv_analysis).sort_values('Anomaly_Score', ascending=False)
                st.write("**Traffic Anomalies:**")
                st.dataframe(anomaly_df.head(15), use_container_width=True)
            else:
                st.success("No significant traffic anomalies detected")
        
        # Geolocation analysis
        st.subheader("🌍 Geographic Analysis")
        if not endpoints_df.empty:
            geo_summary = {}
            for ip, stats in analyzer.endpoints.items():
                location = stats.get('geo_location', 'Unknown')
                if location not in geo_summary:
                    geo_summary[location] = {'count': 0, 'total_bytes': 0}
                geo_summary[location]['count'] += 1
                geo_summary[location]['total_bytes'] += stats['tx_bytes'] + stats['rx_bytes']
            
            geo_df = pd.DataFrame(geo_summary).T.reset_index()
            geo_df.columns = ['Location_Type', 'Host_Count', 'Total_Bytes']
            geo_df = geo_df.sort_values('Total_Bytes', ascending=False)
            
            col1, col2 = st.columns(2)
            with col1:
                st.dataframe(geo_df, use_container_width=True)
            
            with col2:
                fig = px.pie(geo_df, values='Host_Count', names='Location_Type', title="Hosts by Location Type")
                st.plotly_chart(fig, use_container_width=True)
    
    with tab9:
        st.header("📝 Analysis Reports")
        
        st.subheader("Technical Analyst Report")
        technical_md = generate_technical_summary(analyzer)
        st.markdown(technical_md)
        
        st.subheader("Executive Summary")
        executive_md = generate_executive_summary(analyzer)
        st.markdown(executive_md)
        
        # Export reports as Markdown
        full_report = f"{executive_md}\n\n{technical_md}"
        st.download_button(
            "Download Full Report (Markdown)",
            full_report,
            file_name=f"pcap_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md",
            mime="text/markdown"
        )
    
    # Export section
    st.header("📤 Export Options")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        if st.button("📊 Export Statistics Report"):
            # Create comprehensive report
            report_data = {
                'summary': {
                    'total_packets': len(analyzer.packets),
                    'total_bytes': int(analyzer.packet_df['length'].sum()),
                    'unique_ips': int(pd.concat([analyzer.packet_df['src_ip'], analyzer.packet_df['dst_ip']]).nunique()),
                    'duration': float(analyzer.packet_df['timestamp'].max() - analyzer.packet_df['timestamp'].min()),
                    'protocols': dict(analyzer.protocols)
                },
                'top_conversations': conv_df.head(10).to_dict('records'),
                'top_endpoints': endpoints_df.head(10).to_dict('records'),
                'alerts': analyzer.alerts
            }
            
            # Convert to JSON and create download
            import json
            json_str = json.dumps(report_data, indent=2, default=str)
            st.download_button(
                label="Download JSON Report",
                data=json_str,
                file_name=f"pcap_analysis_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                mime="application/json"
            )
    
    with col2:
        if st.button("📋 Export Packet List"):
            # Fix serialization: convert src_port and dst_port to string
            for col in ['src_port', 'dst_port']:
                if col in analyzer.packet_df.columns:
                    analyzer.packet_df[col] = analyzer.packet_df[col].astype(str)
            csv_data = analyzer.packet_df.to_csv(index=False)
            st.download_button(
                label="Download CSV",
                data=csv_data,
                file_name=f"packet_list_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv"
            )
    
    with col3:
        if st.button("💬 Export Conversations"):
            conv_csv = conv_df.to_csv(index=False)
            st.download_button(
                label="Download Conversations CSV",
                data=conv_csv,
                file_name=f"conversations_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv"
            )

if __name__ == "__main__":
    main()