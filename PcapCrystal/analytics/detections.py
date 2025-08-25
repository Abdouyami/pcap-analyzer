"""
Enhanced detection engine with advanced threat detection capabilities
"""

import re
import math
from typing import Dict, List, Optional, Tuple, Set
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from dataclasses import dataclass, field

from models.detection import Detection, Severity, MitreAttack
from models.enrichment import EnrichmentResult
from parsing.http import HTTPParser
from parsing.tls import TLSParser
from parsing.dns import DNSParser
from analytics.mitre import MitreMapper

@dataclass
class DetectionContext:
    """Context information for detections"""
    packet_data: Dict = field(default_factory=dict)
    conversation_data: Dict = field(default_factory=dict)
    endpoint_data: Dict = field(default_factory=dict)
    timeline_events: List = field(default_factory=list)

class EnhancedDetectionEngine:
    """Advanced detection engine with multi-stage correlation and enhanced analytics"""
    
    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.detection_rules = self.config.get('detections', {})
        
        # Initialize parsers
        self.http_parser = HTTPParser()
        self.tls_parser = TLSParser()
        self.dns_parser = DNSParser()
        self.mitre_mapper = MitreMapper()
        
        # Detection state tracking
        self.ip_activity = defaultdict(lambda: {
            'connections': [],
            'ports_accessed': set(),
            'hosts_contacted': set(),
            'data_transferred': 0,
            'first_seen': None,
            'last_seen': None,
            'protocols': Counter(),
            'dns_queries': [],
            'http_requests': [],
            'tls_sessions': []
        })
        
        self.ongoing_sessions = {}
        self.c2_candidates = defaultdict(list)
        self.lateral_movement_chains = []
        
    def analyze_packets(self, packets: List, packet_df) -> List[Detection]:
        """Analyze packets and generate enhanced detections"""
        detections = []
        
        # Build detection context
        context = self._build_detection_context(packets, packet_df)
        
        # Run detection rules
        detections.extend(self._detect_port_scanning(context))
        detections.extend(self._detect_c2_beaconing(context))
        detections.extend(self._detect_data_exfiltration(context))
        detections.extend(self._detect_lateral_movement(context))
        detections.extend(self._detect_dns_tunneling(context))
        detections.extend(self._detect_brute_force_attacks(context))
        detections.extend(self._detect_suspicious_tls(context))
        detections.extend(self._detect_http_anomalies(context))
        detections.extend(self._detect_persistence_indicators(context))
        detections.extend(self._detect_evasion_techniques(context))
        
        # Apply MITRE ATT&CK mappings
        detections = self._apply_mitre_mappings(detections)
        
        return detections
    
    def _build_detection_context(self, packets: List, packet_df) -> DetectionContext:
        """Build comprehensive detection context from packet data"""
        context = DetectionContext()
        
        # Process each packet for context building
        for i, pkt in enumerate(packets):
            try:
                # Parse protocols
                http_data = self.http_parser.parse_http_packet(pkt, i)
                tls_data = self.tls_parser.parse_tls_packet(pkt, i)
                dns_data = self.dns_parser.parse_dns_packet(pkt, i)
                
                # Store parsed data
                if http_data:
                    context.packet_data[i] = http_data
                elif tls_data:
                    context.packet_data[i] = tls_data
                elif dns_data:
                    context.packet_data[i] = dns_data
                
                # Update IP activity tracking
                self._update_ip_activity(pkt, i, http_data, tls_data, dns_data)
                
            except Exception as e:
                continue  # Skip problematic packets
        
        return context
    
    def _update_ip_activity(self, pkt, index: int, http_data: Dict, tls_data: Dict, dns_data: Dict):
        """Update IP activity tracking for behavioral analysis"""
        try:
            # Extract IPs based on available data
            src_ip = None
            dst_ip = None
            
            if hasattr(pkt, 'src') and hasattr(pkt, 'dst'):
                src_ip = str(pkt.src)
                dst_ip = str(pkt.dst)
            
            timestamp = float(pkt.time)
            
            if src_ip:
                activity = self.ip_activity[src_ip]
                
                if activity['first_seen'] is None:
                    activity['first_seen'] = timestamp
                activity['last_seen'] = timestamp
                
                if dst_ip:
                    activity['hosts_contacted'].add(dst_ip)
                    
                activity['data_transferred'] += len(pkt)
                
                # Track protocol-specific activity
                if http_data:
                    activity['http_requests'].append({
                        'timestamp': timestamp,
                        'method': http_data.get('method'),
                        'path': http_data.get('path'),
                        'host': http_data.get('host'),
                        'user_agent': http_data.get('user_agent'),
                        'risk_score': http_data.get('analysis', {}).get('risk_score', 0)
                    })
                
                if tls_data:
                    handshake = tls_data.get('handshake_data', {})
                    activity['tls_sessions'].append({
                        'timestamp': timestamp,
                        'sni': handshake.get('sni'),
                        'ja3': tls_data.get('ja3', {}).get('ja3_hash'),
                        'version': tls_data.get('tls_version')
                    })
                
                if dns_data and dns_data.get('is_query'):
                    for question in dns_data.get('questions', []):
                        activity['dns_queries'].append({
                            'timestamp': timestamp,
                            'domain': question['domain'],
                            'qtype': question['qtype_name'],
                            'analysis': dns_data.get('domain_analysis', {})
                        })
        except Exception as e:
            pass  # Ignore parsing errors
    
    def _detect_port_scanning(self, context: DetectionContext) -> List[Detection]:
        """Detect port scanning activities with enhanced heuristics"""
        detections = []
        
        port_scan_threshold = self.detection_rules.get('port_scanning', {}).get('unique_ports_threshold', 10)
        host_scan_threshold = self.detection_rules.get('port_scanning', {}).get('unique_hosts_threshold', 5)
        time_window = self.detection_rules.get('port_scanning', {}).get('time_window_seconds', 300)
        
        for src_ip, activity in self.ip_activity.items():
            if not activity['first_seen']:
                continue
            
            duration = activity['last_seen'] - activity['first_seen']
            unique_hosts = len(activity['hosts_contacted'])
            
            # Port scanning detection
            if len(activity['ports_accessed']) >= port_scan_threshold:
                detection = Detection(
                    id=f"port_scan_{src_ip}_{int(activity['first_seen'])}",
                    name="Port Scanning Activity",
                    description=f"Host {src_ip} accessed {len(activity['ports_accessed'])} unique ports across {unique_hosts} hosts",
                    severity=Severity.HIGH if len(activity['ports_accessed']) > 50 else Severity.MEDIUM,
                    confidence=85,
                    source_ip=src_ip,
                    first_seen=datetime.fromtimestamp(activity['first_seen']),
                    last_seen=datetime.fromtimestamp(activity['last_seen']),
                    evidence={
                        'unique_ports': len(activity['ports_accessed']),
                        'unique_hosts': unique_hosts,
                        'duration_seconds': duration,
                        'ports_per_second': len(activity['ports_accessed']) / max(duration, 1)
                    },
                    risk_score=70 if len(activity['ports_accessed']) > 50 else 50
                )
                detections.append(detection)
            
            # Host scanning detection
            elif unique_hosts >= host_scan_threshold and duration < time_window:
                detection = Detection(
                    id=f"host_scan_{src_ip}_{int(activity['first_seen'])}",
                    name="Host Discovery Scanning",
                    description=f"Host {src_ip} contacted {unique_hosts} unique hosts in {duration:.1f} seconds",
                    severity=Severity.MEDIUM,
                    confidence=75,
                    source_ip=src_ip,
                    first_seen=datetime.fromtimestamp(activity['first_seen']),
                    last_seen=datetime.fromtimestamp(activity['last_seen']),
                    evidence={
                        'unique_hosts': unique_hosts,
                        'duration_seconds': duration,
                        'hosts_per_second': unique_hosts / max(duration, 1)
                    },
                    risk_score=40
                )
                detections.append(detection)
        
        return detections
    
    def _detect_c2_beaconing(self, context: DetectionContext) -> List[Detection]:
        """Detect C2 beaconing with timing analysis and JA3 correlation"""
        detections = []
        
        min_packets = self.detection_rules.get('c2_beaconing', {}).get('min_packets', 10)
        variance_threshold = self.detection_rules.get('c2_beaconing', {}).get('variance_threshold', 0.3)
        
        # Analyze timing patterns for each conversation
        conversation_timings = defaultdict(list)
        
        for src_ip, activity in self.ip_activity.items():
            for dst_ip in activity['hosts_contacted']:
                # Collect timing data for this conversation
                timings = []
                
                # Use TLS sessions for timing analysis (common for C2)
                for session in activity['tls_sessions']:
                    timings.append(session['timestamp'])
                
                if len(timings) >= min_packets:
                    # Calculate intervals between connections
                    intervals = []
                    for i in range(1, len(timings)):
                        intervals.append(timings[i] - timings[i-1])
                    
                    if len(intervals) > 3:
                        # Calculate variance
                        mean_interval = sum(intervals) / len(intervals)
                        variance = sum((x - mean_interval) ** 2 for x in intervals) / len(intervals)
                        coefficient_of_variation = (variance ** 0.5) / mean_interval if mean_interval > 0 else 1
                        
                        # Low variance suggests regular beaconing
                        if coefficient_of_variation < variance_threshold:
                            # Check for suspicious JA3 patterns
                            ja3_hashes = [s.get('ja3') for s in activity['tls_sessions'] if s.get('ja3')]
                            unique_ja3 = set(filter(None, ja3_hashes))
                            
                            detection = Detection(
                                id=f"c2_beacon_{src_ip}_{dst_ip}_{int(timings[0])}",
                                name="Potential C2 Beaconing",
                                description=f"Regular communication pattern between {src_ip} and {dst_ip} suggests C2 beaconing",
                                severity=Severity.HIGH,
                                confidence=80 if len(unique_ja3) <= 2 else 65,
                                source_ip=src_ip,
                                destination_ip=dst_ip,
                                first_seen=datetime.fromtimestamp(timings[0]),
                                last_seen=datetime.fromtimestamp(timings[-1]),
                                evidence={
                                    'connection_count': len(timings),
                                    'mean_interval_seconds': mean_interval,
                                    'timing_variance': coefficient_of_variation,
                                    'unique_ja3_hashes': len(unique_ja3),
                                    'total_duration_hours': (timings[-1] - timings[0]) / 3600
                                },
                                risk_score=75
                            )
                            detections.append(detection)
        
        return detections
    
    def _detect_data_exfiltration(self, context: DetectionContext) -> List[Detection]:
        """Detect potential data exfiltration patterns"""
        detections = []
        
        # Threshold for large data transfers
        large_transfer_threshold = self.detection_rules.get('large_data_transfer', {}).get('bytes_threshold', 100000000)
        
        for src_ip, activity in self.ip_activity.items():
            # Check for large uploads via HTTP POST
            large_posts = []
            for req in activity['http_requests']:
                if req.get('method') == 'POST' and req.get('risk_score', 0) > 50:
                    large_posts.append(req)
            
            if len(large_posts) > 3:
                detection = Detection(
                    id=f"data_exfil_http_{src_ip}_{int(activity['first_seen'])}",
                    name="Suspicious HTTP Upload Activity",
                    description=f"Host {src_ip} performed {len(large_posts)} suspicious HTTP POST requests",
                    severity=Severity.HIGH,
                    confidence=70,
                    source_ip=src_ip,
                    first_seen=datetime.fromtimestamp(activity['first_seen']),
                    last_seen=datetime.fromtimestamp(activity['last_seen']),
                    evidence={
                        'suspicious_posts': len(large_posts),
                        'hosts_contacted': len(activity['hosts_contacted']),
                        'total_data_transferred': activity['data_transferred']
                    },
                    risk_score=65
                )
                detections.append(detection)
            
            # Check for large overall data transfer
            if activity['data_transferred'] > large_transfer_threshold:
                detection = Detection(
                    id=f"large_transfer_{src_ip}_{int(activity['first_seen'])}",
                    name="Large Data Transfer",
                    description=f"Host {src_ip} transferred {activity['data_transferred'] / (1024*1024):.1f} MB of data",
                    severity=Severity.MEDIUM,
                    confidence=60,
                    source_ip=src_ip,
                    first_seen=datetime.fromtimestamp(activity['first_seen']),
                    last_seen=datetime.fromtimestamp(activity['last_seen']),
                    evidence={
                        'bytes_transferred': activity['data_transferred'],
                        'duration_hours': (activity['last_seen'] - activity['first_seen']) / 3600,
                        'average_rate_mbps': (activity['data_transferred'] * 8 / (1024*1024)) / max((activity['last_seen'] - activity['first_seen']), 1)
                    },
                    risk_score=50
                )
                detections.append(detection)
        
        return detections
    
    def _detect_lateral_movement(self, context: DetectionContext) -> List[Detection]:
        """Detect lateral movement patterns"""
        detections = []
        
        # Administrative ports commonly used for lateral movement
        admin_ports = {22, 23, 135, 139, 445, 1433, 3306, 3389, 5432, 5985, 5986}
        
        for src_ip, activity in self.ip_activity.items():
            # Check for connections to multiple internal hosts on admin ports
            internal_admin_connections = []
            
            for dst_ip in activity['hosts_contacted']:
                if self._is_internal_ip(dst_ip):
                    # Check if connections involve admin ports (this would need port info from packet parsing)
                    internal_admin_connections.append(dst_ip)
            
            if len(internal_admin_connections) >= 3:  # Connected to 3+ internal hosts
                detection = Detection(
                    id=f"lateral_movement_{src_ip}_{int(activity['first_seen'])}",
                    name="Potential Lateral Movement",
                    description=f"Host {src_ip} connected to {len(internal_admin_connections)} internal hosts, suggesting lateral movement",
                    severity=Severity.HIGH,
                    confidence=75,
                    source_ip=src_ip,
                    first_seen=datetime.fromtimestamp(activity['first_seen']),
                    last_seen=datetime.fromtimestamp(activity['last_seen']),
                    evidence={
                        'internal_hosts_contacted': len(internal_admin_connections),
                        'total_duration_minutes': (activity['last_seen'] - activity['first_seen']) / 60,
                        'target_hosts': list(internal_admin_connections)[:10]  # Limit for readability
                    },
                    risk_score=70
                )
                detections.append(detection)
        
        return detections
    
    def _detect_dns_tunneling(self, context: DetectionContext) -> List[Detection]:
        """Detect DNS tunneling using entropy and frequency analysis"""
        detections = []
        
        entropy_threshold = self.detection_rules.get('dns_tunneling', {}).get('entropy_threshold', 3.5)
        query_rate_threshold = self.detection_rules.get('dns_tunneling', {}).get('query_rate_threshold', 50)
        
        for src_ip, activity in self.ip_activity.items():
            if not activity['dns_queries']:
                continue
            
            # Analyze DNS query patterns
            high_entropy_queries = 0
            total_queries = len(activity['dns_queries'])
            
            # Check query rate (queries per minute)
            duration_minutes = (activity['last_seen'] - activity['first_seen']) / 60
            query_rate = total_queries / max(duration_minutes, 1)
            
            # Count high entropy domains
            for query in activity['dns_queries']:
                analysis = query.get('analysis', {})
                if analysis.get('entropy', 0) > entropy_threshold:
                    high_entropy_queries += 1
            
            high_entropy_ratio = high_entropy_queries / total_queries if total_queries > 0 else 0
            
            # Detection criteria
            if (query_rate > query_rate_threshold and high_entropy_ratio > 0.3) or high_entropy_ratio > 0.7:
                detection = Detection(
                    id=f"dns_tunnel_{src_ip}_{int(activity['first_seen'])}",
                    name="Potential DNS Tunneling",
                    description=f"Host {src_ip} showing DNS tunneling indicators: high query rate and entropy",
                    severity=Severity.HIGH,
                    confidence=80 if high_entropy_ratio > 0.7 else 65,
                    source_ip=src_ip,
                    first_seen=datetime.fromtimestamp(activity['first_seen']),
                    last_seen=datetime.fromtimestamp(activity['last_seen']),
                    evidence={
                        'total_queries': total_queries,
                        'queries_per_minute': query_rate,
                        'high_entropy_queries': high_entropy_queries,
                        'high_entropy_ratio': high_entropy_ratio,
                        'avg_query_length': sum(len(q['domain']) for q in activity['dns_queries']) / total_queries
                    },
                    risk_score=75
                )
                detections.append(detection)
        
        return detections
    
    def _detect_brute_force_attacks(self, context: DetectionContext) -> List[Detection]:
        """Detect brute force authentication attempts"""
        detections = []
        
        # Look for repeated connection attempts to authentication services
        auth_ports = {21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 1433, 3306, 3389, 5432}
        
        for src_ip, activity in self.ip_activity.items():
            # Analyze HTTP requests for authentication patterns
            auth_attempts = []
            for req in activity['http_requests']:
                path = req.get('path', '').lower()
                if any(keyword in path for keyword in ['login', 'auth', 'signin', 'admin']):
                    auth_attempts.append(req)
            
            if len(auth_attempts) > 20:  # Many authentication attempts
                # Check for variety in user agents (credential stuffing)
                user_agents = set(req.get('user_agent', '') for req in auth_attempts)
                
                severity = Severity.HIGH if len(user_agents) > 5 else Severity.MEDIUM
                
                detection = Detection(
                    id=f"brute_force_{src_ip}_{int(activity['first_seen'])}",
                    name="Brute Force Authentication Attack",
                    description=f"Host {src_ip} made {len(auth_attempts)} authentication attempts",
                    severity=severity,
                    confidence=85,
                    source_ip=src_ip,
                    first_seen=datetime.fromtimestamp(activity['first_seen']),
                    last_seen=datetime.fromtimestamp(activity['last_seen']),
                    evidence={
                        'auth_attempts': len(auth_attempts),
                        'unique_user_agents': len(user_agents),
                        'duration_minutes': (activity['last_seen'] - activity['first_seen']) / 60,
                        'attempts_per_minute': len(auth_attempts) / max((activity['last_seen'] - activity['first_seen']) / 60, 1)
                    },
                    risk_score=70
                )
                detections.append(detection)
        
        return detections
    
    def _detect_suspicious_tls(self, context: DetectionContext) -> List[Detection]:
        """Detect suspicious TLS configurations and certificates"""
        detections = []
        
        for src_ip, activity in self.ip_activity.items():
            suspicious_tls_count = 0
            suspicious_indicators = []
            
            for session in activity['tls_sessions']:
                # Check for suspicious TLS versions or configurations
                version = session.get('version', '')
                if 'TLS' not in version or 'SSLv' in version:
                    suspicious_tls_count += 1
                    suspicious_indicators.append('Weak TLS version')
                
                # Check for self-signed or suspicious certificates (placeholder)
                # This would need certificate parsing enhancement
                sni = session.get('sni')
                if sni and self._is_suspicious_domain(sni):
                    suspicious_tls_count += 1
                    suspicious_indicators.append(f'Suspicious domain: {sni}')
            
            if suspicious_tls_count >= 3:
                detection = Detection(
                    id=f"suspicious_tls_{src_ip}_{int(activity['first_seen'])}",
                    name="Suspicious TLS Configuration",
                    description=f"Host {src_ip} established {suspicious_tls_count} suspicious TLS sessions",
                    severity=Severity.MEDIUM,
                    confidence=70,
                    source_ip=src_ip,
                    first_seen=datetime.fromtimestamp(activity['first_seen']),
                    last_seen=datetime.fromtimestamp(activity['last_seen']),
                    evidence={
                        'suspicious_sessions': suspicious_tls_count,
                        'total_tls_sessions': len(activity['tls_sessions']),
                        'indicators': suspicious_indicators[:5]  # Limit for readability
                    },
                    risk_score=40
                )
                detections.append(detection)
        
        return detections
    
    def _detect_http_anomalies(self, context: DetectionContext) -> List[Detection]:
        """Detect HTTP-based attacks and anomalies"""
        detections = []
        
        for src_ip, activity in self.ip_activity.items():
            high_risk_requests = [req for req in activity['http_requests'] if req.get('risk_score', 0) > 70]
            
            if len(high_risk_requests) >= 5:
                detection = Detection(
                    id=f"http_attack_{src_ip}_{int(activity['first_seen'])}",
                    name="HTTP-based Attack Patterns",
                    description=f"Host {src_ip} performed {len(high_risk_requests)} high-risk HTTP requests",
                    severity=Severity.HIGH,
                    confidence=80,
                    source_ip=src_ip,
                    first_seen=datetime.fromtimestamp(activity['first_seen']),
                    last_seen=datetime.fromtimestamp(activity['last_seen']),
                    evidence={
                        'high_risk_requests': len(high_risk_requests),
                        'total_http_requests': len(activity['http_requests']),
                        'attack_types': self._categorize_http_attacks(high_risk_requests)
                    },
                    risk_score=70
                )
                detections.append(detection)
        
        return detections
    
    def _detect_persistence_indicators(self, context: DetectionContext) -> List[Detection]:
        """Detect persistence mechanisms"""
        detections = []
        
        # Look for repeated connections to administrative ports over time
        for src_ip, activity in self.ip_activity.items():
            duration_hours = (activity['last_seen'] - activity['first_seen']) / 3600
            
            # Long-lived, low-traffic connections suggest persistence
            if duration_hours > 24 and activity['data_transferred'] < 1000000:  # Low data over long time
                detection = Detection(
                    id=f"persistence_{src_ip}_{int(activity['first_seen'])}",
                    name="Potential Persistence Mechanism",
                    description=f"Host {src_ip} maintained long-lived, low-traffic connections for {duration_hours:.1f} hours",
                    severity=Severity.MEDIUM,
                    confidence=60,
                    source_ip=src_ip,
                    first_seen=datetime.fromtimestamp(activity['first_seen']),
                    last_seen=datetime.fromtimestamp(activity['last_seen']),
                    evidence={
                        'duration_hours': duration_hours,
                        'total_data_bytes': activity['data_transferred'],
                        'hosts_contacted': len(activity['hosts_contacted']),
                        'data_rate_bph': activity['data_transferred'] / duration_hours  # Bytes per hour
                    },
                    risk_score=45
                )
                detections.append(detection)
        
        return detections
    
    def _detect_evasion_techniques(self, context: DetectionContext) -> List[Detection]:
        """Detect defense evasion techniques"""
        detections = []
        
        for src_ip, activity in self.ip_activity.items():
            # Check for protocol tunneling indicators
            protocol_diversity = len(activity['protocols'])
            
            # Unusual protocol usage
            if 'ICMP' in activity['protocols'] and activity['protocols']['ICMP'] > 100:
                detection = Detection(
                    id=f"icmp_tunnel_{src_ip}_{int(activity['first_seen'])}",
                    name="Potential ICMP Tunneling",
                    description=f"Host {src_ip} generated {activity['protocols']['ICMP']} ICMP packets, suggesting tunneling",
                    severity=Severity.MEDIUM,
                    confidence=65,
                    source_ip=src_ip,
                    first_seen=datetime.fromtimestamp(activity['first_seen']),
                    last_seen=datetime.fromtimestamp(activity['last_seen']),
                    evidence={
                        'icmp_packets': activity['protocols']['ICMP'],
                        'protocol_diversity': protocol_diversity,
                        'total_packets': sum(activity['protocols'].values())
                    },
                    risk_score=50
                )
                detections.append(detection)
        
        return detections
    
    def _apply_mitre_mappings(self, detections: List[Detection]) -> List[Detection]:
        """Apply MITRE ATT&CK mappings to detections"""
        mapping_dict = {
            'Port Scanning Activity': 'port_scanning',
            'Host Discovery Scanning': 'network_discovery',
            'Potential C2 Beaconing': 'c2_beaconing',
            'Suspicious HTTP Upload Activity': 'data_exfiltration',
            'Large Data Transfer': 'large_upload',
            'Potential Lateral Movement': 'lateral_movement',
            'Potential DNS Tunneling': 'dns_tunneling',
            'Brute Force Authentication Attack': 'brute_force',
            'Suspicious TLS Configuration': 'encrypted_channel',
            'HTTP-based Attack Patterns': 'data_exfiltration',
            'Potential Persistence Mechanism': 'persistence_connection',
            'Potential ICMP Tunneling': 'protocol_tunneling'
        }
        
        for detection in detections:
            detection_type = mapping_dict.get(detection.name)
            if detection_type:
                detection = self.mitre_mapper.map_detection(detection, detection_type)
        
        return detections
    
    def _is_internal_ip(self, ip: str) -> bool:
        """Check if IP is in internal/private range"""
        try:
            octets = [int(x) for x in ip.split('.')]
            
            # Private IP ranges
            if (octets[0] == 10 or 
                (octets[0] == 172 and 16 <= octets[1] <= 31) or
                (octets[0] == 192 and octets[1] == 168)):
                return True
            
            return False
        except:
            return False
    
    def _is_suspicious_domain(self, domain: str) -> bool:
        """Check if domain appears suspicious"""
        if not domain:
            return False
            
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.bit']
        suspicious_keywords = ['temp', 'test', 'malware', 'phish']
        
        if domain and any(domain.endswith(tld) for tld in suspicious_tlds):
            return True
        
        if domain and any(keyword in domain.lower() for keyword in suspicious_keywords):
            return True
        
        # High entropy check
        if domain and len(domain) > 10:
            unique_chars = len(set(domain.replace('.', '')))
            if unique_chars / len(domain.replace('.', '')) > 0.7:  # High character diversity
                return True
        
        return False
    
    def _categorize_http_attacks(self, requests: List[Dict]) -> List[str]:
        """Categorize HTTP attack patterns"""
        categories = set()
        
        for req in requests:
            path = req.get('path', '').lower()
            user_agent = req.get('user_agent', '').lower()
            
            if any(pattern in path for pattern in ['../', 'etc/passwd', 'boot.ini']):
                categories.add('Directory Traversal')
            
            if any(pattern in path for pattern in ['<script', 'javascript:', 'onerror=']):
                categories.add('Cross-Site Scripting')
            
            if any(pattern in path for pattern in ['union', 'select', 'drop table']):
                categories.add('SQL Injection')
            
            if any(ua in user_agent for ua in ['sqlmap', 'nikto', 'burp']):
                categories.add('Automated Scanner')
        
        return list(categories)
    
    def get_detection_stats(self) -> Dict:
        """Get detection engine statistics"""
        return {
            'tracked_ips': len(self.ip_activity),
            'ongoing_sessions': len(self.ongoing_sessions),
            'c2_candidates': len(self.c2_candidates),
            'lateral_movement_chains': len(self.lateral_movement_chains)
        }
