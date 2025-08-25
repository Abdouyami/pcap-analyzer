"""
Enhanced PCAP Analyzer with threat intelligence and advanced analytics
"""

import asyncio
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from typing import Dict, List, Optional, Any
import warnings
import math
import os

# Scapy imports with error handling
try:
    from scapy.all import rdpcap, IP, TCP, UDP, ICMP, ARP, Ether, DNS, DNSQR
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# ML imports with error handling
try:
    from sklearn.ensemble import IsolationForest
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False

# Import enhanced modules
from intel import VirusTotalProvider, AbuseIPDBProvider, GeolocationProvider, IntelCache
from intel.geo import MaxMindGeolocationProvider
from parsing import HTTPParser, TLSParser, DNSParser
from analytics import MitreMapper, RiskEngine, EnhancedDetectionEngine
from models.enrichment import EnrichmentResult, IndicatorType, GeoLocation
from models.detection import Detection, RiskScore

import streamlit as st

class EnhancedPCAPAnalyzer:
    """Enhanced PCAP analyzer with threat intelligence and advanced analytics"""
    
    def __init__(self, settings: Dict = None, enable_enrichment: bool = True, enable_deep_parsing: bool = True):
        self.settings = settings or {}
        self.enable_enrichment = enable_enrichment
        self.enable_deep_parsing = enable_deep_parsing
        
        # Core packet analysis attributes
        self.packets = []
        self.packet_df = pd.DataFrame()
        self.conversations = defaultdict(lambda: {
            'packets': 0, 'bytes': 0, 'payload_bytes': 0,
            'start_time': 0, 'end_time': 0,
            'protocols': Counter(), 'ports': set(),
            'tcp_flags': Counter(), 'directions': {},
            'avg_packet_size': 0, 'max_packet_size': 0,
            'min_packet_size': float('inf')
        })
        self.endpoints = defaultdict(lambda: {
            'tx_packets': 0, 'rx_packets': 0,
            'tx_bytes': 0, 'rx_bytes': 0
        })
        self.protocols = Counter()
        self.alerts = []
        self.dns_queries = defaultdict(list)
        self.problematic_packets = []
        
        # Enhanced analysis attributes
        self.enrichment_results = {}
        self.protocol_analysis = {}
        self.detections = []
        self.risk_scores = []
        self.mitre_report = {}
        
        # Initialize components
        self._initialize_components()
    
    def _initialize_components(self):
        """Initialize threat intelligence and analysis components"""
        # Initialize caching
        cache_dir = self.settings.get('cache_dir', './data/cache')
        self.intel_cache = IntelCache(cache_dir=cache_dir)
        
        # Initialize threat intelligence providers
        self.vt_provider = VirusTotalProvider(self.settings.get('vt_api_key'))
        self.abuseipdb_provider = AbuseIPDBProvider(self.settings.get('abuseipdb_api_key'))
        
        # Initialize geolocation provider
        self.geo_provider = MaxMindGeolocationProvider()
        
        # Initialize parsers
        if self.enable_deep_parsing:
            self.http_parser = HTTPParser()
            self.tls_parser = TLSParser()
            self.dns_parser = DNSParser()
        
        # Initialize analytics engines
        self.mitre_mapper = MitreMapper()
        self.risk_engine = RiskEngine()
        self.detection_engine = EnhancedDetectionEngine()
    
    def has_intel_capabilities(self) -> bool:
        """Check if threat intelligence capabilities are available"""
        return (self.vt_provider.is_enabled() or 
                self.abuseipdb_provider.is_enabled() or
                self.geo_provider.is_available())
    
    def load_pcap(self, file_path: str, max_packets: Optional[int] = None) -> bool:
        """Load and analyze PCAP file with enhanced capabilities"""
        if not SCAPY_AVAILABLE:
            st.error("Scapy not available. Cannot load PCAP files.")
            return False
        
        try:
            st.info("Loading PCAP file... This may take a moment for large files.")
            
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                all_packets = rdpcap(file_path)
            
            if max_packets and len(all_packets) > max_packets:
                self.packets = all_packets[:max_packets]
                st.warning(f"Limited analysis to first {max_packets:,} packets out of {len(all_packets):,} total")
            else:
                self.packets = all_packets
            
            # Analyze packets
            self._analyze_packets()
            
            # Run enhanced analysis
            if self.enable_deep_parsing:
                self._run_protocol_analysis()
            
            # Run detection engine
            self._run_detection_analysis()
            
            # Calculate risk scores
            self._calculate_risk_scores()
            
            return True
            
        except Exception as e:
            st.error(f"Error loading PCAP file: {str(e)}")
            return False
    
    def _analyze_packets(self):
        """Analyze packets with enhanced error handling"""
        packet_data = []
        total_packets = len(self.packets)
        
        # Create progress bar for large packet sets
        if total_packets > 1000:
            progress_bar = st.progress(0)
            status_text = st.empty()
        
        for i, pkt in enumerate(self.packets):
            # Update progress for large files
            if total_packets > 1000 and i % 1000 == 0:
                progress = i / total_packets
                progress_bar.progress(progress)
                status_text.text(f"Processing packet {i:,} of {total_packets:,} ({progress*100:.1f}%)")
            
            # Parse packet safely
            packet_info = self._safe_packet_parse(pkt, i)
            packet_data.append(packet_info)
            
            # Update statistics
            if packet_info['parsing_status'] in ['success', 'isakmp_skipped']:
                self._update_statistics(packet_info, pkt)
        
        # Clean up progress indicators
        if total_packets > 1000:
            progress_bar.empty()
            status_text.empty()
        
        # Convert to DataFrame
        self.packet_df = pd.DataFrame(packet_data)
        if not self.packet_df.empty:
            self.packet_df['datetime'] = pd.to_datetime(self.packet_df['timestamp'], unit='s')
        
        # Report parsing issues
        if self.problematic_packets:
            st.warning(f"Encountered parsing issues with {len(self.problematic_packets)} packets. Analysis continues with remaining data.")
        
        # Analyze conversations and generate basic alerts
        self._analyze_conversations()
        self._detect_basic_anomalies()
        self._generate_basic_alerts()
    
    def _safe_packet_parse(self, pkt, index: int) -> Dict:
        """Safely parse packet with enhanced error handling"""
        packet_info = {
            'index': index,
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
            'info': '',
            'parsing_status': 'success'
        }
        
        try:
            packet_info['info'] = str(pkt.summary())
            
            # Network layer parsing
            if IP in pkt:
                try:
                    packet_info['src_ip'] = pkt[IP].src
                    packet_info['dst_ip'] = pkt[IP].dst
                    packet_info['ttl'] = pkt[IP].ttl
                    packet_info['fragment_flags'] = str(pkt[IP].flags)
                    
                    ip_header_len = pkt[IP].ihl * 4
                    packet_info['payload_size'] = len(pkt) - ip_header_len
                    
                except Exception as e:
                    packet_info['parsing_status'] = f'ip_error: {str(e)[:50]}'
                    self.problematic_packets.append(index)
                
                # Transport layer parsing
                try:
                    if UDP in pkt:
                        packet_info['protocol'] = 'UDP'
                        packet_info['src_port'] = pkt[UDP].sport
                        packet_info['dst_port'] = pkt[UDP].dport
                        packet_info['payload_size'] -= 8
                        
                        # Handle ISAKMP
                        if pkt[UDP].dport in (500, 4500) or pkt[UDP].sport in (500, 4500):
                            packet_info['protocol'] = 'ISAKMP'
                            packet_info['info'] = f"ISAKMP packet {pkt[UDP].sport} -> {pkt[UDP].dport}"
                            packet_info['parsing_status'] = 'isakmp_skipped'
                            return packet_info
                        
                        # DNS parsing
                        elif pkt[UDP].dport == 53:
                            try:
                                if DNS in pkt and pkt[DNS].qr == 0 and hasattr(pkt[DNS], 'qd') and pkt[DNS].qd:
                                    domain = pkt[DNSQR].qname.decode('utf-8', errors='ignore').rstrip('.')
                                    self.dns_queries[packet_info['src_ip']].append(domain)
                            except:
                                pass
                                
                    elif TCP in pkt:
                        packet_info['protocol'] = 'TCP'
                        packet_info['src_port'] = pkt[TCP].sport
                        packet_info['dst_port'] = pkt[TCP].dport
                        packet_info['tcp_flags'] = str(pkt[TCP].flags)
                        packet_info['tcp_window'] = pkt[TCP].window
                        packet_info['tcp_seq'] = pkt[TCP].seq
                        packet_info['tcp_ack'] = pkt[TCP].ack
                        tcp_header_len = pkt[TCP].dataofs * 4
                        packet_info['payload_size'] -= tcp_header_len
                        
                    elif ICMP in pkt:
                        packet_info['protocol'] = 'ICMP'
                        packet_info['icmp_type'] = pkt[ICMP].type
                        packet_info['icmp_code'] = pkt[ICMP].code
                        packet_info['payload_size'] -= 8
                        
                except Exception as e:
                    packet_info['parsing_status'] = f'transport_error: {str(e)[:50]}'
                    self.problematic_packets.append(index)
                    
            elif ARP in pkt:
                try:
                    packet_info['protocol'] = 'ARP'
                    packet_info['src_ip'] = pkt[ARP].psrc
                    packet_info['dst_ip'] = pkt[ARP].pdst
                except Exception as e:
                    packet_info['parsing_status'] = f'arp_error: {str(e)[:50]}'
            
            else:
                try:
                    if hasattr(pkt, 'name'):
                        packet_info['protocol'] = pkt.name
                    else:
                        packet_info['protocol'] = 'Other'
                except:
                    packet_info['protocol'] = 'Unknown'
                    
        except Exception as e:
            packet_info['parsing_status'] = f'general_error: {str(e)[:50]}'
            packet_info['protocol'] = 'ParseError'
            self.problematic_packets.append(index)
        
        return packet_info
    
    def _update_statistics(self, packet_info: Dict, pkt):
        """Update conversation, endpoint, and protocol statistics"""
        src_ip = packet_info['src_ip']
        dst_ip = packet_info['dst_ip']
        protocol = packet_info['protocol']
        length = packet_info['length']
        payload_size = packet_info['payload_size']
        
        if src_ip and dst_ip:
            # Update conversations
            conv_key = tuple(sorted([src_ip, dst_ip]))
            conv = self.conversations[conv_key]
            
            if conv['packets'] == 0:  # First packet in conversation
                conv['start_time'] = packet_info['timestamp']
                conv['min_packet_size'] = length
            
            conv['packets'] += 1
            conv['bytes'] += length
            conv['payload_bytes'] += max(0, payload_size)
            conv['end_time'] = packet_info['timestamp']
            conv['protocols'][protocol] += 1
            
            # Update packet size statistics
            conv['max_packet_size'] = max(conv['max_packet_size'], length)
            conv['min_packet_size'] = min(conv['min_packet_size'], length)
            
            # Update directions
            direction_key = f"{src_ip}->{dst_ip}"
            if direction_key not in conv['directions']:
                conv['directions'][direction_key] = 0
            conv['directions'][direction_key] += 1
            
            # Add ports
            if packet_info['src_port']:
                conv['ports'].add(packet_info['src_port'])
            if packet_info['dst_port']:
                conv['ports'].add(packet_info['dst_port'])
            
            # Update endpoints
            self.endpoints[src_ip]['tx_packets'] += 1
            self.endpoints[src_ip]['tx_bytes'] += length
            self.endpoints[dst_ip]['rx_packets'] += 1
            self.endpoints[dst_ip]['rx_bytes'] += length
        
        # Update protocol statistics
        self.protocols[protocol] += 1
    
    def _analyze_conversations(self):
        """Analyze conversations for additional metrics"""
        for conv_key, conv in self.conversations.items():
            if conv['packets'] > 0:
                conv['avg_packet_size'] = conv['bytes'] / conv['packets']
                conv['duration'] = conv['end_time'] - conv['start_time']
                
                # Calculate bidirectionality ratio
                directions = list(conv['directions'].values())
                if len(directions) == 2:
                    conv['bidirectional_ratio'] = min(directions) / max(directions)
                else:
                    conv['bidirectional_ratio'] = 0
    
    def _detect_basic_anomalies(self):
        """Detect basic anomalies using statistical analysis"""
        if SKLEARN_AVAILABLE and not self.packet_df.empty:
            try:
                # Prepare features for anomaly detection
                features = []
                for _, row in self.packet_df.iterrows():
                    if pd.notna(row['length']) and pd.notna(row['timestamp']):
                        features.append([
                            row['length'],
                            row.get('payload_size', 0),
                            row.get('tcp_window', 0)
                        ])
                
                if len(features) > 10:  # Need minimum samples
                    features_array = np.array(features)
                    
                    # Run Isolation Forest
                    iso_forest = IsolationForest(contamination=0.1, random_state=42)
                    anomaly_labels = iso_forest.fit_predict(features_array)
                    
                    # Store anomaly results
                    self.packet_df['is_anomaly'] = False
                    valid_indices = self.packet_df.dropna(subset=['length', 'timestamp']).index
                    self.packet_df.loc[valid_indices, 'is_anomaly'] = (anomaly_labels == -1)
                    
            except Exception as e:
                st.warning(f"Anomaly detection failed: {e}")
    
    def _generate_basic_alerts(self):
        """Generate basic security alerts"""
        self.alerts = []
        
        # Port scanning detection
        for src_ip, queries in self.dns_queries.items():
            if len(queries) > 50:  # High DNS query volume
                self.alerts.append({
                    'type': 'DNS Tunneling',
                    'severity': 'Medium',
                    'description': f'High DNS query volume from {src_ip}: {len(queries)} queries',
                    'source_ip': src_ip
                })
        
        # Large data transfers
        for conv_key, conv in self.conversations.items():
            if conv['bytes'] > 100_000_000:  # 100MB
                src_ip, dst_ip = conv_key
                self.alerts.append({
                    'type': 'Large Data Transfer',
                    'severity': 'Medium',
                    'description': f'Large data transfer between {src_ip} and {dst_ip}: {conv["bytes"]:,} bytes',
                    'source_ip': src_ip,
                    'destination_ip': dst_ip
                })
    
    def _run_protocol_analysis(self):
        """Run enhanced protocol analysis"""
        if not self.enable_deep_parsing:
            return
        
        self.protocol_analysis = {
            'http': {'requests': [], 'responses': []},
            'tls': {'sessions': []},
            'dns': {'queries': []}
        }
        
        # Parse each packet with protocol-specific parsers
        for i, pkt in enumerate(self.packets):
            try:
                # HTTP analysis
                http_data = self.http_parser.parse_http_packet(pkt, i)
                if http_data:
                    if http_data.get('type') == 'http_request':
                        self.protocol_analysis['http']['requests'].append(http_data)
                    elif http_data.get('type') == 'http_response':
                        self.protocol_analysis['http']['responses'].append(http_data)
                
                # TLS analysis
                tls_data = self.tls_parser.parse_tls_packet(pkt, i)
                if tls_data:
                    self.protocol_analysis['tls']['sessions'].append(tls_data)
                
                # DNS analysis
                dns_data = self.dns_parser.parse_dns_packet(pkt, i)
                if dns_data:
                    self.protocol_analysis['dns']['queries'].append(dns_data)
                    
            except Exception as e:
                continue  # Skip problematic packets
    
    def _run_detection_analysis(self):
        """Run enhanced detection analysis"""
        try:
            # Run detection engine
            self.detections = self.detection_engine.analyze_packets(self.packets, self.packet_df)
            
            # Generate MITRE report
            self.mitre_report = self.mitre_mapper.generate_mitre_report(self.detections)
            
        except Exception as e:
            st.warning(f"Detection analysis failed: {e}")
            self.detections = []
    
    def _calculate_risk_scores(self):
        """Calculate risk scores for entities"""
        try:
            entities = []
            
            # Create risk entities for IPs
            for ip in set(self.packet_df['src_ip'].dropna()) | set(self.packet_df['dst_ip'].dropna()):
                ip_detections = [d for d in self.detections if d.source_ip == ip or d.destination_ip == ip]
                ip_traffic = self._get_ip_traffic_stats(ip)
                
                entities.append({
                    'type': 'ip',
                    'ip': ip,
                    'enrichment': self.enrichment_results.get(ip),
                    'detections': ip_detections,
                    'traffic_stats': ip_traffic
                })
            
            # Calculate risk scores
            self.risk_scores = self.risk_engine.bulk_calculate_risks(entities)
            
        except Exception as e:
            st.warning(f"Risk scoring failed: {e}")
            self.risk_scores = []
    
    def _get_ip_traffic_stats(self, ip: str) -> Dict:
        """Get traffic statistics for an IP"""
        ip_packets = self.packet_df[
            (self.packet_df['src_ip'] == ip) | (self.packet_df['dst_ip'] == ip)
        ]
        
        if ip_packets.empty:
            return {}
        
        total_bytes = ip_packets['length'].sum()
        duration = ip_packets['timestamp'].max() - ip_packets['timestamp'].min()
        
        return {
            'total_packets': len(ip_packets),
            'total_bytes': total_bytes,
            'duration': duration,
            'packets_per_second': len(ip_packets) / max(duration, 1),
            'avg_packet_size': ip_packets['length'].mean(),
            'protocols': ip_packets['protocol'].value_counts().to_dict()
        }
    
    async def enrich_indicators(self):
        """Enrich network indicators with threat intelligence"""
        if not self.enable_enrichment or not self.has_intel_capabilities():
            st.info("Threat intelligence enrichment not available or disabled.")
            return
        
        # Extract unique IPs
        unique_ips = set()
        if not self.packet_df.empty:
            unique_ips = set(self.packet_df['src_ip'].dropna()) | set(self.packet_df['dst_ip'].dropna())
        
        # Remove private/local IPs
        public_ips = [ip for ip in unique_ips if self._is_public_ip(ip)]
        
        if not public_ips:
            st.info("No public IPs found for enrichment.")
            return
        
        st.info(f"Enriching {len(public_ips)} public IP addresses...")
        
        # Enrich IPs with threat intelligence
        enrichment_tasks = []
        for ip in public_ips[:50]:  # Limit to prevent API quota exhaustion
            enrichment_tasks.append(self._enrich_single_ip(ip))
        
        # Run enrichment tasks concurrently
        results = await asyncio.gather(*enrichment_tasks, return_exceptions=True)
        
        # Process results
        successful_enrichments = 0
        for ip, result in zip(public_ips[:50], results):
            if isinstance(result, EnrichmentResult):
                self.enrichment_results[ip] = result
                successful_enrichments += 1
            elif isinstance(result, Exception):
                st.warning(f"Failed to enrich {ip}: {result}")
        
        st.success(f"Successfully enriched {successful_enrichments} IP addresses.")
        
        # Update cache stats in session state
        st.session_state.cache_stats = self.intel_cache.get_cache_stats()
    
    async def _enrich_single_ip(self, ip: str) -> Optional[EnrichmentResult]:
        """Enrich a single IP address"""
        try:
            # Check cache first
            cached_result = self._get_cached_enrichment(ip)
            if cached_result:
                return cached_result
            
            enrichment = EnrichmentResult(
                indicator=ip,
                indicator_type=IndicatorType.IP,
                sources={},
                overall_reputation=0
            )
            
            # Gather data from enabled sources
            tasks = []
            
            if self.vt_provider.is_enabled():
                tasks.append(('virustotal', self.vt_provider.enrich_ip(ip)))
            
            if self.abuseipdb_provider.is_enabled():
                tasks.append(('abuseipdb', self.abuseipdb_provider.enrich_ip(ip)))
            
            # Run API calls concurrently
            if tasks:
                api_results = await asyncio.gather(*[task[1] for task in tasks], return_exceptions=True)
                
                for i, (source_name, api_result) in enumerate(zip([task[0] for task in tasks], api_results)):
                    if isinstance(api_result, dict) and api_result:
                        if source_name == 'virustotal':
                            enrichment.sources[source_name] = self.vt_provider.create_source_result(api_result)
                        elif source_name == 'abuseipdb':
                            enrichment.sources[source_name] = self.abuseipdb_provider.create_source_result(api_result)
            
            # Get geographic data
            if self.geo_provider.is_available():
                geo_data = await self.geo_provider.get_location(ip)
                if geo_data:
                    enrichment.geo_location = self.geo_provider.create_geo_location(geo_data)
            
            # Calculate overall reputation
            if enrichment.sources:
                reputations = [source.reputation for source in enrichment.sources.values()]
                enrichment.overall_reputation = int(sum(reputations) / len(reputations))
                enrichment.confidence = min(100, len(enrichment.sources) * 30)  # Confidence based on source count
                
                # Check if malicious
                enrichment.is_malicious = any(source.reputation > 70 for source in enrichment.sources.values())
            
            # Cache the result
            self._cache_enrichment(ip, enrichment)
            
            return enrichment
            
        except Exception as e:
            st.warning(f"Error enriching {ip}: {e}")
            return None
    
    def _is_public_ip(self, ip: str) -> bool:
        """Check if IP is public (not private/local)"""
        try:
            octets = [int(x) for x in ip.split('.')]
            
            # Private IP ranges
            if (octets[0] == 10 or 
                (octets[0] == 172 and 16 <= octets[1] <= 31) or
                (octets[0] == 192 and octets[1] == 168) or
                octets[0] == 127):  # Loopback
                return False
            
            return True
        except:
            return False
    
    def _get_cached_enrichment(self, ip: str) -> Optional[EnrichmentResult]:
        """Get cached enrichment result"""
        # Implementation would use intel_cache
        return None
    
    def _cache_enrichment(self, ip: str, enrichment: EnrichmentResult):
        """Cache enrichment result"""
        # Implementation would use intel_cache
        pass
    
    def get_analysis_summary(self) -> Dict[str, Any]:
        """Get comprehensive analysis summary"""
        return {
            'packets': {
                'total': len(self.packets),
                'problematic': len(self.problematic_packets),
                'protocols': dict(self.protocols)
            },
            'conversations': {
                'total': len(self.conversations),
                'top_by_bytes': sorted(
                    [(k, v['bytes']) for k, v in self.conversations.items()],
                    key=lambda x: x[1],
                    reverse=True
                )[:10]
            },
            'enrichment': {
                'total_ips': len(self.enrichment_results),
                'malicious_ips': sum(1 for r in self.enrichment_results.values() if r.is_malicious),
                'sources_used': list(set(
                    source for result in self.enrichment_results.values()
                    for source in result.sources.keys()
                ))
            },
            'detections': {
                'total': len(self.detections),
                'by_severity': Counter(d.severity.value for d in self.detections),
                'mitre_techniques': len(set(
                    d.mitre_attack.technique for d in self.detections
                    if d.mitre_attack
                ))
            },
            'risk_assessment': {
                'entities_scored': len(self.risk_scores),
                'high_risk': sum(1 for r in self.risk_scores if r.overall_score >= 70),
                'medium_risk': sum(1 for r in self.risk_scores if 40 <= r.overall_score < 70),
                'low_risk': sum(1 for r in self.risk_scores if r.overall_score < 40)
            }
        }

