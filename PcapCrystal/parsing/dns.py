"""
DNS protocol analysis and tunneling detection
"""

import math
import re
from typing import Dict, List, Optional, Set
from collections import Counter, defaultdict
from datetime import datetime, timedelta

try:
    from scapy.all import DNS, DNSQR, DNSRR, UDP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

class DNSParser:
    """Enhanced DNS protocol parser with tunneling detection"""
    
    def __init__(self):
        self.suspicious_tlds = {
            '.tk', '.ml', '.ga', '.cf', '.onion', '.bit',
            '.xxx', '.click', '.download', '.work'
        }
        
        self.dga_indicators = [
            r'^[a-z0-9]{8,}$',  # Long random strings
            r'[0-9]{3,}',       # Multiple numbers
            r'[bcdfghjklmnpqrstvwxyz]{5,}',  # Consonant clusters
        ]
        
        # Track DNS queries for tunneling detection
        self.query_history = defaultdict(list)
        self.domain_entropy_cache = {}
        
    def parse_dns_packet(self, packet, packet_index: int) -> Optional[Dict]:
        """Parse DNS packet and extract query/response information"""
        if not SCAPY_AVAILABLE or not packet.haslayer(DNS):
            return None
        
        try:
            dns_layer = packet[DNS]
            
            result = {
                'packet_index': packet_index,
                'type': 'dns',
                'transaction_id': dns_layer.id,
                'flags': dns_layer.flags,
                'is_query': dns_layer.qr == 0,
                'is_response': dns_layer.qr == 1,
                'opcode': dns_layer.opcode,
                'response_code': dns_layer.rcode,
                'questions': [],
                'answers': [],
                'timestamp': float(packet.time),
                'src_ip': packet[UDP].sport if packet.haslayer(UDP) else None,
                'dst_ip': packet[UDP].dport if packet.haslayer(UDP) else None
            }
            
            # Parse questions
            if dns_layer.qdcount > 0 and hasattr(dns_layer, 'qd') and dns_layer.qd:
                query = dns_layer.qd
                domain = query.qname.decode('utf-8', errors='ignore').rstrip('.')
                
                question_data = {
                    'domain': domain,
                    'qtype': query.qtype,
                    'qtype_name': self._get_qtype_name(query.qtype),
                    'qclass': query.qclass
                }
                
                result['questions'].append(question_data)
                
                # Add domain analysis
                if dns_layer.qr == 0:  # Query
                    domain_analysis = self._analyze_domain(domain, packet_index)
                    result['domain_analysis'] = domain_analysis
                    
                    # Track for tunneling detection
                    src_ip = str(packet.src) if hasattr(packet, 'src') else 'unknown'
                    self._track_query(src_ip, domain, packet.time)
            
            # Parse answers
            if dns_layer.ancount > 0 and hasattr(dns_layer, 'an') and dns_layer.an:
                answer = dns_layer.an
                while answer:
                    answer_data = {
                        'name': answer.rrname.decode('utf-8', errors='ignore').rstrip('.'),
                        'type': answer.type,
                        'type_name': self._get_qtype_name(answer.type),
                        'class': answer.rclass,
                        'ttl': answer.ttl,
                        'data': str(answer.rdata) if hasattr(answer, 'rdata') else ''
                    }
                    result['answers'].append(answer_data)
                    answer = answer.payload if hasattr(answer, 'payload') else None
            
            return result
            
        except Exception as e:
            return {
                'packet_index': packet_index,
                'parsing_error': str(e),
                'type': 'dns_parse_error'
            }
    
    def _get_qtype_name(self, qtype: int) -> str:
        """Get human-readable query type name"""
        qtypes = {
            1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 12: 'PTR',
            15: 'MX', 16: 'TXT', 28: 'AAAA', 33: 'SRV', 99: 'SPF'
        }
        return qtypes.get(qtype, f'TYPE{qtype}')
    
    def _analyze_domain(self, domain: str, packet_index: int) -> Dict:
        """Analyze domain for suspicious characteristics"""
        analysis = {
            'length': len(domain),
            'entropy': self._calculate_entropy(domain),
            'is_suspicious_tld': any(domain.endswith(tld) for tld in self.suspicious_tlds),
            'is_dga_like': self._check_dga_patterns(domain),
            'subdomain_count': domain.count('.'),
            'numeric_ratio': sum(c.isdigit() for c in domain) / len(domain),
            'risk_score': 0
        }
        
        # Calculate risk score
        risk_score = 0
        
        # Long domains are suspicious
        if analysis['length'] > 50:
            risk_score += 30
        elif analysis['length'] > 30:
            risk_score += 15
        
        # High entropy suggests randomness
        if analysis['entropy'] > 4.5:
            risk_score += 40
        elif analysis['entropy'] > 3.5:
            risk_score += 20
        
        # Suspicious TLD
        if analysis['is_suspicious_tld']:
            risk_score += 25
        
        # DGA-like patterns
        if analysis['is_dga_like']:
            risk_score += 35
        
        # Many subdomains
        if analysis['subdomain_count'] > 3:
            risk_score += 15
        
        # High numeric content
        if analysis['numeric_ratio'] > 0.3:
            risk_score += 20
        
        analysis['risk_score'] = min(100, risk_score)
        
        return analysis
    
    def _calculate_entropy(self, domain: str) -> float:
        """Calculate Shannon entropy of domain name"""
        if domain in self.domain_entropy_cache:
            return self.domain_entropy_cache[domain]
        
        # Remove common separators for entropy calculation
        clean_domain = domain.replace('.', '').replace('-', '').lower()
        
        if not clean_domain:
            return 0.0
        
        # Count character frequencies
        char_counts = Counter(clean_domain)
        length = len(clean_domain)
        
        # Calculate Shannon entropy
        entropy = 0.0
        for count in char_counts.values():
            probability = count / length
            entropy -= probability * math.log2(probability)
        
        self.domain_entropy_cache[domain] = entropy
        return entropy
    
    def _check_dga_patterns(self, domain: str) -> bool:
        """Check if domain matches DGA patterns"""
        domain_parts = domain.split('.')
        
        for part in domain_parts[:-1]:  # Exclude TLD
            for pattern in self.dga_indicators:
                if re.search(pattern, part.lower()):
                    return True
        
        return False
    
    def _track_query(self, src_ip: str, domain: str, timestamp: float):
        """Track DNS queries for tunneling detection"""
        query_record = {
            'domain': domain,
            'timestamp': timestamp,
            'length': len(domain)
        }
        
        self.query_history[src_ip].append(query_record)
        
        # Keep only recent queries (last hour)
        cutoff_time = timestamp - 3600  # 1 hour ago
        self.query_history[src_ip] = [
            q for q in self.query_history[src_ip] 
            if q['timestamp'] > cutoff_time
        ]
    
    def detect_dns_tunneling(self, src_ip: str, time_window_minutes: int = 60) -> Dict:
        """Detect DNS tunneling patterns for a specific IP"""
        if src_ip not in self.query_history:
            return {'is_tunneling': False, 'confidence': 0, 'indicators': []}
        
        queries = self.query_history[src_ip]
        if not queries:
            return {'is_tunneling': False, 'confidence': 0, 'indicators': []}
        
        current_time = max(q['timestamp'] for q in queries)
        cutoff_time = current_time - (time_window_minutes * 60)
        
        recent_queries = [q for q in queries if q['timestamp'] > cutoff_time]
        
        if len(recent_queries) < 10:  # Need sufficient data
            return {'is_tunneling': False, 'confidence': 0, 'indicators': []}
        
        indicators = []
        confidence = 0
        
        # High query rate
        query_rate = len(recent_queries) / time_window_minutes
        if query_rate > 5:  # More than 5 queries per minute
            indicators.append(f'High query rate: {query_rate:.1f}/min')
            confidence += 30
        
        # Unusual query lengths
        lengths = [q['length'] for q in recent_queries]
        avg_length = sum(lengths) / len(lengths)
        if avg_length > 40:
            indicators.append(f'Long domain names: avg {avg_length:.1f} chars')
            confidence += 25
        
        # High entropy domains
        high_entropy_count = 0
        for query in recent_queries:
            entropy = self._calculate_entropy(query['domain'])
            if entropy > 3.5:
                high_entropy_count += 1
        
        if high_entropy_count / len(recent_queries) > 0.5:
            indicators.append(f'High entropy domains: {high_entropy_count}/{len(recent_queries)}')
            confidence += 25
        
        # Unique domains (not repeated queries)
        unique_domains = len(set(q['domain'] for q in recent_queries))
        uniqueness_ratio = unique_domains / len(recent_queries)
        if uniqueness_ratio > 0.8:
            indicators.append(f'Many unique domains: {uniqueness_ratio:.1%}')
            confidence += 20
        
        return {
            'is_tunneling': confidence > 50,
            'confidence': min(100, confidence),
            'indicators': indicators,
            'query_count': len(recent_queries),
            'unique_domains': unique_domains,
            'avg_length': avg_length,
            'query_rate_per_minute': query_rate
        }
    
    def get_top_queried_domains(self, src_ip: str, limit: int = 10) -> List[Dict]:
        """Get top queried domains for an IP"""
        if src_ip not in self.query_history:
            return []
        
        domain_counts = Counter(q['domain'] for q in self.query_history[src_ip])
        
        top_domains = []
        for domain, count in domain_counts.most_common(limit):
            domain_analysis = self._analyze_domain(domain, 0)
            top_domains.append({
                'domain': domain,
                'query_count': count,
                'risk_score': domain_analysis['risk_score'],
                'entropy': domain_analysis['entropy'],
                'length': domain_analysis['length']
            })
        
        return top_domains
    
    def get_dns_stats(self) -> Dict:
        """Get overall DNS statistics"""
        total_ips = len(self.query_history)
        total_queries = sum(len(queries) for queries in self.query_history.values())
        
        all_domains = []
        for queries in self.query_history.values():
            all_domains.extend(q['domain'] for q in queries)
        
        unique_domains = len(set(all_domains))
        
        return {
            'total_querying_ips': total_ips,
            'total_queries': total_queries,
            'unique_domains': unique_domains,
            'avg_queries_per_ip': total_queries / total_ips if total_ips > 0 else 0
        }
