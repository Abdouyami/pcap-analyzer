"""
Risk scoring engine for comprehensive threat assessment
"""

import yaml
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime
import math

from models.detection import RiskScore, Detection, Severity
from models.enrichment import EnrichmentResult, GeoLocation

class RiskEngine:
    """Comprehensive risk scoring engine with configurable weights and factors"""
    
    def __init__(self, config_path: str = "config.yaml"):
        self.config = self._load_config(config_path)
        self.weights = self.config.get('risk_scoring', {}).get('weights', {})
        self.thresholds = self.config.get('risk_scoring', {}).get('thresholds', {})
        self.geographic_config = self.config.get('geographic', {})
        
        # Default weights if config not available
        self.default_weights = {
            'threat_intel_reputation': 0.3,
            'protocol_anomalies': 0.2,
            'traffic_volume': 0.15,
            'geographic_risk': 0.15,
            'port_scanning': 0.1,
            'timing_anomalies': 0.1
        }
        
        # Ensure weights exist
        if not self.weights:
            self.weights = self.default_weights
    
    def _load_config(self, config_path: str) -> Dict:
        """Load configuration from YAML file"""
        try:
            with open(config_path, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            print(f"Warning: Could not load config from {config_path}: {e}")
            return {}
    
    def calculate_ip_risk(self, ip: str, enrichment: Optional[EnrichmentResult] = None,
                         detections: List[Detection] = None, traffic_stats: Dict = None) -> RiskScore:
        """Calculate comprehensive risk score for an IP address"""
        
        detections = detections or []
        traffic_stats = traffic_stats or {}
        
        contributing_factors = {}
        
        # Threat Intelligence Factor
        intel_score = self._calculate_intel_factor(enrichment)
        contributing_factors['threat_intelligence'] = intel_score * self.weights.get('threat_intel_reputation', 0.3)
        
        # Geographic Risk Factor  
        geo_score = self._calculate_geographic_factor(enrichment)
        contributing_factors['geographic_risk'] = geo_score * self.weights.get('geographic_risk', 0.15)
        
        # Detection Factor
        detection_score = self._calculate_detection_factor(detections)
        contributing_factors['security_detections'] = detection_score * self.weights.get('protocol_anomalies', 0.2)
        
        # Traffic Volume Factor
        traffic_score = self._calculate_traffic_factor(traffic_stats)
        contributing_factors['traffic_patterns'] = traffic_score * self.weights.get('traffic_volume', 0.15)
        
        # Port Scanning Factor
        scanning_score = self._calculate_scanning_factor(detections)
        contributing_factors['port_scanning'] = scanning_score * self.weights.get('port_scanning', 0.1)
        
        # Timing Anomalies Factor
        timing_score = self._calculate_timing_factor(traffic_stats)
        contributing_factors['timing_anomalies'] = timing_score * self.weights.get('timing_anomalies', 0.1)
        
        # Calculate weighted overall score
        overall_score = min(100, int(sum(contributing_factors.values())))
        
        return RiskScore(
            entity=ip,
            entity_type='ip_address',
            overall_score=overall_score,
            contributing_factors=contributing_factors,
            detections=detections,
            threat_intel=enrichment.dict() if enrichment else None,
            calculated_at=datetime.now()
        )
    
    def calculate_conversation_risk(self, src_ip: str, dst_ip: str,
                                   conversation_data: Dict, detections: List[Detection] = None) -> RiskScore:
        """Calculate risk score for a conversation between two IPs"""
        
        detections = detections or []
        contributing_factors = {}
        
        # Traffic Volume Risk
        bytes_transferred = conversation_data.get('bytes', 0)
        packets_count = conversation_data.get('packets', 0)
        duration = conversation_data.get('duration', 0)
        
        volume_risk = self._assess_volume_risk(bytes_transferred, packets_count, duration)
        contributing_factors['traffic_volume'] = volume_risk * 0.3
        
        # Port Risk Assessment
        ports = conversation_data.get('ports', set())
        port_risk = self._assess_port_risk(ports)
        contributing_factors['port_risk'] = port_risk * 0.2
        
        # Protocol Distribution Risk
        protocols = conversation_data.get('protocols', {})
        protocol_risk = self._assess_protocol_risk(protocols)
        contributing_factors['protocol_risk'] = protocol_risk * 0.2
        
        # Detection Severity
        detection_risk = self._calculate_detection_factor(detections)
        contributing_factors['detections'] = detection_risk * 0.3
        
        overall_score = min(100, int(sum(contributing_factors.values())))
        
        conversation_id = f"{src_ip}<->{dst_ip}"
        
        return RiskScore(
            entity=conversation_id,
            entity_type='conversation',
            overall_score=overall_score,
            contributing_factors=contributing_factors,
            detections=detections,
            calculated_at=datetime.now()
        )
    
    def calculate_domain_risk(self, domain: str, dns_analysis: Dict = None,
                             enrichment: Optional[EnrichmentResult] = None) -> RiskScore:
        """Calculate risk score for a domain"""
        
        dns_analysis = dns_analysis or {}
        contributing_factors = {}
        
        # Domain characteristics
        domain_risk = self._assess_domain_characteristics(domain, dns_analysis)
        contributing_factors['domain_characteristics'] = domain_risk * 0.4
        
        # Threat intelligence
        intel_risk = self._calculate_intel_factor(enrichment) if enrichment else 0
        contributing_factors['threat_intelligence'] = intel_risk * 0.3
        
        # DNS query patterns
        query_risk = self._assess_dns_patterns(dns_analysis)
        contributing_factors['query_patterns'] = query_risk * 0.3
        
        overall_score = min(100, int(sum(contributing_factors.values())))
        
        return RiskScore(
            entity=domain,
            entity_type='domain',
            overall_score=overall_score,
            contributing_factors=contributing_factors,
            threat_intel=enrichment.dict() if enrichment else None,
            calculated_at=datetime.now()
        )
    
    def _calculate_intel_factor(self, enrichment: Optional[EnrichmentResult]) -> float:
        """Calculate threat intelligence risk factor (0-100)"""
        if not enrichment:
            return 10  # Slight risk for unknown entities
        
        # Use overall reputation (inverted - high reputation = low risk)
        reputation = enrichment.overall_reputation
        risk_score = max(0, 100 - reputation)
        
        # Boost if marked as malicious
        if enrichment.is_malicious:
            risk_score = max(risk_score, 80)
        
        # Factor in confidence
        confidence_factor = enrichment.confidence / 100
        risk_score *= confidence_factor
        
        return min(100, risk_score)
    
    def _calculate_geographic_factor(self, enrichment: Optional[EnrichmentResult]) -> float:
        """Calculate geographic risk factor"""
        if not enrichment or not enrichment.geo_location:
            return 0
        
        geo = enrichment.geo_location
        risk_score = 0
        
        # High-risk countries
        high_risk_countries = set(self.geographic_config.get('high_risk_countries', []))
        if geo.country_code in high_risk_countries:
            risk_score += 40
        
        # Suspicious ASNs
        suspicious_asns = set(self.geographic_config.get('suspicious_asns', []))
        if geo.asn and geo.asn in suspicious_asns:
            risk_score += 30
        
        # Use geo risk score if available
        if hasattr(geo, 'risk_score') and geo.risk_score:
            risk_score = max(risk_score, geo.risk_score)
        
        return min(100, risk_score)
    
    def _calculate_detection_factor(self, detections: List[Detection]) -> float:
        """Calculate detection-based risk factor"""
        if not detections:
            return 0
        
        # Weight detections by severity
        severity_weights = {
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4
        }
        
        weighted_score = 0
        for detection in detections:
            weight = severity_weights.get(detection.severity, 1)
            confidence_factor = detection.confidence / 100
            weighted_score += weight * confidence_factor * 20  # Scale to 0-80 per detection
        
        return min(100, weighted_score)
    
    def _calculate_traffic_factor(self, traffic_stats: Dict) -> float:
        """Calculate traffic volume risk factor"""
        if not traffic_stats:
            return 0
        
        risk_score = 0
        
        # High packet rate
        packet_rate = traffic_stats.get('packets_per_second', 0)
        if packet_rate > 1000:
            risk_score += 40
        elif packet_rate > 100:
            risk_score += 20
        
        # Large data transfer
        total_bytes = traffic_stats.get('total_bytes', 0)
        if total_bytes > 1e9:  # 1GB
            risk_score += 30
        elif total_bytes > 1e8:  # 100MB
            risk_score += 15
        
        # Unusual packet size patterns
        avg_packet_size = traffic_stats.get('avg_packet_size', 0)
        if avg_packet_size > 1400 or avg_packet_size < 64:
            risk_score += 10
        
        return min(100, risk_score)
    
    def _calculate_scanning_factor(self, detections: List[Detection]) -> float:
        """Calculate port scanning risk factor"""
        scanning_detections = [
            d for d in detections 
            if 'scan' in d.name.lower() or 'reconnaissance' in d.name.lower()
        ]
        
        if not scanning_detections:
            return 0
        
        # High risk for multiple scanning activities
        return min(100, len(scanning_detections) * 30)
    
    def _calculate_timing_factor(self, traffic_stats: Dict) -> float:
        """Calculate timing anomaly risk factor"""
        if not traffic_stats:
            return 0
        
        risk_score = 0
        
        # Check for beaconing patterns
        timing_variance = traffic_stats.get('timing_variance', 1.0)
        if timing_variance < 0.3:  # Low variance suggests beaconing
            risk_score += 40
        
        # Unusual session duration
        session_duration = traffic_stats.get('duration', 0)
        if session_duration > 3600:  # Very long sessions
            risk_score += 20
        
        return min(100, risk_score)
    
    def _assess_volume_risk(self, bytes_transferred: int, packets: int, duration: float) -> float:
        """Assess risk based on traffic volume"""
        if duration <= 0:
            return 0
        
        bytes_per_second = bytes_transferred / duration
        packets_per_second = packets / duration
        
        risk = 0
        
        # High bandwidth usage
        if bytes_per_second > 10e6:  # 10MB/s
            risk += 40
        elif bytes_per_second > 1e6:  # 1MB/s
            risk += 20
        
        # High packet rate
        if packets_per_second > 1000:
            risk += 30
        elif packets_per_second > 100:
            risk += 15
        
        return min(100, risk)
    
    def _assess_port_risk(self, ports: set) -> float:
        """Assess risk based on ports used"""
        if not ports:
            return 0
        
        # High-risk ports
        high_risk_ports = {22, 23, 3389, 1433, 3306, 5432, 6379, 27017}
        admin_ports = {22, 23, 3389, 5985, 5986}
        
        risk = 0
        
        # Count high-risk ports
        risky_ports = ports.intersection(high_risk_ports)
        risk += len(risky_ports) * 15
        
        # Administrative ports
        admin_access = ports.intersection(admin_ports)
        risk += len(admin_access) * 20
        
        # Many different ports (potential scanning)
        if len(ports) > 10:
            risk += 25
        
        return min(100, risk)
    
    def _assess_protocol_risk(self, protocols: Dict) -> float:
        """Assess risk based on protocol distribution"""
        if not protocols:
            return 0
        
        risk = 0
        total_packets = sum(protocols.values())
        
        # Check for unusual protocol usage
        unusual_protocols = {'ICMP', 'ISAKMP', 'GRE'}
        for proto in unusual_protocols:
            if proto in protocols:
                ratio = protocols[proto] / total_packets
                if ratio > 0.5:  # More than 50% unusual protocol
                    risk += 30
        
        return min(100, risk)
    
    def _assess_domain_characteristics(self, domain: str, dns_analysis: Dict) -> float:
        """Assess domain risk based on characteristics"""
        risk = 0
        
        # Domain length
        if len(domain) > 50:
            risk += 25
        
        # Entropy (randomness)
        entropy = dns_analysis.get('entropy', 0)
        if entropy > 4.5:
            risk += 30
        elif entropy > 3.5:
            risk += 15
        
        # DGA-like characteristics
        if dns_analysis.get('is_dga_like', False):
            risk += 35
        
        # Suspicious TLD
        if dns_analysis.get('is_suspicious_tld', False):
            risk += 20
        
        return min(100, risk)
    
    def _assess_dns_patterns(self, dns_analysis: Dict) -> float:
        """Assess DNS query pattern risk"""
        risk = 0
        
        # High query rate
        query_rate = dns_analysis.get('query_rate_per_minute', 0)
        if query_rate > 50:
            risk += 40
        elif query_rate > 10:
            risk += 20
        
        # Many unique domains
        unique_ratio = dns_analysis.get('unique_domains_ratio', 0)
        if unique_ratio > 0.8:
            risk += 25
        
        return min(100, risk)
    
    def get_risk_explanation(self, risk_score: RiskScore) -> List[str]:
        """Generate human-readable risk explanation"""
        explanations = []
        
        # Sort factors by contribution
        sorted_factors = sorted(
            risk_score.contributing_factors.items(),
            key=lambda x: x[1],
            reverse=True
        )
        
        for factor, contribution in sorted_factors[:5]:  # Top 5 factors
            if contribution > 5:  # Only significant factors
                explanations.append(f"{factor.replace('_', ' ').title()}: {contribution:.1f} points")
        
        return explanations
    
    def bulk_calculate_risks(self, entities: List[Dict]) -> List[RiskScore]:
        """Calculate risk scores for multiple entities efficiently"""
        risk_scores = []
        
        for entity in entities:
            entity_type = entity.get('type')
            
            if entity_type == 'ip':
                risk_score = self.calculate_ip_risk(
                    ip=entity['ip'],
                    enrichment=entity.get('enrichment'),
                    detections=entity.get('detections'),
                    traffic_stats=entity.get('traffic_stats')
                )
            elif entity_type == 'conversation':
                risk_score = self.calculate_conversation_risk(
                    src_ip=entity['src_ip'],
                    dst_ip=entity['dst_ip'],
                    conversation_data=entity['conversation_data'],
                    detections=entity.get('detections')
                )
            elif entity_type == 'domain':
                risk_score = self.calculate_domain_risk(
                    domain=entity['domain'],
                    dns_analysis=entity.get('dns_analysis'),
                    enrichment=entity.get('enrichment')
                )
            else:
                continue
            
            risk_scores.append(risk_score)
        
        return risk_scores
