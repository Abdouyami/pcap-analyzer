"""
MITRE ATT&CK framework mapping for detections
"""

from typing import Dict, List, Optional
from models.detection import MitreAttack, Detection

class MitreMapper:
    """Maps security detections to MITRE ATT&CK framework"""
    
    def __init__(self):
        # MITRE ATT&CK mapping database
        self.attack_patterns = {
            # Reconnaissance (TA0043)
            'port_scanning': MitreAttack(
                tactic='TA0043',
                technique='T1046',
                name='Network Service Scanning',
                description='Adversaries may attempt to get a listing of services running on remote hosts.',
                url='https://attack.mitre.org/techniques/T1046/'
            ),
            
            # Discovery (TA0007)
            'network_discovery': MitreAttack(
                tactic='TA0007',
                technique='T1018',
                name='Remote System Discovery',
                description='Adversaries may attempt to get a listing of other systems by IP address, hostname, or other logical identifier.',
                url='https://attack.mitre.org/techniques/T1018/'
            ),
            
            # Command and Control (TA0011)
            'c2_beaconing': MitreAttack(
                tactic='TA0011',
                technique='T1071.001',
                subtechnique='T1071.001',
                name='Application Layer Protocol: Web Protocols',
                description='Adversaries may communicate using application layer protocols associated with web traffic.',
                url='https://attack.mitre.org/techniques/T1071/001/'
            ),
            
            'dns_tunneling': MitreAttack(
                tactic='TA0011',
                technique='T1071.004',
                subtechnique='T1071.004',
                name='Application Layer Protocol: DNS',
                description='Adversaries may communicate using the Domain Name System (DNS) application layer protocol.',
                url='https://attack.mitre.org/techniques/T1071/004/'
            ),
            
            # Exfiltration (TA0010)
            'data_exfiltration': MitreAttack(
                tactic='TA0010',
                technique='T1041',
                name='Exfiltration Over C2 Channel',
                description='Adversaries may steal data by exfiltrating it over an existing command and control channel.',
                url='https://attack.mitre.org/techniques/T1041/'
            ),
            
            'large_upload': MitreAttack(
                tactic='TA0010',
                technique='T1567.002',
                subtechnique='T1567.002',
                name='Exfiltration Over Web Service: Exfiltration to Cloud Storage',
                description='Adversaries may exfiltrate data to a cloud storage service rather than over their primary command and control channel.',
                url='https://attack.mitre.org/techniques/T1567/002/'
            ),
            
            # Credential Access (TA0006)
            'brute_force': MitreAttack(
                tactic='TA0006',
                technique='T1110',
                name='Brute Force',
                description='Adversaries may use brute force techniques to gain access to accounts.',
                url='https://attack.mitre.org/techniques/T1110/'
            ),
            
            'password_spraying': MitreAttack(
                tactic='TA0006',
                technique='T1110.003',
                subtechnique='T1110.003',
                name='Brute Force: Password Spraying',
                description='Adversaries may use a single or small list of commonly used passwords against many different accounts.',
                url='https://attack.mitre.org/techniques/T1110/003/'
            ),
            
            # Lateral Movement (TA0008)
            'lateral_movement': MitreAttack(
                tactic='TA0008',
                technique='T1021',
                name='Remote Services',
                description='Adversaries may use Valid Accounts to log into a service specifically designed to accept remote connections.',
                url='https://attack.mitre.org/techniques/T1021/'
            ),
            
            'smb_lateral_movement': MitreAttack(
                tactic='TA0008',
                technique='T1021.002',
                subtechnique='T1021.002',
                name='Remote Services: SMB/Windows Admin Shares',
                description='Adversaries may use SMB to interact with file shares, allowing them to move laterally throughout a network.',
                url='https://attack.mitre.org/techniques/T1021/002/'
            ),
            
            'rdp_lateral_movement': MitreAttack(
                tactic='TA0008',
                technique='T1021.001',
                subtechnique='T1021.001',
                name='Remote Services: Remote Desktop Protocol',
                description='Adversaries may use RDP to move laterally throughout a network.',
                url='https://attack.mitre.org/techniques/T1021/001/'
            ),
            
            # Persistence (TA0003)
            'persistence_connection': MitreAttack(
                tactic='TA0003',
                technique='T1053',
                name='Scheduled Task/Job',
                description='Adversaries may abuse task scheduling functionality to facilitate initial or recurring execution of malicious code.',
                url='https://attack.mitre.org/techniques/T1053/'
            ),
            
            'backdoor_connection': MitreAttack(
                tactic='TA0003',
                technique='T1205',
                name='Traffic Signaling',
                description='Adversaries may use traffic signaling to hide open ports or other malicious functionality.',
                url='https://attack.mitre.org/techniques/T1205/'
            ),
            
            # Defense Evasion (TA0005)
            'encrypted_channel': MitreAttack(
                tactic='TA0005',
                technique='T1573',
                name='Encrypted Channel',
                description='Adversaries may employ a known encryption algorithm to conceal command and control traffic.',
                url='https://attack.mitre.org/techniques/T1573/'
            ),
            
            'protocol_tunneling': MitreAttack(
                tactic='TA0005',
                technique='T1572',
                name='Protocol Tunneling',
                description='Adversaries may tunnel network communications to and from a victim system within a protocol to avoid detection.',
                url='https://attack.mitre.org/techniques/T1572/'
            ),
            
            # Impact (TA0040)
            'resource_hijacking': MitreAttack(
                tactic='TA0040',
                technique='T1496',
                name='Resource Hijacking',
                description='Adversaries may leverage the resources of co-opted systems in order to solve resource intensive problems.',
                url='https://attack.mitre.org/techniques/T1496/'
            ),
            
            'dos_attack': MitreAttack(
                tactic='TA0040',
                technique='T1498',
                name='Network Denial of Service',
                description='Adversaries may perform Network DoS attacks to degrade or block the availability of targeted resources to users.',
                url='https://attack.mitre.org/techniques/T1498/'
            )
        }
        
        # Tactic descriptions
        self.tactics = {
            'TA0043': 'Reconnaissance',
            'TA0042': 'Resource Development',
            'TA0001': 'Initial Access',
            'TA0002': 'Execution',
            'TA0003': 'Persistence',
            'TA0004': 'Privilege Escalation',
            'TA0005': 'Defense Evasion',
            'TA0006': 'Credential Access',
            'TA0007': 'Discovery',
            'TA0008': 'Lateral Movement',
            'TA0009': 'Collection',
            'TA0011': 'Command and Control',
            'TA0010': 'Exfiltration',
            'TA0040': 'Impact'
        }
    
    def get_mitre_mapping(self, detection_type: str) -> Optional[MitreAttack]:
        """Get MITRE ATT&CK mapping for detection type"""
        return self.attack_patterns.get(detection_type.lower())
    
    def map_detection(self, detection: Detection, detection_type: str) -> Detection:
        """Add MITRE ATT&CK mapping to detection"""
        mitre_mapping = self.get_mitre_mapping(detection_type)
        if mitre_mapping:
            detection.mitre_attack = mitre_mapping
        return detection
    
    def get_tactic_name(self, tactic_id: str) -> str:
        """Get human-readable tactic name"""
        return self.tactics.get(tactic_id, tactic_id)
    
    def get_techniques_by_tactic(self, tactic_id: str) -> List[MitreAttack]:
        """Get all techniques for a specific tactic"""
        return [
            attack for attack in self.attack_patterns.values()
            if attack.tactic == tactic_id
        ]
    
    def get_all_tactics(self) -> Dict[str, str]:
        """Get all MITRE ATT&CK tactics"""
        return self.tactics.copy()
    
    def get_kill_chain_stage(self, tactic_id: str) -> str:
        """Map MITRE tactic to kill chain stage"""
        kill_chain_mapping = {
            'TA0043': 'Reconnaissance',
            'TA0042': 'Weaponization',
            'TA0001': 'Delivery',
            'TA0002': 'Exploitation', 
            'TA0004': 'Installation',
            'TA0003': 'Installation',
            'TA0011': 'Command & Control',
            'TA0007': 'Actions on Objectives',
            'TA0008': 'Actions on Objectives',
            'TA0009': 'Actions on Objectives',
            'TA0010': 'Actions on Objectives',
            'TA0040': 'Actions on Objectives'
        }
        return kill_chain_mapping.get(tactic_id, 'Unknown')
    
    def create_attack_matrix_view(self, detections: List[Detection]) -> Dict[str, List[str]]:
        """Create ATT&CK matrix view of detections"""
        matrix = {}
        
        for detection in detections:
            if detection.mitre_attack:
                tactic = detection.mitre_attack.tactic
                tactic_name = self.get_tactic_name(tactic)
                
                if tactic_name not in matrix:
                    matrix[tactic_name] = []
                
                technique_info = f"{detection.mitre_attack.technique}: {detection.mitre_attack.name}"
                if technique_info not in matrix[tactic_name]:
                    matrix[tactic_name].append(technique_info)
        
        return matrix
    
    def generate_mitre_report(self, detections: List[Detection]) -> Dict:
        """Generate comprehensive MITRE ATT&CK report"""
        # Count techniques by tactic
        tactic_counts = {}
        technique_details = {}
        
        for detection in detections:
            if detection.mitre_attack:
                tactic = detection.mitre_attack.tactic
                technique = detection.mitre_attack.technique
                
                tactic_name = self.get_tactic_name(tactic)
                
                if tactic_name not in tactic_counts:
                    tactic_counts[tactic_name] = 0
                tactic_counts[tactic_name] += 1
                
                technique_key = f"{tactic}_{technique}"
                if technique_key not in technique_details:
                    technique_details[technique_key] = {
                        'tactic': tactic_name,
                        'technique_id': technique,
                        'technique_name': detection.mitre_attack.name,
                        'description': detection.mitre_attack.description,
                        'url': detection.mitre_attack.url,
                        'detection_count': 0,
                        'severity_breakdown': {'low': 0, 'medium': 0, 'high': 0, 'critical': 0}
                    }
                
                technique_details[technique_key]['detection_count'] += 1
                technique_details[technique_key]['severity_breakdown'][detection.severity.value] += 1
        
        return {
            'summary': {
                'total_detections': len(detections),
                'techniques_detected': len(technique_details),
                'tactics_involved': len(tactic_counts)
            },
            'tactic_breakdown': tactic_counts,
            'technique_details': list(technique_details.values()),
            'attack_matrix': self.create_attack_matrix_view(detections)
        }
