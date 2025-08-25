"""
TLS protocol analysis and fingerprinting
"""

import hashlib
import struct
from typing import Dict, List, Optional, Tuple
import binascii

try:
    from scapy.all import TCP, Raw, TLS
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

class TLSParser:
    """Enhanced TLS protocol parser with JA3/JA3S fingerprinting"""
    
    def __init__(self):
        self.tls_versions = {
            0x0300: "SSLv3",
            0x0301: "TLSv1.0", 
            0x0302: "TLSv1.1",
            0x0303: "TLSv1.2",
            0x0304: "TLSv1.3"
        }
        
        # Common cipher suites (subset for analysis)
        self.cipher_suites = {
            0x0000: "TLS_NULL_WITH_NULL_NULL",
            0x0001: "TLS_RSA_WITH_NULL_MD5",
            0x002F: "TLS_RSA_WITH_AES_128_CBC_SHA",
            0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
            0x009C: "TLS_RSA_WITH_AES_128_GCM_SHA256",
            0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            0xC030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            0x1301: "TLS_AES_128_GCM_SHA256",
            0x1302: "TLS_AES_256_GCM_SHA384",
            0x1303: "TLS_CHACHA20_POLY1305_SHA256"
        }
        
        self.suspicious_ciphers = {
            0x0000, 0x0001  # NULL ciphers
        }
    
    def parse_tls_packet(self, packet, packet_index: int) -> Optional[Dict]:
        """Parse TLS packet and extract handshake information"""
        if not SCAPY_AVAILABLE or not packet.haslayer(TCP) or not packet.haslayer(Raw):
            return None
        
        try:
            payload = packet[Raw].load
            
            # Check if this looks like TLS
            if len(payload) < 5 or payload[0] not in [0x16, 0x14, 0x15, 0x17]:  # TLS record types
                return None
            
            return self._parse_tls_record(payload, packet, packet_index)
            
        except Exception as e:
            return {
                'packet_index': packet_index,
                'parsing_error': str(e),
                'type': 'tls_parse_error'
            }
    
    def _parse_tls_record(self, payload: bytes, packet, packet_index: int) -> Optional[Dict]:
        """Parse TLS record structure"""
        if len(payload) < 5:
            return None
        
        # TLS Record Header: Type(1) + Version(2) + Length(2)
        record_type = payload[0]
        tls_version = struct.unpack('>H', payload[1:3])[0]
        record_length = struct.unpack('>H', payload[3:5])[0]
        
        record_data = {
            'packet_index': packet_index,
            'type': 'tls_record',
            'record_type': record_type,
            'tls_version': self.tls_versions.get(tls_version, f"Unknown (0x{tls_version:04x})"),
            'tls_version_hex': tls_version,
            'record_length': record_length,
            'src_ip': packet[TCP].sport,
            'dst_ip': packet[TCP].dport,
            'timestamp': float(packet.time),
            'handshake_data': None
        }
        
        # Parse handshake messages (record type 0x16)
        if record_type == 0x16 and len(payload) >= 9:  # Handshake
            handshake_data = self._parse_handshake(payload[5:])
            if handshake_data:
                record_data['handshake_data'] = handshake_data
                
                # Generate JA3 fingerprint for Client Hello
                if handshake_data.get('handshake_type') == 'client_hello':
                    ja3 = self._generate_ja3(handshake_data)
                    record_data['ja3'] = ja3
                    
                # Generate JA3S fingerprint for Server Hello
                elif handshake_data.get('handshake_type') == 'server_hello':
                    ja3s = self._generate_ja3s(handshake_data)
                    record_data['ja3s'] = ja3s
        
        return record_data
    
    def _parse_handshake(self, handshake_payload: bytes) -> Optional[Dict]:
        """Parse TLS handshake message"""
        if len(handshake_payload) < 4:
            return None
        
        # Handshake Header: Type(1) + Length(3)
        handshake_type = handshake_payload[0]
        handshake_length = struct.unpack('>I', b'\x00' + handshake_payload[1:4])[0]
        
        handshake_types = {
            0x01: 'client_hello',
            0x02: 'server_hello',
            0x0B: 'certificate',
            0x0C: 'server_key_exchange',
            0x0E: 'server_hello_done',
            0x10: 'client_key_exchange',
            0x14: 'finished'
        }
        
        result = {
            'handshake_type': handshake_types.get(handshake_type, f'unknown_{handshake_type:02x}'),
            'handshake_length': handshake_length
        }
        
        # Parse specific handshake types
        if handshake_type == 0x01:  # Client Hello
            client_hello = self._parse_client_hello(handshake_payload[4:])
            result.update(client_hello)
        elif handshake_type == 0x02:  # Server Hello
            server_hello = self._parse_server_hello(handshake_payload[4:])
            result.update(server_hello)
        elif handshake_type == 0x0B:  # Certificate
            cert_info = self._parse_certificate(handshake_payload[4:])
            result.update(cert_info)
        
        return result
    
    def _parse_client_hello(self, payload: bytes) -> Dict:
        """Parse Client Hello message"""
        if len(payload) < 34:  # Minimum Client Hello size
            return {}
        
        # Client Version (2 bytes)
        client_version = struct.unpack('>H', payload[0:2])[0]
        
        # Random (32 bytes) - skip for now
        offset = 34
        
        # Session ID
        if len(payload) <= offset:
            return {}
        session_id_length = payload[offset]
        offset += 1 + session_id_length
        
        # Cipher Suites
        if len(payload) <= offset + 1:
            return {}
        cipher_suites_length = struct.unpack('>H', payload[offset:offset+2])[0]
        offset += 2
        
        cipher_suites = []
        for i in range(0, cipher_suites_length, 2):
            if offset + i + 1 < len(payload):
                cipher = struct.unpack('>H', payload[offset+i:offset+i+2])[0]
                cipher_suites.append(cipher)
        offset += cipher_suites_length
        
        # Compression Methods
        if len(payload) <= offset:
            return {}
        compression_methods_length = payload[offset]
        offset += 1 + compression_methods_length
        
        # Extensions
        extensions = []
        sni = None
        if len(payload) > offset + 1:
            extensions_length = struct.unpack('>H', payload[offset:offset+2])[0]
            offset += 2
            
            # Parse extensions for SNI
            ext_data = payload[offset:offset+extensions_length]
            sni = self._extract_sni(ext_data)
            extensions = self._parse_extensions(ext_data)
        
        return {
            'client_version': self.tls_versions.get(client_version, f"Unknown (0x{client_version:04x})"),
            'cipher_suites': cipher_suites,
            'cipher_suites_names': [self.cipher_suites.get(cs, f"Unknown (0x{cs:04x})") for cs in cipher_suites],
            'extensions': extensions,
            'sni': sni,
            'suspicious_ciphers': [cs for cs in cipher_suites if cs in self.suspicious_ciphers]
        }
    
    def _parse_server_hello(self, payload: bytes) -> Dict:
        """Parse Server Hello message"""
        if len(payload) < 34:
            return {}
        
        # Server Version (2 bytes)
        server_version = struct.unpack('>H', payload[0:2])[0]
        
        # Skip Random (32 bytes)
        offset = 34
        
        # Session ID
        if len(payload) <= offset:
            return {}
        session_id_length = payload[offset]
        offset += 1 + session_id_length
        
        # Cipher Suite (selected)
        if len(payload) <= offset + 1:
            return {}
        selected_cipher = struct.unpack('>H', payload[offset:offset+2])[0]
        offset += 2
        
        # Compression Method
        if len(payload) <= offset:
            return {}
        compression_method = payload[offset]
        offset += 1
        
        # Extensions
        extensions = []
        if len(payload) > offset + 1:
            extensions_length = struct.unpack('>H', payload[offset:offset+2])[0]
            offset += 2
            ext_data = payload[offset:offset+extensions_length]
            extensions = self._parse_extensions(ext_data)
        
        return {
            'server_version': self.tls_versions.get(server_version, f"Unknown (0x{server_version:04x})"),
            'selected_cipher': selected_cipher,
            'selected_cipher_name': self.cipher_suites.get(selected_cipher, f"Unknown (0x{selected_cipher:04x})"),
            'compression_method': compression_method,
            'extensions': extensions,
            'suspicious_cipher': selected_cipher in self.suspicious_ciphers
        }
    
    def _parse_certificate(self, payload: bytes) -> Dict:
        """Parse Certificate message (basic analysis)"""
        if len(payload) < 3:
            return {}
        
        # Certificate list length
        cert_list_length = struct.unpack('>I', b'\x00' + payload[0:3])[0]
        
        # For now, just extract basic info
        return {
            'certificate_list_length': cert_list_length,
            'has_certificate': cert_list_length > 0
        }
    
    def _extract_sni(self, extensions_data: bytes) -> Optional[str]:
        """Extract Server Name Indication from extensions"""
        offset = 0
        
        while offset + 4 <= len(extensions_data):
            ext_type = struct.unpack('>H', extensions_data[offset:offset+2])[0]
            ext_length = struct.unpack('>H', extensions_data[offset+2:offset+4])[0]
            offset += 4
            
            # SNI extension type is 0x0000
            if ext_type == 0x0000 and ext_length > 0:
                return self._parse_sni_extension(extensions_data[offset:offset+ext_length])
            
            offset += ext_length
        
        return None
    
    def _parse_sni_extension(self, sni_data: bytes) -> Optional[str]:
        """Parse SNI extension data"""
        if len(sni_data) < 5:
            return None
        
        # Skip server name list length (2 bytes)
        offset = 2
        
        # Name type (1 byte) - should be 0 for hostname
        if sni_data[offset] != 0:
            return None
        offset += 1
        
        # Name length (2 bytes)
        name_length = struct.unpack('>H', sni_data[offset:offset+2])[0]
        offset += 2
        
        # Extract hostname
        if offset + name_length <= len(sni_data):
            return sni_data[offset:offset+name_length].decode('utf-8', errors='ignore')
        
        return None
    
    def _parse_extensions(self, extensions_data: bytes) -> List[int]:
        """Parse extension types"""
        extensions = []
        offset = 0
        
        while offset + 4 <= len(extensions_data):
            ext_type = struct.unpack('>H', extensions_data[offset:offset+2])[0]
            ext_length = struct.unpack('>H', extensions_data[offset+2:offset+4])[0]
            extensions.append(ext_type)
            offset += 4 + ext_length
        
        return extensions
    
    def _generate_ja3(self, client_hello: Dict) -> str:
        """Generate JA3 fingerprint from Client Hello"""
        try:
            # JA3 format: Version,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
            version = str(client_hello.get('client_version', '').split('(')[1].split(')')[0] if '(' in str(client_hello.get('client_version', '')) else '771')
            ciphers = '-'.join([str(cs) for cs in client_hello.get('cipher_suites', [])])
            extensions = '-'.join([str(ext) for ext in client_hello.get('extensions', [])])
            
            # For now, use placeholder values for curves and point formats
            curves = "23-24"  # Common curves
            point_formats = "0"  # Uncompressed
            
            ja3_string = f"{version},{ciphers},{extensions},{curves},{point_formats}"
            ja3_hash = hashlib.md5(ja3_string.encode()).hexdigest()
            
            return {
                'ja3_string': ja3_string,
                'ja3_hash': ja3_hash
            }
        except Exception as e:
            return {
                'ja3_string': '',
                'ja3_hash': '',
                'error': str(e)
            }
    
    def _generate_ja3s(self, server_hello: Dict) -> str:
        """Generate JA3S fingerprint from Server Hello"""
        try:
            # JA3S format: Version,Cipher,Extensions
            version = str(server_hello.get('server_version', '').split('(')[1].split(')')[0] if '(' in str(server_hello.get('server_version', '')) else '771')
            cipher = str(server_hello.get('selected_cipher', ''))
            extensions = '-'.join([str(ext) for ext in server_hello.get('extensions', [])])
            
            ja3s_string = f"{version},{cipher},{extensions}"
            ja3s_hash = hashlib.md5(ja3s_string.encode()).hexdigest()
            
            return {
                'ja3s_string': ja3s_string,
                'ja3s_hash': ja3s_hash
            }
        except Exception as e:
            return {
                'ja3s_string': '',
                'ja3s_hash': '',
                'error': str(e)
            }
    
    def analyze_tls_security(self, tls_data: Dict) -> Dict:
        """Analyze TLS configuration for security issues"""
        analysis = {
            'risk_score': 0,
            'issues': [],
            'recommendations': []
        }
        
        # Check handshake data
        handshake = tls_data.get('handshake_data', {})
        
        # Check for weak TLS versions
        tls_version = tls_data.get('tls_version_hex', 0)
        if tls_version < 0x0303:  # Below TLS 1.2
            analysis['risk_score'] += 40
            analysis['issues'].append('Weak TLS version')
            analysis['recommendations'].append('Upgrade to TLS 1.2 or higher')
        
        # Check for suspicious ciphers
        if handshake.get('suspicious_ciphers'):
            analysis['risk_score'] += 50
            analysis['issues'].append('Weak cipher suites')
            analysis['recommendations'].append('Use strong cipher suites')
        
        # Check for self-signed or unusual certificates (placeholder)
        if handshake.get('has_certificate') and not handshake.get('cert_verified', True):
            analysis['risk_score'] += 30
            analysis['issues'].append('Unverified certificate')
        
        return analysis
