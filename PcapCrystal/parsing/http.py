"""
HTTP protocol deep packet inspection
"""

import re
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse
import base64

try:
    from scapy.all import TCP, Raw
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

class HTTPParser:
    """Enhanced HTTP protocol parser for deep packet inspection"""
    
    def __init__(self):
        self.suspicious_user_agents = {
            'curl', 'wget', 'python-requests', 'python-urllib', 'powershell',
            'metasploit', 'nmap', 'sqlmap', 'nikto', 'burp', 'dirb'
        }
        
        self.suspicious_methods = {
            'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'TRACE', 'CONNECT'
        }
        
        self.common_attack_patterns = [
            r'(\.\./)+',           # Directory traversal
            r'<script[^>]*>',      # XSS
            r'union.*select',      # SQL injection
            r'exec\s*\(',          # Code execution
            r'eval\s*\(',          # Code evaluation
            r'system\s*\(',        # System commands
        ]
        
        self.file_types = {
            b'\x89PNG': 'image/png',
            b'GIF8': 'image/gif', 
            b'\xFF\xD8\xFF': 'image/jpeg',
            b'%PDF': 'application/pdf',
            b'PK\x03\x04': 'application/zip',
            b'\x00\x00\x01\x00': 'application/x-ico'
        }
    
    def parse_http_packet(self, packet, packet_index: int) -> Optional[Dict]:
        """Parse HTTP packet and extract relevant information"""
        if not SCAPY_AVAILABLE or not packet.haslayer(TCP) or not packet.haslayer(Raw):
            return None
        
        try:
            payload = packet[Raw].load
            payload_str = payload.decode('utf-8', errors='ignore')
            
            # Check if this looks like HTTP
            if not self._is_http_traffic(payload_str):
                return None
            
            # Determine if request or response
            if payload_str.startswith(('GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ', 'OPTIONS ', 'PATCH ', 'TRACE ', 'CONNECT ')):
                return self._parse_http_request(payload_str, packet, packet_index)
            elif payload_str.startswith('HTTP/'):
                return self._parse_http_response(payload_str, packet, packet_index)
            
            return None
            
        except Exception as e:
            return {
                'packet_index': packet_index,
                'parsing_error': str(e),
                'type': 'http_parse_error'
            }
    
    def _is_http_traffic(self, payload: str) -> bool:
        """Determine if payload contains HTTP traffic"""
        http_indicators = [
            'HTTP/1.', 'GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ',
            'Content-Type:', 'User-Agent:', 'Host:', 'Accept:'
        ]
        return any(indicator in payload[:200] for indicator in http_indicators)
    
    def _parse_http_request(self, payload: str, packet, packet_index: int) -> Dict:
        """Parse HTTP request"""
        lines = payload.split('\r\n')
        if not lines:
            return None
        
        # Parse request line
        request_line = lines[0]
        request_parts = request_line.split(' ')
        if len(request_parts) < 3:
            return None
        
        method, path, version = request_parts[0], request_parts[1], request_parts[2]
        
        # Parse headers
        headers = {}
        body_start = 0
        for i, line in enumerate(lines[1:], 1):
            if line == '':
                body_start = i + 1
                break
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip().lower()] = value.strip()
        
        # Extract body if present
        body = '\r\n'.join(lines[body_start:]) if body_start < len(lines) else ''
        
        # Analyze request
        analysis = self._analyze_http_request(method, path, headers, body)
        
        return {
            'packet_index': packet_index,
            'type': 'http_request',
            'method': method,
            'path': path,
            'version': version,
            'headers': headers,
            'body_length': len(body),
            'body_preview': body[:500] if body else '',
            'host': headers.get('host', ''),
            'user_agent': headers.get('user-agent', ''),
            'content_type': headers.get('content-type', ''),
            'content_length': int(headers.get('content-length', 0)) if headers.get('content-length', '').isdigit() else 0,
            'referer': headers.get('referer', ''),
            'analysis': analysis,
            'src_ip': packet[TCP].sport,
            'dst_ip': packet[TCP].dport,
            'timestamp': float(packet.time)
        }
    
    def _parse_http_response(self, payload: str, packet, packet_index: int) -> Dict:
        """Parse HTTP response"""
        lines = payload.split('\r\n')
        if not lines:
            return None
        
        # Parse status line
        status_line = lines[0]
        status_parts = status_line.split(' ', 2)
        if len(status_parts) < 3:
            return None
        
        version, status_code, reason = status_parts
        
        # Parse headers
        headers = {}
        body_start = 0
        for i, line in enumerate(lines[1:], 1):
            if line == '':
                body_start = i + 1
                break
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip().lower()] = value.strip()
        
        # Extract body if present
        body = '\r\n'.join(lines[body_start:]) if body_start < len(lines) else ''
        
        # Detect file type from body
        file_type = self._detect_file_type(body.encode('utf-8', errors='ignore')[:50])
        
        return {
            'packet_index': packet_index,
            'type': 'http_response',
            'version': version,
            'status_code': int(status_code) if status_code.isdigit() else 0,
            'reason': reason,
            'headers': headers,
            'body_length': len(body),
            'body_preview': body[:500] if body else '',
            'content_type': headers.get('content-type', ''),
            'content_length': int(headers.get('content-length', 0)) if headers.get('content-length', '').isdigit() else 0,
            'server': headers.get('server', ''),
            'file_type': file_type,
            'src_ip': packet[TCP].sport,
            'dst_ip': packet[TCP].dport,
            'timestamp': float(packet.time)
        }
    
    def _analyze_http_request(self, method: str, path: str, headers: Dict, body: str) -> Dict:
        """Analyze HTTP request for suspicious patterns"""
        analysis = {
            'suspicious_method': method in self.suspicious_methods,
            'suspicious_user_agent': False,
            'potential_attacks': [],
            'risk_score': 0
        }
        
        # Check user agent
        user_agent = headers.get('user-agent', '').lower()
        analysis['suspicious_user_agent'] = any(
            ua in user_agent for ua in self.suspicious_user_agents
        )
        
        # Check for attack patterns in path and body
        combined_content = f"{path} {body}".lower()
        for pattern in self.common_attack_patterns:
            if re.search(pattern, combined_content, re.IGNORECASE):
                analysis['potential_attacks'].append(pattern)
        
        # Calculate risk score
        risk_score = 0
        if analysis['suspicious_method']:
            risk_score += 20
        if analysis['suspicious_user_agent']:
            risk_score += 30
        risk_score += len(analysis['potential_attacks']) * 25
        
        # Check for large POST data (potential exfiltration)
        if method == 'POST' and headers.get('content-length'):
            try:
                content_length = int(headers['content-length'])
                if content_length > 1000000:  # 1MB
                    risk_score += 40
                    analysis['large_upload'] = True
            except ValueError:
                pass
        
        analysis['risk_score'] = min(100, risk_score)
        
        return analysis
    
    def _detect_file_type(self, data: bytes) -> Optional[str]:
        """Detect file type from binary data"""
        for signature, file_type in self.file_types.items():
            if data.startswith(signature):
                return file_type
        return None
    
    def extract_urls(self, http_data: Dict) -> List[str]:
        """Extract URLs from HTTP data"""
        urls = []
        
        if http_data.get('type') == 'http_request':
            host = http_data.get('host', '')
            path = http_data.get('path', '')
            if host and path:
                urls.append(f"http://{host}{path}")
        
        # Extract URLs from referer
        referer = http_data.get('referer', '')
        if referer:
            urls.append(referer)
        
        return urls
    
    def get_session_key(self, http_data: Dict) -> Optional[str]:
        """Generate session key for HTTP conversation tracking"""
        src_ip = http_data.get('src_ip')
        dst_ip = http_data.get('dst_ip')
        host = http_data.get('host', '')
        
        if src_ip and dst_ip:
            return f"{src_ip}:{dst_ip}:{host}"
        
        return None
