"""
Utility helper functions for data formatting and processing
"""

import math
import re
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Union
from urllib.parse import urlparse

def format_bytes(bytes_value: Union[int, float]) -> str:
    """Format bytes value into human-readable string"""
    if bytes_value == 0:
        return "0 B"
    
    size_names = ["B", "KB", "MB", "GB", "TB", "PB"]
    i = int(math.floor(math.log(bytes_value, 1024)))
    i = min(i, len(size_names) - 1)  # Prevent index out of range
    
    p = math.pow(1024, i)
    s = round(bytes_value / p, 2)
    
    return f"{s:g} {size_names[i]}"

def format_duration(seconds: Union[int, float]) -> str:
    """Format duration in seconds to human-readable string"""
    if seconds < 0:
        return "0s"
    
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        minutes = seconds / 60
        return f"{minutes:.1f}m"
    elif seconds < 86400:
        hours = seconds / 3600
        return f"{hours:.1f}h"
    else:
        days = seconds / 86400
        return f"{days:.1f}d"

def format_timestamp(timestamp: Union[int, float, datetime], format_str: str = "%Y-%m-%d %H:%M:%S") -> str:
    """Format timestamp to human-readable string"""
    try:
        if isinstance(timestamp, datetime):
            return timestamp.strftime(format_str)
        elif isinstance(timestamp, (int, float)):
            return datetime.fromtimestamp(timestamp).strftime(format_str)
        else:
            return str(timestamp)
    except (ValueError, OSError):
        return "Invalid timestamp"

def get_severity_color(severity: str) -> str:
    """Get color code for severity level"""
    color_map = {
        'low': '#28a745',      # Green
        'medium': '#ffc107',   # Yellow
        'high': '#fd7e14',     # Orange
        'critical': '#dc3545', # Red
        'info': '#17a2b8',     # Blue
        'warning': '#ffc107'   # Yellow
    }
    return color_map.get(severity.lower(), '#6c757d')  # Default gray

def calculate_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string"""
    if not data:
        return 0.0
    
    # Count character frequencies
    from collections import Counter
    char_counts = Counter(data.lower())
    
    # Calculate probabilities
    length = len(data)
    probabilities = [count / length for count in char_counts.values()]
    
    # Calculate Shannon entropy
    entropy = 0.0
    for p in probabilities:
        if p > 0:
            entropy -= p * math.log2(p)
    
    return entropy

def is_private_ip(ip: str) -> bool:
    """Check if IP address is in private range"""
    try:
        octets = [int(x) for x in ip.split('.')]
        
        # Private IP ranges (RFC 1918)
        if (octets[0] == 10 or
            (octets[0] == 172 and 16 <= octets[1] <= 31) or
            (octets[0] == 192 and octets[1] == 168)):
            return True
        
        # Loopback
        if octets[0] == 127:
            return True
        
        # Link-local
        if octets[0] == 169 and octets[1] == 254:
            return True
        
        return False
        
    except (ValueError, IndexError):
        return False

def is_public_ip(ip: str) -> bool:
    """Check if IP address is public"""
    return not is_private_ip(ip)

def extract_domain_from_url(url: str) -> Optional[str]:
    """Extract domain from URL"""
    try:
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        
        # Remove port if present
        if ':' in domain:
            domain = domain.split(':')[0]
        
        return domain if domain else None
        
    except Exception:
        return None

def safe_dict_get(dictionary: Dict, keys: Union[str, List[str]], default: Any = None) -> Any:
    """Safely get value from nested dictionary using dot notation or key list"""
    if isinstance(keys, str):
        keys = keys.split('.')
    
    current = dictionary
    
    try:
        for key in keys:
            if isinstance(current, dict) and key in current:
                current = current[key]
            else:
                return default
        return current
    except (KeyError, TypeError):
        return default

def truncate_string(text: str, max_length: int = 50, suffix: str = "...") -> str:
    """Truncate string if longer than max_length"""
    if len(text) <= max_length:
        return text
    return text[:max_length - len(suffix)] + suffix

def normalize_port(port: Union[int, str]) -> Optional[int]:
    """Normalize port number to integer"""
    try:
        port_num = int(port)
        if 0 <= port_num <= 65535:
            return port_num
        return None
    except (ValueError, TypeError):
        return None

def classify_port(port: int) -> str:
    """Classify port into service category"""
    if port in [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995]:
        return "Standard Service"
    elif port in [135, 139, 445, 1433, 3306, 3389, 5432]:
        return "Administrative"
    elif port < 1024:
        return "Well-Known"
    elif port < 49152:
        return "Registered"
    else:
        return "Dynamic/Private"

def get_protocol_description(protocol: str) -> str:
    """Get human-readable description for protocol"""
    descriptions = {
        'TCP': 'Transmission Control Protocol',
        'UDP': 'User Datagram Protocol',
        'ICMP': 'Internet Control Message Protocol',
        'ARP': 'Address Resolution Protocol',
        'HTTP': 'Hypertext Transfer Protocol',
        'HTTPS': 'HTTP Secure',
        'DNS': 'Domain Name System',
        'SMTP': 'Simple Mail Transfer Protocol',
        'POP3': 'Post Office Protocol v3',
        'IMAP': 'Internet Message Access Protocol',
        'FTP': 'File Transfer Protocol',
        'SSH': 'Secure Shell',
        'TELNET': 'Telnet Protocol',
        'SNMP': 'Simple Network Management Protocol',
        'DHCP': 'Dynamic Host Configuration Protocol',
        'ISAKMP': 'Internet Security Association and Key Management Protocol',
        'TLS': 'Transport Layer Security'
    }
    return descriptions.get(protocol.upper(), protocol)

def validate_ip_address(ip: str) -> bool:
    """Validate IP address format"""
    try:
        octets = ip.split('.')
        if len(octets) != 4:
            return False
        
        for octet in octets:
            num = int(octet)
            if not 0 <= num <= 255:
                return False
        
        return True
    except (ValueError, AttributeError):
        return False

def calculate_network_metrics(packets_df) -> Dict[str, Any]:
    """Calculate various network performance metrics"""
    if packets_df.empty:
        return {}
    
    metrics = {}
    
    # Basic metrics
    metrics['total_packets'] = len(packets_df)
    metrics['total_bytes'] = packets_df['length'].sum()
    metrics['avg_packet_size'] = packets_df['length'].mean()
    metrics['max_packet_size'] = packets_df['length'].max()
    metrics['min_packet_size'] = packets_df['length'].min()
    
    # Time-based metrics
    if 'timestamp' in packets_df.columns:
        duration = packets_df['timestamp'].max() - packets_df['timestamp'].min()
        metrics['duration_seconds'] = duration
        metrics['packets_per_second'] = len(packets_df) / max(duration, 1)
        metrics['bytes_per_second'] = metrics['total_bytes'] / max(duration, 1)
    
    # Protocol distribution
    if 'protocol' in packets_df.columns:
        metrics['protocol_distribution'] = packets_df['protocol'].value_counts().to_dict()
    
    return metrics

def generate_summary_stats(data: List[Union[int, float]]) -> Dict[str, float]:
    """Generate summary statistics for numerical data"""
    if not data:
        return {}
    
    import statistics
    
    try:
        stats = {
            'count': len(data),
            'mean': statistics.mean(data),
            'median': statistics.median(data),
            'min': min(data),
            'max': max(data),
            'std_dev': statistics.stdev(data) if len(data) > 1 else 0,
        }
        
        # Calculate percentiles
        sorted_data = sorted(data)
        n = len(sorted_data)
        
        stats['q1'] = sorted_data[int(n * 0.25)] if n > 0 else 0
        stats['q3'] = sorted_data[int(n * 0.75)] if n > 0 else 0
        stats['p95'] = sorted_data[int(n * 0.95)] if n > 0 else 0
        stats['p99'] = sorted_data[int(n * 0.99)] if n > 0 else 0
        
        return stats
        
    except statistics.StatisticsError:
        return {'count': len(data), 'error': 'Insufficient data for statistics'}

def format_percentage(value: float, precision: int = 1) -> str:
    """Format value as percentage"""
    return f"{value:.{precision}f}%"

def create_time_buckets(timestamps: List[Union[int, float]], bucket_size_minutes: int = 5) -> Dict[str, int]:
    """Create time buckets for temporal analysis"""
    if not timestamps:
        return {}
    
    from datetime import datetime
    
    buckets = {}
    bucket_size_seconds = bucket_size_minutes * 60
    
    min_time = min(timestamps)
    
    for timestamp in timestamps:
        # Calculate bucket
        bucket_offset = int((timestamp - min_time) // bucket_size_seconds)
        bucket_start = min_time + (bucket_offset * bucket_size_seconds)
        bucket_label = datetime.fromtimestamp(bucket_start).strftime('%H:%M')
        
        buckets[bucket_label] = buckets.get(bucket_label, 0) + 1
    
    return buckets

def detect_patterns_in_timestamps(timestamps: List[Union[int, float]], threshold: float = 0.3) -> Dict[str, Any]:
    """Detect periodic patterns in timestamps"""
    if len(timestamps) < 3:
        return {'pattern_detected': False, 'reason': 'Insufficient data'}
    
    # Calculate intervals
    sorted_timestamps = sorted(timestamps)
    intervals = []
    
    for i in range(1, len(sorted_timestamps)):
        interval = sorted_timestamps[i] - sorted_timestamps[i-1]
        intervals.append(interval)
    
    if not intervals:
        return {'pattern_detected': False, 'reason': 'No intervals calculated'}
    
    # Calculate coefficient of variation
    mean_interval = sum(intervals) / len(intervals)
    
    if mean_interval == 0:
        return {'pattern_detected': False, 'reason': 'Zero mean interval'}
    
    variance = sum((x - mean_interval) ** 2 for x in intervals) / len(intervals)
    std_dev = math.sqrt(variance)
    cv = std_dev / mean_interval
    
    # Low coefficient of variation suggests regular pattern
    pattern_detected = cv < threshold
    
    return {
        'pattern_detected': pattern_detected,
        'coefficient_of_variation': cv,
        'mean_interval_seconds': mean_interval,
        'std_deviation': std_dev,
        'threshold_used': threshold,
        'intervals_analyzed': len(intervals)
    }

def clean_string_for_analysis(text: str) -> str:
    """Clean string for analysis by removing special characters"""
    if not text:
        return ""
    
    # Remove non-alphanumeric characters except dots and hyphens
    cleaned = re.sub(r'[^a-zA-Z0-9.-]', '', text.lower())
    return cleaned

def extract_file_extension(filename: str) -> Optional[str]:
    """Extract file extension from filename"""
    if not filename or '.' not in filename:
        return None
    
    return filename.split('.')[-1].lower()

def is_suspicious_file_extension(extension: str) -> bool:
    """Check if file extension is suspicious"""
    suspicious_extensions = {
        'exe', 'bat', 'cmd', 'com', 'pif', 'scr', 'vbs', 'js',
        'jar', 'dll', 'msi', 'reg', 'ps1', 'sh', 'php', 'asp'
    }
    
    return extension.lower() in suspicious_extensions

