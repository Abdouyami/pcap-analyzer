"""
Geolocation intelligence provider using MaxMind GeoLite2
"""

import geoip2.database
import geoip2.errors
from pathlib import Path
from typing import Optional, Dict, Any
import requests
import tarfile
import tempfile
import os

from .base import GeolocationProvider
from models.enrichment import GeoLocation

class MaxMindGeolocationProvider(GeolocationProvider):
    """MaxMind GeoLite2 database provider for IP geolocation"""
    
    def __init__(self, db_path: Optional[str] = None):
        super().__init__("MaxMind GeoLite2")
        self.db_path = db_path or "./data/GeoLite2-City.mmdb"
        self.reader = None
        self._initialize_database()
    
    def _initialize_database(self):
        """Initialize MaxMind database reader"""
        db_path = Path(self.db_path)
        
        if not db_path.exists():
            print(f"MaxMind database not found at {db_path}")
            print("Please download GeoLite2-City.mmdb from MaxMind and place it in ./data/")
            self.enabled = False
            return
        
        try:
            self.reader = geoip2.database.Reader(str(db_path))
            self.enabled = True
        except Exception as e:
            print(f"Error initializing MaxMind database: {e}")
            self.enabled = False
    
    async def get_location(self, ip: str) -> Optional[Dict[str, Any]]:
        """Get geographic location for IP address"""
        if not self.is_available():
            return None
        
        try:
            response = self.reader.city(ip)
            
            # Determine risk based on geographic factors
            risk_score = self._calculate_geo_risk(
                response.country.iso_code,
                response.traits.autonomous_system_number,
                response.traits.autonomous_system_organization
            )
            
            return {
                "country": response.country.name,
                "country_code": response.country.iso_code,
                "region": response.subdivisions.most_specific.name,
                "city": response.city.name,
                "latitude": float(response.location.latitude) if response.location.latitude else None,
                "longitude": float(response.location.longitude) if response.location.longitude else None,
                "asn": response.traits.autonomous_system_number,
                "org": response.traits.autonomous_system_organization,
                "is_malicious": risk_score > 50,
                "risk_score": risk_score,
                "accuracy_radius": response.location.accuracy_radius,
                "time_zone": str(response.location.time_zone) if response.location.time_zone else None
            }
            
        except geoip2.errors.AddressNotFoundError:
            # IP not in database (likely private/reserved)
            return self._handle_private_ip(ip)
        except Exception as e:
            print(f"Error looking up IP {ip}: {e}")
            return None
    
    def _handle_private_ip(self, ip: str) -> Dict[str, Any]:
        """Handle private/reserved IP addresses"""
        if ip.startswith(("192.168.", "10.", "172.")):
            return {
                "country": "Private Network",
                "country_code": "XX",
                "region": "RFC1918",
                "city": "Private",
                "latitude": None,
                "longitude": None,
                "asn": None,
                "org": "Private Network",
                "is_malicious": False,
                "risk_score": 0
            }
        elif ip.startswith("127."):
            return {
                "country": "Localhost",
                "country_code": "XX", 
                "region": "Loopback",
                "city": "Localhost",
                "latitude": None,
                "longitude": None,
                "asn": None,
                "org": "Loopback",
                "is_malicious": False,
                "risk_score": 0
            }
        else:
            return {
                "country": "Unknown",
                "country_code": "XX",
                "region": "Unknown",
                "city": "Unknown", 
                "latitude": None,
                "longitude": None,
                "asn": None,
                "org": "Unknown",
                "is_malicious": False,
                "risk_score": 10  # Slight risk for unknown IPs
            }
    
    def _calculate_geo_risk(self, country_code: str, asn: int, org: str) -> int:
        """Calculate geographic risk score based on country, ASN, and organization"""
        risk_score = 0
        
        # High-risk countries (based on common threat landscape)
        high_risk_countries = {"CN", "RU", "KP", "IR", "PK", "BD", "VN"}
        medium_risk_countries = {"UA", "BY", "KZ", "UZ", "TR", "EG", "BR", "IN"}
        
        if country_code in high_risk_countries:
            risk_score += 40
        elif country_code in medium_risk_countries:
            risk_score += 20
        
        # Suspicious ASNs (common bulletproof hosting)
        suspicious_asns = {13335, 16509, 14061, 197695, 29073, 39572}
        if asn and asn in suspicious_asns:
            risk_score += 30
        
        # Suspicious organizations (keywords)
        if org:
            org_lower = org.lower()
            suspicious_keywords = ["vpn", "proxy", "tor", "bulletproof", "offshore", "anonymous"]
            for keyword in suspicious_keywords:
                if keyword in org_lower:
                    risk_score += 25
                    break
        
        return min(100, risk_score)
    
    def is_available(self) -> bool:
        """Check if MaxMind database is available"""
        return self.enabled and self.reader is not None
    
    def create_geo_location(self, data: Dict[str, Any]) -> GeoLocation:
        """Create GeoLocation model from lookup data"""
        return GeoLocation(**data)
    
    def __del__(self):
        """Clean up database reader"""
        if self.reader:
            self.reader.close()
