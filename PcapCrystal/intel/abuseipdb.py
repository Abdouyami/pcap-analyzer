"""
AbuseIPDB threat intelligence provider
"""

import httpx
import asyncio
from typing import Optional, Dict, Any
from datetime import datetime
from tenacity import retry, stop_after_attempt, wait_exponential

from .base import ThreatIntelProvider
from models.enrichment import ThreatIntelSource

class AbuseIPDBProvider(ThreatIntelProvider):
    """AbuseIPDB API integration for IP reputation"""
    
    def __init__(self, api_key: Optional[str] = None):
        super().__init__("AbuseIPDB", api_key, rate_limit=60)  # Free tier: 1000/day
        self.base_url = "https://api.abuseipdb.com/api/v2"
        self.headers = {
            "Key": api_key,
            "Accept": "application/json",
            "User-Agent": "Enhanced-PCAP-Analyzer/1.0"
        } if api_key else {}
    
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=10)
    )
    async def _make_request(self, endpoint: str, params: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Make rate-limited API request to AbuseIPDB"""
        if not self.is_enabled():
            return None
        
        url = f"{self.base_url}/{endpoint}"
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            try:
                async with self._semaphore:
                    response = await client.get(url, headers=self.headers, params=params)
                    
                    if response.status_code == 200:
                        return response.json()
                    elif response.status_code == 429:
                        # Rate limited
                        await asyncio.sleep(60)
                        raise httpx.RequestError("Rate limited")
                    elif response.status_code == 422:
                        # Invalid IP or not found
                        return {"data": {"abuseConfidencePercentage": 0}}
                    else:
                        response.raise_for_status()
                        
            except Exception as e:
                print(f"AbuseIPDB API error for {endpoint}: {e}")
                return None
    
    async def enrich_ip(self, ip: str) -> Optional[Dict[str, Any]]:
        """Enrich IP address with AbuseIPDB data"""
        params = {
            "ipAddress": ip,
            "maxAgeInDays": 90,
            "verbose": ""
        }
        
        result = await self._make_request("check", params)
        if not result:
            return None
        
        try:
            data = result.get("data", {})
            abuse_score = data.get("abuseConfidencePercentage", 0)
            
            # Convert abuse score to reputation (inverted)
            reputation = max(0, 100 - abuse_score)
            
            # Parse last reported date
            last_reported = None
            if data.get("lastReportedAt"):
                try:
                    last_reported = datetime.fromisoformat(
                        data["lastReportedAt"].replace("Z", "+00:00")
                    )
                except (ValueError, AttributeError):
                    pass
            
            return {
                "reputation": reputation,
                "detections": data.get("totalReports", 0),
                "last_analysis": last_reported,
                "labels": self._parse_usage_types(data.get("usageType", "")),
                "abuse_score": abuse_score,
                "country": data.get("countryCode"),
                "is_whitelisted": data.get("isWhitelisted", False),
                "isp": data.get("isp"),
                "domain": data.get("domain"),
                "raw_response": result
            }
            
        except Exception as e:
            print(f"Error parsing AbuseIPDB response: {e}")
            return None
    
    async def enrich_domain(self, domain: str) -> Optional[Dict[str, Any]]:
        """AbuseIPDB doesn't support domain lookups directly"""
        return None
    
    async def enrich_hash(self, file_hash: str) -> Optional[Dict[str, Any]]:
        """AbuseIPDB doesn't support hash lookups"""
        return None
    
    def _parse_usage_types(self, usage_type: str) -> list:
        """Parse usage type string into labels"""
        if not usage_type:
            return []
        
        # Common AbuseIPDB usage types
        usage_map = {
            "Commercial": ["hosting"],
            "Organization": ["corporate"],
            "Government": ["government"],
            "Military": ["military"],
            "University": ["education"],
            "Library": ["education"],
            "CDN": ["cdn"],
            "ISP": ["isp"],
            "Hosting": ["hosting"],
            "Reserved": ["reserved"]
        }
        
        return usage_map.get(usage_type, [usage_type.lower()])
    
    def create_source_result(self, data: Dict[str, Any]) -> ThreatIntelSource:
        """Create ThreatIntelSource from AbuseIPDB response"""
        return ThreatIntelSource(
            source=self.name,
            reputation=data.get("reputation", 0),
            detections=data.get("detections", 0),
            last_analysis=data.get("last_analysis"),
            labels=data.get("labels", []),
            raw_response=data.get("raw_response", {})
        )
