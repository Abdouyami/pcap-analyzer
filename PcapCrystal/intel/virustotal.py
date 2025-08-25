"""
VirusTotal threat intelligence provider
"""

import httpx
import asyncio
from typing import Optional, Dict, Any
from datetime import datetime
from tenacity import retry, stop_after_attempt, wait_exponential

from .base import ThreatIntelProvider
from models.enrichment import ThreatIntelSource

class VirusTotalProvider(ThreatIntelProvider):
    """VirusTotal API integration for threat intelligence"""
    
    def __init__(self, api_key: Optional[str] = None):
        super().__init__("VirusTotal", api_key, rate_limit=4)  # Free tier: 4 requests/minute
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = {
            "x-apikey": api_key,
            "User-Agent": "Enhanced-PCAP-Analyzer/1.0"
        } if api_key else {}
    
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=10)
    )
    async def _make_request(self, endpoint: str) -> Optional[Dict[str, Any]]:
        """Make rate-limited API request to VirusTotal"""
        if not self.is_enabled():
            return None
        
        url = f"{self.base_url}/{endpoint}"
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            try:
                async with self._semaphore:
                    response = await client.get(url, headers=self.headers)
                    
                    if response.status_code == 200:
                        return response.json()
                    elif response.status_code == 429:
                        # Rate limited - wait and retry
                        await asyncio.sleep(60)
                        raise httpx.RequestError("Rate limited")
                    elif response.status_code == 404:
                        # Not found - return empty result
                        return {"data": {"attributes": {"last_analysis_stats": {}}}}
                    else:
                        response.raise_for_status()
                        
            except Exception as e:
                print(f"VirusTotal API error for {endpoint}: {e}")
                return None
    
    async def enrich_ip(self, ip: str) -> Optional[Dict[str, Any]]:
        """Enrich IP address with VirusTotal data"""
        result = await self._make_request(f"ip_addresses/{ip}")
        if not result:
            return None
        
        try:
            attributes = result.get("data", {}).get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})
            
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total_engines = sum(stats.values()) if stats else 1
            
            # Calculate reputation (inverted - higher malicious = lower reputation)
            reputation = max(0, 100 - int((malicious + suspicious * 0.5) * 100 / total_engines))
            
            return {
                "reputation": reputation,
                "detections": malicious + suspicious,
                "last_analysis": attributes.get("last_analysis_date"),
                "labels": attributes.get("tags", []),
                "country": attributes.get("country"),
                "asn": attributes.get("asn"),
                "as_owner": attributes.get("as_owner"),
                "raw_response": result
            }
            
        except Exception as e:
            print(f"Error parsing VirusTotal IP response: {e}")
            return None
    
    async def enrich_domain(self, domain: str) -> Optional[Dict[str, Any]]:
        """Enrich domain with VirusTotal data"""
        result = await self._make_request(f"domains/{domain}")
        if not result:
            return None
        
        try:
            attributes = result.get("data", {}).get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})
            
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total_engines = sum(stats.values()) if stats else 1
            
            # Calculate reputation
            reputation = max(0, 100 - int((malicious + suspicious * 0.5) * 100 / total_engines))
            
            return {
                "reputation": reputation,
                "detections": malicious + suspicious,
                "last_analysis": attributes.get("last_analysis_date"),
                "labels": attributes.get("tags", []),
                "categories": attributes.get("categories", {}),
                "creation_date": attributes.get("creation_date"),
                "raw_response": result
            }
            
        except Exception as e:
            print(f"Error parsing VirusTotal domain response: {e}")
            return None
    
    async def enrich_hash(self, file_hash: str) -> Optional[Dict[str, Any]]:
        """Enrich file hash with VirusTotal data"""
        result = await self._make_request(f"files/{file_hash}")
        if not result:
            return None
        
        try:
            attributes = result.get("data", {}).get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})
            
            malicious = stats.get("malicious", 0)
            total_engines = sum(stats.values()) if stats else 1
            
            # For files, be more strict - any detection is concerning
            reputation = max(0, 100 - int(malicious * 100 / total_engines))
            
            return {
                "reputation": reputation,
                "detections": malicious,
                "last_analysis": attributes.get("last_analysis_date"),
                "labels": attributes.get("tags", []),
                "file_type": attributes.get("type_description"),
                "size": attributes.get("size"),
                "names": attributes.get("names", []),
                "raw_response": result
            }
            
        except Exception as e:
            print(f"Error parsing VirusTotal file response: {e}")
            return None
    
    def create_source_result(self, data: Dict[str, Any]) -> ThreatIntelSource:
        """Create ThreatIntelSource from VirusTotal response"""
        last_analysis = None
        if data.get("last_analysis"):
            try:
                last_analysis = datetime.fromtimestamp(data["last_analysis"])
            except (ValueError, TypeError):
                pass
        
        return ThreatIntelSource(
            source=self.name,
            reputation=data.get("reputation", 0),
            detections=data.get("detections", 0),
            last_analysis=last_analysis,
            labels=data.get("labels", []),
            raw_response=data.get("raw_response", {})
        )
