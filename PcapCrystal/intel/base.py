"""
Base classes for threat intelligence providers
"""

from abc import ABC, abstractmethod
from typing import Optional, List, Dict, Any
import asyncio
from models.enrichment import EnrichmentResult, IndicatorType

class ThreatIntelProvider(ABC):
    """Abstract base class for threat intelligence providers"""
    
    def __init__(self, name: str, api_key: Optional[str] = None, rate_limit: int = 60):
        self.name = name
        self.api_key = api_key
        self.rate_limit = rate_limit
        self.enabled = bool(api_key)
        self._semaphore = asyncio.Semaphore(rate_limit)
    
    @abstractmethod
    async def enrich_ip(self, ip: str) -> Optional[Dict[str, Any]]:
        """Enrich IP address with threat intelligence"""
        pass
    
    @abstractmethod
    async def enrich_domain(self, domain: str) -> Optional[Dict[str, Any]]:
        """Enrich domain with threat intelligence"""
        pass
    
    @abstractmethod
    async def enrich_hash(self, file_hash: str) -> Optional[Dict[str, Any]]:
        """Enrich file hash with threat intelligence"""
        pass
    
    def is_enabled(self) -> bool:
        """Check if provider is enabled (has API key)"""
        return self.enabled
    
    async def rate_limited_request(self, coro):
        """Execute request with rate limiting"""
        async with self._semaphore:
            return await coro
    
    def normalize_reputation(self, raw_score: int, max_score: int = 100) -> int:
        """Normalize reputation score to 0-100 scale"""
        if raw_score is None or max_score <= 0:
            return 0
        return min(100, max(0, int((raw_score / max_score) * 100)))

class GeolocationProvider(ABC):
    """Abstract base class for geolocation providers"""
    
    def __init__(self, name: str):
        self.name = name
        self.enabled = True
    
    @abstractmethod
    async def get_location(self, ip: str) -> Optional[Dict[str, Any]]:
        """Get geographic location for IP address"""
        pass
    
    @abstractmethod
    def is_available(self) -> bool:
        """Check if provider is available"""
        pass
