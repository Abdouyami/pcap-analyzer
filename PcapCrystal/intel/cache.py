"""
Intelligent caching system for threat intelligence data
"""

import diskcache
import hashlib
import json
from pathlib import Path
from typing import Optional, Dict, Any, Union
from datetime import datetime, timedelta
import pickle

from models.enrichment import EnrichmentResult, IndicatorType

class IntelCache:
    """Disk-based cache for threat intelligence results"""
    
    def __init__(self, cache_dir: str = "./data/cache", max_size_gb: float = 1.0, default_ttl_hours: int = 24):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize diskcache with size limit
        self.cache = diskcache.Cache(
            str(self.cache_dir),
            size_limit=int(max_size_gb * 1024 * 1024 * 1024),  # Convert GB to bytes
            eviction_policy='least-recently-used'
        )
        
        self.default_ttl = timedelta(hours=default_ttl_hours)
        
        # Separate caches for different data types
        self.intel_cache = diskcache.Cache(str(self.cache_dir / "intel"))
        self.geo_cache = diskcache.Cache(str(self.cache_dir / "geo"))
        self.domain_cache = diskcache.Cache(str(self.cache_dir / "domains"))
        
    def _make_key(self, source: str, indicator: str, indicator_type: str) -> str:
        """Create cache key from source, indicator, and type"""
        key_data = f"{source}:{indicator_type}:{indicator}"
        return hashlib.sha256(key_data.encode()).hexdigest()[:32]
    
    def get_intel_result(self, source: str, indicator: str, indicator_type: Union[str, IndicatorType]) -> Optional[Dict[str, Any]]:
        """Retrieve threat intelligence result from cache"""
        if isinstance(indicator_type, IndicatorType):
            indicator_type = indicator_type.value
            
        key = self._make_key(source, indicator, indicator_type)
        
        try:
            cached_data = self.intel_cache.get(key)
            if cached_data:
                # Check if data has expired
                cached_time = datetime.fromisoformat(cached_data.get("cached_at", "1970-01-01"))
                if datetime.now() - cached_time < self.default_ttl:
                    return cached_data.get("data")
                else:
                    # Expired, remove from cache
                    self.intel_cache.delete(key)
            return None
        except Exception as e:
            print(f"Cache read error: {e}")
            return None
    
    def set_intel_result(self, source: str, indicator: str, indicator_type: Union[str, IndicatorType], data: Dict[str, Any]):
        """Store threat intelligence result in cache"""
        if isinstance(indicator_type, IndicatorType):
            indicator_type = indicator_type.value
            
        key = self._make_key(source, indicator, indicator_type)
        
        cache_entry = {
            "data": data,
            "cached_at": datetime.now().isoformat(),
            "source": source,
            "indicator": indicator,
            "indicator_type": indicator_type
        }
        
        try:
            # Set with TTL
            self.intel_cache.set(key, cache_entry, expire=self.default_ttl.total_seconds())
        except Exception as e:
            print(f"Cache write error: {e}")
    
    def get_geo_result(self, ip: str) -> Optional[Dict[str, Any]]:
        """Retrieve geolocation result from cache"""
        key = f"geo:{ip}"
        
        try:
            cached_data = self.geo_cache.get(key)
            if cached_data:
                # Geo data expires after 1 week
                cached_time = datetime.fromisoformat(cached_data.get("cached_at", "1970-01-01"))
                if datetime.now() - cached_time < timedelta(days=7):
                    return cached_data.get("data")
                else:
                    self.geo_cache.delete(key)
            return None
        except Exception as e:
            print(f"Geo cache read error: {e}")
            return None
    
    def set_geo_result(self, ip: str, data: Dict[str, Any]):
        """Store geolocation result in cache"""
        key = f"geo:{ip}"
        
        cache_entry = {
            "data": data,
            "cached_at": datetime.now().isoformat(),
            "ip": ip
        }
        
        try:
            # Geo data cached for 1 week
            self.geo_cache.set(key, cache_entry, expire=timedelta(days=7).total_seconds())
        except Exception as e:
            print(f"Geo cache write error: {e}")
    
    def get_domain_analysis(self, domain: str) -> Optional[Dict[str, Any]]:
        """Retrieve domain analysis from cache"""
        key = f"domain:{domain}"
        return self.domain_cache.get(key)
    
    def set_domain_analysis(self, domain: str, analysis: Dict[str, Any]):
        """Store domain analysis in cache"""
        key = f"domain:{domain}"
        
        cache_entry = {
            "analysis": analysis,
            "cached_at": datetime.now().isoformat()
        }
        
        try:
            # Domain analysis cached for 6 hours
            self.domain_cache.set(key, cache_entry, expire=timedelta(hours=6).total_seconds())
        except Exception as e:
            print(f"Domain cache write error: {e}")
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        try:
            return {
                "intel_cache": {
                    "size": len(self.intel_cache),
                    "volume": self.intel_cache.volume()
                },
                "geo_cache": {
                    "size": len(self.geo_cache), 
                    "volume": self.geo_cache.volume()
                },
                "domain_cache": {
                    "size": len(self.domain_cache),
                    "volume": self.domain_cache.volume()
                },
                "total_volume_mb": (self.cache.volume() + self.intel_cache.volume() + 
                                   self.geo_cache.volume() + self.domain_cache.volume()) / 1024 / 1024
            }
        except Exception as e:
            print(f"Error getting cache stats: {e}")
            return {}
    
    def clear_expired(self):
        """Clear expired entries from all caches"""
        try:
            self.intel_cache.expire()
            self.geo_cache.expire() 
            self.domain_cache.expire()
            self.cache.expire()
        except Exception as e:
            print(f"Error clearing expired cache entries: {e}")
    
    def clear_all(self):
        """Clear all cache data"""
        try:
            self.intel_cache.clear()
            self.geo_cache.clear()
            self.domain_cache.clear()
            self.cache.clear()
        except Exception as e:
            print(f"Error clearing all cache data: {e}")
    
    def __del__(self):
        """Clean up cache connections"""
        try:
            if hasattr(self, 'intel_cache'):
                self.intel_cache.close()
            if hasattr(self, 'geo_cache'):
                self.geo_cache.close()
            if hasattr(self, 'domain_cache'):
                self.domain_cache.close()
            if hasattr(self, 'cache'):
                self.cache.close()
        except:
            pass
