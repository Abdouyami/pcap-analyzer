"""
Pydantic models for threat intelligence enrichment
"""

from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum

class IndicatorType(str, Enum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    SHA256 = "sha256"
    MD5 = "md5"

class ThreatIntelSource(BaseModel):
    """Individual threat intelligence source result"""
    source: str = Field(..., description="Name of the intelligence source")
    reputation: int = Field(..., ge=0, le=100, description="Reputation score 0-100")
    detections: int = Field(default=0, description="Number of detections")
    last_analysis: Optional[datetime] = Field(default=None, description="Last analysis timestamp")
    labels: List[str] = Field(default_factory=list, description="Threat labels/tags")
    raw_response: Dict[str, Any] = Field(default_factory=dict, description="Raw API response")

class GeoLocation(BaseModel):
    """Geographic location information"""
    country: Optional[str] = None
    country_code: Optional[str] = None
    region: Optional[str] = None
    city: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    asn: Optional[int] = None
    org: Optional[str] = None
    is_malicious: bool = False
    risk_score: int = Field(default=0, ge=0, le=100)

class EnrichmentResult(BaseModel):
    """Complete enrichment result for an indicator"""
    indicator: str = Field(..., description="The indicator value")
    indicator_type: IndicatorType = Field(..., description="Type of indicator")
    sources: Dict[str, ThreatIntelSource] = Field(default_factory=dict, description="Results from each source")
    geo_location: Optional[GeoLocation] = Field(default=None, description="Geographic information")
    overall_reputation: int = Field(default=0, ge=0, le=100, description="Combined reputation score")
    enriched_at: datetime = Field(default_factory=datetime.now, description="Enrichment timestamp")
    is_malicious: bool = Field(default=False, description="Overall maliciousness assessment")
    confidence: int = Field(default=0, ge=0, le=100, description="Confidence in assessment")
    
    def get_reputation_summary(self) -> str:
        """Get human-readable reputation summary"""
        if self.overall_reputation >= 70:
            return "High Risk"
        elif self.overall_reputation >= 40:
            return "Medium Risk"
        elif self.overall_reputation >= 20:
            return "Low Risk"
        else:
            return "Clean"
    
    def get_source_count(self) -> int:
        """Get number of sources that provided data"""
        return len([s for s in self.sources.values() if s.reputation > 0])

class DomainAnalysis(BaseModel):
    """Domain-specific analysis results"""
    domain: str
    entropy: float = 0.0
    length: int = 0
    is_dga_like: bool = False
    suspicious_tld: bool = False
    newly_registered: Optional[bool] = None
    registration_date: Optional[datetime] = None
    subdomains_count: int = 0
    dns_record_types: List[str] = Field(default_factory=list)

class FileCarving(BaseModel):
    """Carved file metadata"""
    filename: str
    mime_type: str
    size: int
    sha256: str
    md5: str
    first_seen: datetime
    last_seen: datetime
    source_conversation: str
    yara_matches: List[str] = Field(default_factory=list)
    enrichment: Optional[EnrichmentResult] = None
