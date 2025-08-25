"""
Pydantic models for security detections and MITRE ATT&CK mapping
"""

from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum

class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class MitreAttack(BaseModel):
    """MITRE ATT&CK technique information"""
    tactic: str = Field(..., description="MITRE ATT&CK tactic (e.g., TA0007)")
    technique: str = Field(..., description="MITRE ATT&CK technique (e.g., T1046)")
    subtechnique: Optional[str] = Field(default=None, description="MITRE ATT&CK sub-technique")
    name: str = Field(..., description="Technique name")
    description: str = Field(..., description="Technique description")
    url: str = Field(..., description="MITRE ATT&CK documentation URL")

class Detection(BaseModel):
    """Security detection/alert"""
    id: str = Field(..., description="Unique detection ID")
    name: str = Field(..., description="Detection rule name")
    description: str = Field(..., description="Detailed description")
    severity: Severity = Field(..., description="Severity level")
    confidence: int = Field(..., ge=0, le=100, description="Detection confidence")
    mitre_attack: Optional[MitreAttack] = Field(default=None, description="MITRE ATT&CK mapping")
    
    # Context information
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    protocol: Optional[str] = None
    port: Optional[int] = None
    
    # Temporal information
    first_seen: datetime = Field(default_factory=datetime.now)
    last_seen: datetime = Field(default_factory=datetime.now)
    occurrence_count: int = Field(default=1)
    
    # Evidence
    evidence: Dict[str, Any] = Field(default_factory=dict, description="Supporting evidence")
    related_packets: List[int] = Field(default_factory=list, description="Related packet indices")
    
    # Scoring
    risk_score: int = Field(default=0, ge=0, le=100, description="Risk score contribution")
    
    def get_mitre_url(self) -> Optional[str]:
        """Get MITRE ATT&CK documentation URL"""
        if self.mitre_attack:
            return self.mitre_attack.url
        return None
    
    def get_severity_color(self) -> str:
        """Get color code for severity"""
        colors = {
            Severity.LOW: "#28a745",
            Severity.MEDIUM: "#ffc107", 
            Severity.HIGH: "#fd7e14",
            Severity.CRITICAL: "#dc3545"
        }
        return colors.get(self.severity, "#6c757d")

class RiskScore(BaseModel):
    """Risk scoring result"""
    entity: str = Field(..., description="Entity being scored (IP, conversation, etc.)")
    entity_type: str = Field(..., description="Type of entity")
    overall_score: int = Field(..., ge=0, le=100, description="Overall risk score")
    contributing_factors: Dict[str, float] = Field(default_factory=dict, description="Factor contributions")
    detections: List[Detection] = Field(default_factory=list, description="Related detections")
    threat_intel: Optional[Dict[str, Any]] = Field(default=None, description="Threat intelligence data")
    calculated_at: datetime = Field(default_factory=datetime.now)
    
    def get_risk_level(self) -> str:
        """Get human-readable risk level"""
        if self.overall_score >= 70:
            return "High Risk"
        elif self.overall_score >= 40:
            return "Medium Risk"
        elif self.overall_score >= 20:
            return "Low Risk"
        else:
            return "Minimal Risk"
    
    def get_top_factors(self, limit: int = 5) -> List[tuple]:
        """Get top contributing factors"""
        return sorted(
            self.contributing_factors.items(),
            key=lambda x: x[1],
            reverse=True
        )[:limit]

class CorrelationRule(BaseModel):
    """Multi-stage attack correlation rule"""
    name: str
    description: str
    stages: List[str]
    time_window_hours: int = 24
    min_confidence: int = 50
    required_techniques: List[str] = Field(default_factory=list)

class Incident(BaseModel):
    """Multi-stage security incident"""
    id: str = Field(..., description="Unique incident ID")
    name: str = Field(..., description="Incident name")
    description: str = Field(..., description="Incident description")
    severity: Severity = Field(..., description="Incident severity")
    confidence: int = Field(..., ge=0, le=100, description="Incident confidence")
    
    # Temporal information
    start_time: datetime = Field(..., description="Incident start time")
    end_time: datetime = Field(..., description="Incident end time")
    duration_minutes: int = Field(default=0, description="Incident duration in minutes")
    
    # Entities involved
    source_ips: List[str] = Field(default_factory=list)
    destination_ips: List[str] = Field(default_factory=list)
    affected_hosts: List[str] = Field(default_factory=list)
    
    # Attack chain
    kill_chain_stages: List[str] = Field(default_factory=list)
    mitre_techniques: List[MitreAttack] = Field(default_factory=list)
    detections: List[Detection] = Field(default_factory=list)
    
    # Scoring and impact
    risk_score: int = Field(default=0, ge=0, le=100)
    impact_assessment: str = Field(default="Unknown")
    
    # Evidence and context
    evidence_summary: str = Field(default="")
    artifacts: List[str] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)
    
    def get_duration_string(self) -> str:
        """Get human-readable duration"""
        if self.duration_minutes < 60:
            return f"{self.duration_minutes} minutes"
        elif self.duration_minutes < 1440:  # 24 hours
            hours = self.duration_minutes // 60
            minutes = self.duration_minutes % 60
            return f"{hours}h {minutes}m"
        else:
            days = self.duration_minutes // 1440
            hours = (self.duration_minutes % 1440) // 60
            return f"{days}d {hours}h"
    
    def get_technique_names(self) -> List[str]:
        """Get list of technique names"""
        return [t.name for t in self.mitre_techniques]
