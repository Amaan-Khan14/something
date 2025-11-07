"""
Pydantic schemas for API request/response models
"""
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime


class URLAnalysisRequest(BaseModel):
    """Request model for single URL analysis"""
    url: str = Field(..., description="URL to analyze")
    method: Optional[str] = Field("GET", description="HTTP method")
    source_ip: Optional[str] = Field(None, description="Source IP address")
    dest_ip: Optional[str] = Field(None, description="Destination IP address")
    dest_port: Optional[int] = Field(80, description="Destination port")
    user_agent: Optional[str] = Field(None, description="User agent string")
    store_result: bool = Field(True, description="Store result in database")


class BatchURLAnalysisRequest(BaseModel):
    """Request model for batch URL analysis"""
    urls: List[Dict[str, Any]] = Field(..., description="List of URLs with metadata")


class DetectionResponse(BaseModel):
    """Response model for attack detection"""
    is_attack: bool
    attack_type: Optional[str] = None
    attack_subtype: Optional[str] = None
    confidence_score: float
    severity: str
    detection_method: str
    matched_patterns: List[str] = []
    id: Optional[int] = None

    class Config:
        from_attributes = True


class AttackDetail(BaseModel):
    """Detailed attack information"""
    id: int
    timestamp: Optional[datetime]
    source_ip: str
    dest_ip: str
    dest_port: Optional[int]
    url: str
    method: Optional[str]
    attack_type: str
    attack_subtype: Optional[str]
    success_status: bool
    severity: str
    confidence_score: float
    raw_request: Optional[str]
    detection_method: str
    user_agent: Optional[str]
    referer: Optional[str]

    class Config:
        from_attributes = True


class AttackListResponse(BaseModel):
    """Response model for attack list"""
    total: int
    skip: int
    limit: int
    attacks: List[Dict[str, Any]]
