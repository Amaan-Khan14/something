from sqlalchemy import Column, Integer, String, Float, DateTime
from sqlalchemy.sql import func
from .database import Base


class IPMetadata(Base):
    """Model for storing IP geolocation and threat intelligence"""
    __tablename__ = "ip_metadata"

    id = Column(Integer, primary_key=True, index=True)
    ip = Column(String(45), unique=True, index=True)
    country = Column(String(100))
    country_code = Column(String(2))
    city = Column(String(100))
    latitude = Column(Float)
    longitude = Column(Float)
    isp = Column(String(200))
    organization = Column(String(200))
    threat_score = Column(Float, default=0.0)  # 0-100
    is_proxy = Column(Integer, default=0)
    is_vpn = Column(Integer, default=0)
    is_tor = Column(Integer, default=0)
    total_attacks = Column(Integer, default=0)
    last_seen = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    first_seen = Column(DateTime(timezone=True), server_default=func.now())

    def to_dict(self):
        """Convert model to dictionary"""
        return {
            "id": self.id,
            "ip": self.ip,
            "country": self.country,
            "country_code": self.country_code,
            "city": self.city,
            "latitude": self.latitude,
            "longitude": self.longitude,
            "isp": self.isp,
            "organization": self.organization,
            "threat_score": self.threat_score,
            "is_proxy": bool(self.is_proxy),
            "is_vpn": bool(self.is_vpn),
            "is_tor": bool(self.is_tor),
            "total_attacks": self.total_attacks,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
        }
