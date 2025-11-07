"""
FastAPI Backend for URL Attack Detection System
Main application entry point
"""
from fastapi import FastAPI, UploadFile, File, HTTPException, Depends, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, FileResponse
from sqlalchemy.orm import Session
from typing import List, Optional
import logging
import os
from datetime import datetime, timedelta
import tempfile
import csv
import io

from app.models import get_db, Base, engine, Attack, IPMetadata, AttackPattern
from app.services.detection_engine import DetectionEngine
from app.utils.pcap_parser import PCAPParser
from app.api import schemas

# Initialize logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Create database tables
Base.metadata.create_all(bind=engine)

# Initialize FastAPI app
app = FastAPI(
    title="URL Attack Detection API",
    description="Comprehensive cybersecurity API for detecting URL-based attacks",
    version="1.0.0"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify actual origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize detection engine
MODEL_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "models", "attack_detection_model.pkl")
detection_engine = DetectionEngine(ml_model_path=MODEL_PATH if os.path.exists(MODEL_PATH) else None)

logger.info("Detection engine initialized")


@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "service": "URL Attack Detection API",
        "version": "1.0.0",
        "status": "operational"
    }


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "ml_model_loaded": detection_engine.ml_model is not None
    }


@app.post("/api/analyze/url", response_model=schemas.DetectionResponse)
async def analyze_url(request: schemas.URLAnalysisRequest, db: Session = Depends(get_db)):
    """
    Analyze a single URL for attacks.

    Args:
        request: URLAnalysisRequest with url and optional metadata
        db: Database session

    Returns:
        DetectionResponse with attack details
    """
    try:
        # Detect attack
        result = detection_engine.detect(
            url=request.url,
            method=request.method or "GET",
            user_agent=request.user_agent
        )

        # Store in database if attack detected
        if result.is_attack and request.store_result:
            attack = Attack(
                timestamp=datetime.utcnow(),
                source_ip=request.source_ip or "0.0.0.0",
                dest_ip=request.dest_ip or "0.0.0.0",
                dest_port=request.dest_port or 80,
                url=request.url,
                method=request.method or "GET",
                attack_type=result.attack_type,
                attack_subtype=result.attack_subtype,
                success_status=False,  # Default to attempt
                severity=result.severity,
                confidence_score=result.confidence_score,
                detection_method=result.detection_method,
                user_agent=request.user_agent,
                raw_request=request.url[:1000]
            )
            db.add(attack)
            db.commit()
            db.refresh(attack)

            result_dict = result.to_dict()
            result_dict['id'] = attack.id
            return result_dict

        return result.to_dict()

    except Exception as e:
        logger.error(f"Error analyzing URL: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/analyze/batch", response_model=List[schemas.DetectionResponse])
async def analyze_batch(request: schemas.BatchURLAnalysisRequest, db: Session = Depends(get_db)):
    """
    Analyze multiple URLs in batch.

    Args:
        request: BatchURLAnalysisRequest with list of URLs
        db: Database session

    Returns:
        List of DetectionResponse objects
    """
    try:
        results = []

        for url_data in request.urls:
            result = detection_engine.detect(
                url=url_data.get('url'),
                method=url_data.get('method', 'GET'),
                user_agent=url_data.get('user_agent')
            )

            # Store if attack detected
            if result.is_attack:
                attack = Attack(
                    timestamp=datetime.utcnow(),
                    source_ip=url_data.get('source_ip', '0.0.0.0'),
                    dest_ip=url_data.get('dest_ip', '0.0.0.0'),
                    dest_port=url_data.get('dest_port', 80),
                    url=url_data.get('url'),
                    method=url_data.get('method', 'GET'),
                    attack_type=result.attack_type,
                    attack_subtype=result.attack_subtype,
                    success_status=False,
                    severity=result.severity,
                    confidence_score=result.confidence_score,
                    detection_method=result.detection_method,
                    user_agent=url_data.get('user_agent'),
                    raw_request=url_data.get('url')[:1000]
                )
                db.add(attack)

            results.append(result.to_dict())

        db.commit()
        return results

    except Exception as e:
        logger.error(f"Error in batch analysis: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/upload/pcap")
async def upload_pcap(file: UploadFile = File(...), db: Session = Depends(get_db)):
    """
    Upload and analyze PCAP file.

    Args:
        file: PCAP file upload
        db: Database session

    Returns:
        Summary of detected attacks
    """
    try:
        # Save uploaded file temporarily
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp_file:
            content = await file.read()
            tmp_file.write(content)
            tmp_path = tmp_file.name

        # Parse PCAP
        parser = PCAPParser()
        requests = parser.parse_pcap(tmp_path, max_packets=10000)  # Limit for demo

        logger.info(f"Parsed {len(requests)} HTTP requests from PCAP")

        # Analyze each request
        attacks_detected = 0
        for req in requests:
            result = detection_engine.detect(req.url, req.method, req.user_agent)

            if result.is_attack:
                attack = Attack(
                    timestamp=req.timestamp,
                    source_ip=req.source_ip,
                    dest_ip=req.dest_ip,
                    dest_port=req.dest_port,
                    url=req.url,
                    method=req.method,
                    attack_type=result.attack_type,
                    attack_subtype=result.attack_subtype,
                    success_status=False,
                    severity=result.severity,
                    confidence_score=result.confidence_score,
                    detection_method=result.detection_method,
                    user_agent=req.user_agent,
                    referer=req.referer,
                    raw_request=req.raw_request
                )
                db.add(attack)
                attacks_detected += 1

        db.commit()

        # Clean up temp file
        os.unlink(tmp_path)

        return {
            "status": "success",
            "total_requests": len(requests),
            "attacks_detected": attacks_detected,
            "message": f"Processed {len(requests)} requests, detected {attacks_detected} attacks"
        }

    except Exception as e:
        logger.error(f"Error processing PCAP: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/attacks", response_model=schemas.AttackListResponse)
async def get_attacks(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    attack_type: Optional[str] = None,
    severity: Optional[str] = None,
    source_ip: Optional[str] = None,
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
    success_status: Optional[bool] = None,
    db: Session = Depends(get_db)
):
    """
    Get list of detected attacks with filtering.

    Args:
        skip: Number of records to skip
        limit: Maximum number of records to return
        attack_type: Filter by attack type
        severity: Filter by severity
        source_ip: Filter by source IP
        start_date: Filter by start date
        end_date: Filter by end date
        success_status: Filter by success status
        db: Database session

    Returns:
        AttackListResponse with attacks and metadata
    """
    try:
        # Build query
        query = db.query(Attack)

        # Apply filters
        if attack_type:
            query = query.filter(Attack.attack_type == attack_type)

        if severity:
            query = query.filter(Attack.severity == severity)

        if source_ip:
            query = query.filter(Attack.source_ip == source_ip)

        if start_date:
            query = query.filter(Attack.timestamp >= start_date)

        if end_date:
            query = query.filter(Attack.timestamp <= end_date)

        if success_status is not None:
            query = query.filter(Attack.success_status == success_status)

        # Get total count
        total = query.count()

        # Get paginated results
        attacks = query.order_by(Attack.timestamp.desc()).offset(skip).limit(limit).all()

        return {
            "total": total,
            "skip": skip,
            "limit": limit,
            "attacks": [attack.to_dict() for attack in attacks]
        }

    except Exception as e:
        logger.error(f"Error fetching attacks: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/attacks/{attack_id}", response_model=schemas.AttackDetail)
async def get_attack_detail(attack_id: int, db: Session = Depends(get_db)):
    """
    Get detailed information about a specific attack.

    Args:
        attack_id: Attack ID
        db: Database session

    Returns:
        AttackDetail with full information
    """
    attack = db.query(Attack).filter(Attack.id == attack_id).first()

    if not attack:
        raise HTTPException(status_code=404, detail="Attack not found")

    return attack.to_dict()


@app.get("/api/stats/summary")
async def get_stats_summary(db: Session = Depends(get_db)):
    """
    Get summary statistics of attacks.

    Returns:
        Summary statistics
    """
    try:
        total_attacks = db.query(Attack).count()

        # Attack type distribution
        attack_types = db.query(
            Attack.attack_type,
            db.func.count(Attack.id)
        ).group_by(Attack.attack_type).all()

        # Severity distribution
        severities = db.query(
            Attack.severity,
            db.func.count(Attack.id)
        ).group_by(Attack.severity).all()

        # Top attacking IPs
        top_ips = db.query(
            Attack.source_ip,
            db.func.count(Attack.id)
        ).group_by(Attack.source_ip).order_by(
            db.func.count(Attack.id).desc()
        ).limit(10).all()

        # Recent 24h stats
        last_24h = datetime.utcnow() - timedelta(hours=24)
        recent_attacks = db.query(Attack).filter(Attack.timestamp >= last_24h).count()

        return {
            "total_attacks": total_attacks,
            "recent_24h": recent_attacks,
            "attack_types": [{"type": t, "count": c} for t, c in attack_types],
            "severities": [{"severity": s, "count": c} for s, c in severities],
            "top_attacking_ips": [{"ip": ip, "count": c} for ip, c in top_ips]
        }

    except Exception as e:
        logger.error(f"Error fetching stats: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/stats/timeline")
async def get_timeline_stats(
    hours: int = Query(24, ge=1, le=168),
    db: Session = Depends(get_db)
):
    """
    Get attack timeline statistics.

    Args:
        hours: Number of hours to include
        db: Database session

    Returns:
        Timeline data
    """
    try:
        start_time = datetime.utcnow() - timedelta(hours=hours)

        # Query attacks grouped by hour
        attacks = db.query(Attack).filter(Attack.timestamp >= start_time).all()

        # Group by hour
        timeline = {}
        for attack in attacks:
            hour = attack.timestamp.replace(minute=0, second=0, microsecond=0)
            hour_str = hour.isoformat()

            if hour_str not in timeline:
                timeline[hour_str] = {"timestamp": hour_str, "count": 0, "by_type": {}}

            timeline[hour_str]["count"] += 1

            if attack.attack_type not in timeline[hour_str]["by_type"]:
                timeline[hour_str]["by_type"][attack.attack_type] = 0

            timeline[hour_str]["by_type"][attack.attack_type] += 1

        return {
            "period_hours": hours,
            "timeline": list(timeline.values())
        }

    except Exception as e:
        logger.error(f"Error fetching timeline: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/export/csv")
async def export_csv(
    attack_type: Optional[str] = None,
    severity: Optional[str] = None,
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
    db: Session = Depends(get_db)
):
    """
    Export attacks to CSV.

    Args:
        attack_type: Filter by attack type
        severity: Filter by severity
        start_date: Filter by start date
        end_date: Filter by end date
        db: Database session

    Returns:
        CSV file
    """
    try:
        # Build query
        query = db.query(Attack)

        if attack_type:
            query = query.filter(Attack.attack_type == attack_type)

        if severity:
            query = query.filter(Attack.severity == severity)

        if start_date:
            query = query.filter(Attack.timestamp >= start_date)

        if end_date:
            query = query.filter(Attack.timestamp <= end_date)

        attacks = query.all()

        # Create CSV
        output = io.StringIO()
        writer = csv.writer(output)

        # Header
        writer.writerow([
            'ID', 'Timestamp', 'Source IP', 'Dest IP', 'URL', 'Method',
            'Attack Type', 'Subtype', 'Severity', 'Confidence', 'Success Status'
        ])

        # Data
        for attack in attacks:
            writer.writerow([
                attack.id,
                attack.timestamp.isoformat() if attack.timestamp else '',
                attack.source_ip,
                attack.dest_ip,
                attack.url,
                attack.method,
                attack.attack_type,
                attack.attack_subtype,
                attack.severity,
                attack.confidence_score,
                attack.success_status
            ])

        output.seek(0)

        return StreamingResponse(
            iter([output.getvalue()]),
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename=attacks_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv"}
        )

    except Exception as e:
        logger.error(f"Error exporting CSV: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/export/json")
async def export_json(
    attack_type: Optional[str] = None,
    severity: Optional[str] = None,
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
    db: Session = Depends(get_db)
):
    """
    Export attacks to JSON.

    Args:
        attack_type: Filter by attack type
        severity: Filter by severity
        start_date: Filter by start date
        end_date: Filter by end date
        db: Database session

    Returns:
        JSON file
    """
    try:
        # Build query
        query = db.query(Attack)

        if attack_type:
            query = query.filter(Attack.attack_type == attack_type)

        if severity:
            query = query.filter(Attack.severity == severity)

        if start_date:
            query = query.filter(Attack.timestamp >= start_date)

        if end_date:
            query = query.filter(Attack.timestamp <= end_date)

        attacks = query.all()

        # Convert to dict
        data = {
            "export_date": datetime.utcnow().isoformat(),
            "total_records": len(attacks),
            "attacks": [attack.to_dict() for attack in attacks]
        }

        return data

    except Exception as e:
        logger.error(f"Error exporting JSON: {e}")
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
