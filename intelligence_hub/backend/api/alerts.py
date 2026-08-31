from fastapi import APIRouter, Query, HTTPException
from typing import Optional
from sqlalchemy import select, desc, update
from database.postgres import AsyncSessionLocal, Alert, AlertStatus
from datetime import datetime

router = APIRouter()


@router.get("/")
async def get_alerts(
    limit:  int                    = Query(50, le=200),
    offset: int                    = Query(0),
    status: Optional[AlertStatus]  = Query(None),
):
    async with AsyncSessionLocal() as db:
        q = select(Alert)
        if status:
            q = q.where(Alert.status == status)
        q = q.order_by(desc(Alert.created_at)).offset(offset).limit(limit)
        result = await db.execute(q)
        alerts = result.scalars().all()

    return {
        "total":  len(alerts),
        "alerts": [
            {
                "id":               a.id,
                "session_id":       a.session_id,
                "src_ip":           a.src_ip,
                "alert_type":       a.alert_type,
                "description":      a.description,
                "threat_score":     a.threat_score,
                "mitre_technique":  a.mitre_technique,
                "country":          a.country,
                "status":           a.status,
                "created_at":       a.created_at.isoformat() if a.created_at else None,
            }
            for a in alerts
        ]
    }


@router.patch("/{alert_id}")
async def update_alert(alert_id: int, status: AlertStatus):
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(Alert).where(Alert.id == alert_id)
        )
        alert = result.scalar_one_or_none()
        if not alert:
            raise HTTPException(status_code=404, detail="Alert not found")

        alert.status     = status
        alert.updated_at = datetime.utcnow()
        await db.commit()

    return {"id": alert_id, "status": status}


@router.get("/summary")
async def get_alert_summary():
    """Count by status — for navbar badge."""
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(Alert))
        all_alerts = result.scalars().all()

    summary = {"open": 0, "acked": 0, "escalated": 0, "suppressed": 0}
    for a in all_alerts:
        summary[a.status.value] += 1

    return summary