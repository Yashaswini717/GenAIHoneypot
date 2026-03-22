from fastapi import APIRouter, Query, HTTPException
from typing import Optional
from sqlalchemy import select, desc
from database.postgres import AsyncSessionLocal, Session
from database.elastic import get_es
from database.neo4j import get_correlated_ips, get_ip_graph

router = APIRouter()


@router.get("/")
async def get_sessions(
    limit:   int           = Query(50, le=200),
    offset:  int           = Query(0),
    src_ip:  Optional[str] = Query(None),
    country: Optional[str] = Query(None),
    min_score: int         = Query(0),
):
    async with AsyncSessionLocal() as db:
        q = select(Session)
        if src_ip:
            q = q.where(Session.src_ip == src_ip)
        if country:
            q = q.where(Session.country == country)
        if min_score:
            q = q.where(Session.threat_score >= min_score)
        q = q.order_by(desc(Session.started_at)).offset(offset).limit(limit)
        result = await db.execute(q)
        sessions = result.scalars().all()

    return {
        "total":    len(sessions),
        "sessions": [
            {
                "session_id":     s.session_id,
                "src_ip":         s.src_ip,
                "country":        s.country,
                "city":           s.city,
                "protocol":       s.protocol,
                "started_at":     s.started_at.isoformat() if s.started_at else None,
                "ended_at":       s.ended_at.isoformat() if s.ended_at else None,
                "duration":       s.duration,
                "event_count":    s.event_count,
                "login_attempts": s.login_attempts,
                "threat_score":   s.threat_score,
                "hassh":          s.hassh,
            }
            for s in sessions
        ]
    }


@router.get("/{session_id}")
async def get_session_detail(session_id: str):
    """Full session detail — all events + Neo4j correlation."""
    es = get_es()

    # get all events for this session from ES
    result = await es.search(
        index="cowrie-events",
        body={
            "query": {"term": {"session_id": session_id}},
            "sort":  [{"timestamp": {"order": "asc"}}],
            "size":  200,
        }
    )
    events = [h["_source"] for h in result["hits"]["hits"]]

    if not events:
        raise HTTPException(status_code=404, detail="Session not found")

    src_ip = events[0].get("src_ip")

    # get attacker graph from Neo4j
    ip_graph     = await get_ip_graph(src_ip)
    correlated   = []
    if events[0].get("hassh"):
        correlated = await get_correlated_ips(events[0]["hassh"])

    return {
        "session_id":  session_id,
        "src_ip":      src_ip,
        "events":      events,
        "ip_graph":    ip_graph,
        "correlated_ips": correlated,
    }