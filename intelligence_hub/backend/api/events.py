from fastapi import APIRouter, Query
from typing import Optional
from database.elastic import get_es

router = APIRouter()


@router.get("/")
async def get_events(
    limit:      int            = Query(50, le=500),
    offset:     int            = Query(0),
    src_ip:     Optional[str]  = Query(None),
    event_type: Optional[str]  = Query(None),
    session_id: Optional[str]  = Query(None),
    time_range: Optional[str]  = Query(None),  # 1h, 6h, 24h, 7d
):
    es = get_es()

    must = []

    if src_ip:
        must.append({"term": {"src_ip": src_ip}})
    if event_type:
        must.append({"term": {"event_type": event_type}})
    if session_id:
        must.append({"term": {"session_id": session_id}})
    if time_range:
        must.append({"range": {"timestamp": {"gte": f"now-{time_range}"}}})

    query = {"bool": {"must": must}} if must else {"match_all": {}}

    result = await es.search(
        index="cowrie-events",
        body={
            "query": query,
            "sort": [{"timestamp": {"order": "desc"}}],
            "from": offset,
            "size": limit,
        }
    )

    hits = result["hits"]["hits"]
    total = result["hits"]["total"]["value"]

    return {
        "total": total,
        "events": [h["_source"] for h in hits]
    }


@router.get("/stats")
async def get_event_stats():
    """Aggregations for dashboard charts."""
    es = get_es()

    result = await es.search(
        index="cowrie-events",
        body={
            "size": 0,
            "aggs": {
                "by_type": {
                    "terms": {"field": "event_type", "size": 10}
                },
                "by_country": {
                    "terms": {"field": "country", "size": 10}
                },
                "by_hour": {
                    "date_histogram": {
                        "field": "timestamp",
                        "calendar_interval": "hour",
                        "min_doc_count": 1
                    }
                },
                "top_ips": {
                    "terms": {"field": "src_ip", "size": 10}
                },
                "avg_threat_score": {
                    "avg": {"field": "threat_score"}
                }
            }
        }
    )

    aggs = result["aggregations"]
    return {
        "by_type":          aggs["by_type"]["buckets"],
        "by_country":       aggs["by_country"]["buckets"],
        "by_hour":          aggs["by_hour"]["buckets"],
        "top_ips":          aggs["top_ips"]["buckets"],
        "avg_threat_score": round(aggs["avg_threat_score"]["value"] or 0, 1),
    }