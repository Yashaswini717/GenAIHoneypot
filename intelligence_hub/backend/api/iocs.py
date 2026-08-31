from fastapi import APIRouter, Query
from typing import Optional
from database.elastic import get_es

router = APIRouter()


@router.get("/")
async def get_iocs(
    limit:    int           = Query(50, le=500),
    offset:   int           = Query(0),
    ioc_type: Optional[str] = Query(None),  # ip, hassh, username
    search:   Optional[str] = Query(None),
    min_score: int          = Query(0),
):
    es = get_es()

    must = []
    if ioc_type:
        must.append({"term": {"ioc_type": ioc_type}})
    if search:
        must.append({"wildcard": {"value": f"*{search}*"}})
    if min_score > 0:
        must.append({"range": {"threat_score": {"gte": min_score}}})

    query = {"bool": {"must": must}} if must else {"match_all": {}}

    result = await es.search(
        index="cowrie-iocs",
        body={
            "query": query,
            "sort": [{"threat_score": {"order": "desc"}}],
            "from": offset,
            "size": limit,
        }
    )

    hits = result["hits"]["hits"]
    return {
        "total": result["hits"]["total"]["value"],
        "iocs":  [h["_source"] for h in hits]
    }