from elasticsearch import AsyncElasticsearch
from config import settings

es: AsyncElasticsearch = None

async def init_elasticsearch():
    global es
    es = AsyncElasticsearch(settings.es_url)

    # Create cowrie events index
    if not await es.indices.exists(index="cowrie-events"):
        await es.indices.create(index="cowrie-events", body={
            "mappings": {
                "properties": {
                    "raw_event_id":    {"type": "keyword"},
                    "session_id":      {"type": "keyword"},
                    "src_ip":          {"type": "ip"},
                    "src_port":        {"type": "integer"},
                    "dst_ip":          {"type": "ip"},
                    "dst_port":        {"type": "integer"},
                    "protocol":        {"type": "keyword"},
                    "event_type":      {"type": "keyword"},
                    "base_score":      {"type": "integer"},
                    "threat_score":    {"type": "integer"},
                    "sensor_id":       {"type": "keyword"},
                    "timestamp":       {"type": "date"},
                    "username":        {"type": "keyword"},
                    "password":        {"type": "keyword"},
                    "hassh":           {"type": "keyword"},
                    "ssh_version":     {"type": "keyword"},
                    "command":         {"type": "text"},
                    "duration":        {"type": "float"},
                    "raw_message":     {"type": "text"},
                    "country":         {"type": "keyword"},
                    "city":            {"type": "keyword"},
                    "latitude":        {"type": "float"},
                    "longitude":       {"type": "float"},
                    "asn":             {"type": "keyword"},
                    "mitre_tactic":    {"type": "keyword"},
                    "mitre_technique": {"type": "keyword"},
                    "location": {
                        "type": "geo_point"
                    }
                }
            }
        })
        print("✓ Created index: cowrie-events")

    # Create IOC index
    if not await es.indices.exists(index="cowrie-iocs"):
        await es.indices.create(index="cowrie-iocs", body={
            "mappings": {
                "properties": {
                    "ioc_type":        {"type": "keyword"},
                    "value":           {"type": "keyword"},
                    "first_seen":      {"type": "date"},
                    "last_seen":       {"type": "date"},
                    "hit_count":       {"type": "integer"},
                    "sessions":        {"type": "keyword"},
                    "mitre_tags":      {"type": "keyword"},
                    "threat_score":    {"type": "integer"},
                    "country":         {"type": "keyword"},
                    "asn":             {"type": "keyword"},
                }
            }
        })
        print("✓ Created index: cowrie-iocs")

    print("✓ Elasticsearch ready")


async def index_event(event: dict):
    """Index a single normalized event."""
    if event.get("latitude") and event.get("longitude"):
        event["location"] = {
            "lat": event["latitude"],
            "lon": event["longitude"]
        }
    await es.index(index="cowrie-events", document=event)


async def upsert_ioc(ioc_type: str, value: str, event: dict):
    """Insert or update an IOC entry."""
    doc_id = f"{ioc_type}:{value}"
    existing = None

    try:
        existing = await es.get(index="cowrie-iocs", id=doc_id)
    except Exception:
        pass

    if existing:
        src = existing["_source"]
        await es.update(index="cowrie-iocs", id=doc_id, body={
            "doc": {
                "last_seen":   event.get("timestamp"),
                "hit_count":   src.get("hit_count", 0) + 1,
                "sessions":    list(set(src.get("sessions", []) + [event.get("session_id")])),
                "threat_score": max(src.get("threat_score", 0), event.get("threat_score", 0)),
            }
        })
    else:
        await es.index(index="cowrie-iocs", id=doc_id, document={
            "ioc_type":     ioc_type,
            "value":        value,
            "first_seen":   event.get("timestamp"),
            "last_seen":    event.get("timestamp"),
            "hit_count":    1,
            "sessions":     [event.get("session_id")],
            "mitre_tags":   [event.get("mitre_technique")] if event.get("mitre_technique") else [],
            "threat_score": event.get("threat_score", 0),
            "country":      event.get("country"),
            "asn":          event.get("asn"),
        })


def get_es() -> AsyncElasticsearch:
    return es