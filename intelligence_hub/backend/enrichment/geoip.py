import geoip2.database
import geoip2.errors
import os

_reader = None


def init_geoip():
    global _reader
    db_path = os.path.join(os.path.dirname(__file__), "..", "geoip", "GeoLite2-City.mmdb")
    db_path = os.path.abspath(db_path)
    if os.path.exists(db_path):
        _reader = geoip2.database.Reader(db_path)
        print("✓ GeoIP database loaded")
    else:
        print("⚠ GeoIP database not found — skipping geo enrichment")
        print(f"  Place GeoLite2-City.mmdb in: intelligence_hub/geoip/")


def enrich_geoip(event: dict) -> dict:
    if not _reader:
        return event
    try:
        response = _reader.city(event["src_ip"])
        event["country"]   = response.country.name
        event["city"]      = response.city.name
        event["latitude"]  = float(response.location.latitude or 0)
        event["longitude"] = float(response.location.longitude or 0)
    except (geoip2.errors.AddressNotFoundError, Exception):
        pass
    return event