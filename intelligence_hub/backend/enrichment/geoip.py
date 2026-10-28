"""Geolocation for attacker addresses.

Two things were wrong here and both were silent. `init_geoip()` was never
called from anywhere, so `_reader` stayed None and `enrich_geoip` returned on
its first line for every event the system has ever ingested -- the attack map
could not have worked even with a database present. And the only filename
accepted was GeoLite2-City.mmdb, which needs a MaxMind account; the free
DB-IP City Lite build is the same MaxMind DB format and needs none.

Private addresses are handled explicitly rather than left to fail. Lab traffic
is RFC1918 and will never geolocate, so an empty map there means "this attacker
is internal", not "geolocation is broken" -- and those are worth telling apart
when you are looking at a blank world map wondering which one you have.
"""
import ipaddress
import logging
import os

import geoip2.database
import geoip2.errors

log = logging.getLogger("enrichment.geoip")

_reader = None

#: Accepted in order. DB-IP City Lite is free and needs no account; GeoLite2
#: is used if someone has supplied it.
_DB_NAMES = ("dbip-city-lite.mmdb", "GeoLite2-City.mmdb")


def init_geoip() -> None:
    """Open whichever city database is present. Called from the app lifespan."""
    global _reader
    base = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "geoip"))
    for name in _DB_NAMES:
        path = os.path.join(base, name)
        if os.path.exists(path):
            try:
                _reader = geoip2.database.Reader(path)
                log.info("geoip database loaded: %s", name)
                return
            except Exception as exc:
                log.warning("geoip database %s could not be opened: %s", name, exc)
    log.warning(
        "no geoip database in %s - events will carry no location. "
        "Expected one of: %s", base, ", ".join(_DB_NAMES),
    )


def _scope(ip: str) -> str:
    """Why an address has no location, when it has none."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "invalid"
    if addr.is_loopback:
        return "loopback"
    if addr.is_private:
        return "private"
    return "public"


def enrich_geoip(event: dict) -> dict:
    ip = event.get("src_ip") or ""
    scope = _scope(ip)

    # Recorded on every event so the dashboard can say why a marker is missing
    # instead of showing an empty map and leaving the reader to guess.
    event["ip_scope"] = scope

    if scope != "public" or _reader is None:
        return event

    try:
        response = _reader.city(ip)
        event["country"] = response.country.name
        event["city"] = response.city.name
        if response.location.latitude is not None:
            event["latitude"] = float(response.location.latitude)
        if response.location.longitude is not None:
            event["longitude"] = float(response.location.longitude)
    except geoip2.errors.AddressNotFoundError:
        # A public address the database does not cover. Normal; not an error.
        pass
    except Exception as exc:
        log.debug("geoip lookup failed for %s: %s", ip, exc)
    return event
