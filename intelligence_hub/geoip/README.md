# Geolocation database

The attack map plots attackers by IP. That needs a city-level database, which
is not committed: it is ~127 MB unpacked, over GitHub's file limit, and it is a
redistributable third-party build rather than our source.

Fetch it once, from the repository root:

    curl -L -o intelligence_hub/geoip/dbip-city-lite.mmdb.gz       https://download.db-ip.com/free/dbip-city-lite-$(date +%Y-%m).mmdb.gz
    gunzip intelligence_hub/geoip/dbip-city-lite.mmdb.gz

Then restart the hub backend. It logs `geoip database loaded` at startup, and
`no geoip database in ...` if it found none.

DB-IP City Lite is free and needs no account. MaxMind's GeoLite2-City.mmdb is
also accepted, under the same directory, if you already have one -- it needs a
MaxMind account.

Attribution is required by DB-IP's CC BY 4.0 licence and is already in the map
component's tile attribution.

Without a database the system runs normally; events simply carry no location,
and the map says so.
