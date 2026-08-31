from neo4j import AsyncGraphDatabase
from config import settings

driver = None


async def init_neo4j():
    global driver
    driver = AsyncGraphDatabase.driver(
        settings.neo4j_uri,
        auth=(settings.neo4j_user, settings.neo4j_password)
    )
    # Create constraints (run once, idempotent)
    async with driver.session() as session:
        await session.run(
            "CREATE CONSTRAINT ip_unique IF NOT EXISTS "
            "FOR (n:IP) REQUIRE n.address IS UNIQUE"
        )
        await session.run(
            "CREATE CONSTRAINT hassh_unique IF NOT EXISTS "
            "FOR (n:HASSH) REQUIRE n.fingerprint IS UNIQUE"
        )
        await session.run(
            "CREATE CONSTRAINT session_unique IF NOT EXISTS "
            "FOR (n:Session) REQUIRE n.session_id IS UNIQUE"
        )
    print("✓ Neo4j ready")


async def write_session_graph(event: dict):
    """
    Creates/merges nodes and relationships for each event.
    Graph model:
      (IP)-[:INITIATED]->(Session)
      (IP)-[:USES]->(HASSH)
      (IP)-[:ATTEMPTED]->(Credential {username, password})
      (Session)-[:HAS_TECHNIQUE]->(MITRETechnique)
    """
    if not driver:
        return

    async with driver.session() as session:
        await session.run("""
            MERGE (ip:IP {address: $src_ip})
            SET ip.country   = $country,
                ip.asn       = $asn,
                ip.last_seen = $timestamp

            MERGE (s:Session {session_id: $session_id})
            SET s.protocol   = $protocol,
                s.src_ip     = $src_ip,
                s.started_at = $timestamp

            MERGE (ip)-[:INITIATED]->(s)
        """, {
            "src_ip":     event.get("src_ip"),
            "country":    event.get("country"),
            "asn":        event.get("asn"),
            "timestamp":  str(event.get("timestamp")),
            "session_id": event.get("session_id"),
            "protocol":   event.get("protocol", "ssh"),
        })

        # Link HASSH fingerprint if present
        if event.get("hassh"):
            await session.run("""
                MERGE (ip:IP {address: $src_ip})
                MERGE (h:HASSH {fingerprint: $hassh})
                SET h.ssh_version = $ssh_version
                MERGE (ip)-[:USES]->(h)
            """, {
                "src_ip":      event.get("src_ip"),
                "hassh":       event.get("hassh"),
                "ssh_version": event.get("ssh_version"),
            })

        # Link credential attempt if present
        if event.get("username") and event.get("password"):
            await session.run("""
                MERGE (ip:IP {address: $src_ip})
                MERGE (c:Credential {username: $username, password: $password})
                MERGE (ip)-[:ATTEMPTED]->(c)
            """, {
                "src_ip":   event.get("src_ip"),
                "username": event.get("username"),
                "password": event.get("password"),
            })

        # Link MITRE technique if present
        if event.get("mitre_technique"):
            await session.run("""
                MERGE (s:Session {session_id: $session_id})
                MERGE (m:MITRETechnique {technique_id: $technique_id})
                SET m.tactic = $tactic
                MERGE (s)-[:HAS_TECHNIQUE]->(m)
            """, {
                "session_id":   event.get("session_id"),
                "technique_id": event.get("mitre_technique"),
                "tactic":       event.get("mitre_tactic"),
            })


async def get_correlated_ips(hassh: str) -> list:
    """Find all IPs that share the same HASSH — same attacker tool."""
    if not driver:
        return []
    async with driver.session() as session:
        result = await session.run("""
            MATCH (ip:IP)-[:USES]->(h:HASSH {fingerprint: $hassh})
            RETURN ip.address AS address, ip.country AS country
        """, {"hassh": hassh})
        return [dict(r) for r in await result.data()]


async def get_ip_graph(ip: str) -> dict:
    """Get full attack profile for an IP — sessions, HASHes, credentials."""
    if not driver:
        return {}
    async with driver.session() as session:
        result = await session.run("""
            MATCH (ip:IP {address: $ip})
            OPTIONAL MATCH (ip)-[:INITIATED]->(s:Session)
            OPTIONAL MATCH (ip)-[:USES]->(h:HASSH)
            OPTIONAL MATCH (ip)-[:ATTEMPTED]->(c:Credential)
            RETURN
                ip.address  AS ip,
                ip.country  AS country,
                collect(DISTINCT s.session_id) AS sessions,
                collect(DISTINCT h.fingerprint) AS hassh_list,
                collect(DISTINCT {username: c.username, password: c.password}) AS credentials
        """, {"ip": ip})
        records = await result.data()
        return records[0] if records else {}


def get_driver():
    return driver