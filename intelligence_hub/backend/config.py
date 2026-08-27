from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    postgres_user: str
    postgres_password: str
    postgres_db: str
    redis_url: str = "redis://redis:6379"
    es_url: str = "http://elasticsearch:9200"
    neo4j_uri: str = "bolt://neo4j:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: str
    hmac_secret: str
    log_level: str = "info"
    cors_origin: str = "http://localhost:5173"

    # Two ingest paths with two different trust models.
    #
    #   POST /ingest/       sensor path. Honeypot sidecars stream single
    #                       events here, each individually HMAC-signed. Always
    #                       verified, no exceptions.
    #
    #   POST /ingest/batch  operator path. The Ingest Logs page in the
    #                       dashboard uploads Cowrie JSONL files through it. A
    #                       browser cannot hold the signing secret, so it
    #                       cannot sign — hence this flag rather than a check.
    #
    # True is the development default so the upload UI keeps working. Set it
    # to false before exposing the hub anywhere: while it is true, anyone who
    # can reach the hub can inject unsigned events, which defeats the whole
    # zero-trust layer. Sensors are unaffected either way — they use /ingest/.
    allow_unsigned_batch: bool = True

    class Config:
        env_file = ".env"

settings = Settings()

DATABASE_URL = (
    f"postgresql+asyncpg://{settings.postgres_user}:"
    f"{settings.postgres_password}@postgres/{settings.postgres_db}"
)