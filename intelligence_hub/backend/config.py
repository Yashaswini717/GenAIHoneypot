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

    class Config:
        env_file = ".env"

settings = Settings()

DATABASE_URL = (
    f"postgresql+asyncpg://{settings.postgres_user}:"
    f"{settings.postgres_password}@postgres/{settings.postgres_db}"
)