from pydantic import model_validator
from pydantic_settings import BaseSettings

#: Signing secrets published in this repository, which anyone can sign with.
#: "dev" is the old development convention; "change-me" is the placeholder in
#: honeypot-ecosystem/.env.example.
PUBLISHED_SECRETS = frozenset({"", "dev", "change-me"})

#: Shortest operator token accepted. It guards the one path that writes
#: events without a signature, so it should not be guessable.
MIN_OPERATOR_TOKEN_LENGTH = 16


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
    #                       events here, each HMAC-signed together with a
    #                       timestamp and an event id (ingest/signing.py).
    #                       Always verified, and each event is accepted once.
    #
    #   POST /ingest/batch  operator path. The Ingest Logs page in the
    #                       dashboard uploads Cowrie JSONL files through it. A
    #                       browser cannot hold the signing secret, so this
    #                       path needs the operator token instead, and what
    #                       comes through it is tagged as an upload and kept
    #                       out of the retention figures.

    # -- sensor path -------------------------------------------------------

    # A sensor request signed further than this from the hub's clock is
    # refused, so a captured request is only worth replaying for this long --
    # and inside the window its event id has already been recorded, so the
    # replay is refused anyway.
    ingest_clock_skew_seconds: int = 300

    # How long an accepted event id is remembered in Redis. This is what makes
    # the sidecar's at-least-once retries idempotent, so it should outlast any
    # outage a retry might follow. Never less than twice the clock window,
    # whatever is configured here: that is how long after the original a
    # replay can still carry an acceptable timestamp.
    ingest_dedup_ttl_seconds: int = 24 * 3600

    # Deprecated, removed in the next release. Accepts the old body-only
    # signature from sidecars built before the timestamped scheme, so the hub
    # can be upgraded first. Those requests are deduplicated on the body's
    # hash, but they carry no timestamp: once that record expires a captured
    # one can be replayed. Leave off unless an old sidecar is still running.
    allow_legacy_signatures: bool = False

    # Lets the hub start with a published HMAC secret. With HMAC_SECRET=dev
    # it also switches signature checks off on /ingest/ -- which used to
    # happen silently whenever the secret was "dev". Local development only.
    insecure_dev_mode: bool = False

    # -- operator path -----------------------------------------------------

    # Bearer token the Ingest Logs page sends. Empty disables uploads.
    operator_token: str = ""

    # Deprecated, removed in the next release. Accepts operator uploads with
    # no token at all, which was the default until now. Anyone who can reach
    # the hub can then inject events. Uploads are still tagged as such.
    allow_unsigned_batch: bool = False

    class Config:
        env_file = ".env"

    @model_validator(mode="after")
    def _refuse_insecure_configuration(self) -> "Settings":
        # Refusing to start is the point. A secret anyone can read from this
        # repository makes every signature forgeable, and the old behaviour
        # for "dev" -- skip verification, say nothing -- meant a hub could run
        # exposed with zero trust switched off and no one would know.
        if self.hmac_secret.strip() in PUBLISHED_SECRETS and not self.insecure_dev_mode:
            raise ValueError(
                f"HMAC_SECRET is {self.hmac_secret!r}, which is published in this "
                "repository, so anyone could sign events with it. Use the secret "
                "tools/bootstrap.py generated for honeypot-ecosystem/.env, or set "
                "INSECURE_DEV_MODE=true on a hub that is never exposed."
            )
        if self.operator_token and len(self.operator_token) < MIN_OPERATOR_TOKEN_LENGTH:
            raise ValueError(
                f"OPERATOR_TOKEN must be at least {MIN_OPERATOR_TOKEN_LENGTH} characters. "
                'Generate one with: python -c "import secrets; print(secrets.token_urlsafe(32))"'
            )
        if self.ingest_clock_skew_seconds <= 0:
            raise ValueError("INGEST_CLOCK_SKEW_SECONDS must be positive")
        return self

    @property
    def signatures_disabled(self) -> bool:
        """True only for INSECURE_DEV_MODE with HMAC_SECRET=dev."""
        return self.insecure_dev_mode and self.hmac_secret == "dev"

    @property
    def dedup_ttl_seconds(self) -> int:
        return max(self.ingest_dedup_ttl_seconds, 2 * self.ingest_clock_skew_seconds)


settings = Settings()

DATABASE_URL = (
    f"postgresql+asyncpg://{settings.postgres_user}:"
    f"{settings.postgres_password}@postgres/{settings.postgres_db}"
)
