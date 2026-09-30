import pytest
from populator.filesystem import FilesystemPopulator
from populator.strategies import PopulationStrategy
from datetime import datetime


class _StubGeneration:
    """Stands in for one generator's output."""

    def __init__(self, content: str):
        self.content = content


class _StubGenerator:
    def __init__(self, label: str):
        self.label = label

    async def generate(self, context):
        kind = context.get("token_type") or context.get("config_type") or self.label
        return _StubGeneration(f"# generated {kind}\n")


def _strategy(temp_dir, honeytoken_store=None) -> PopulationStrategy:
    """A strategy with every model call stubbed out.

    Generation quality is not what these tests are about — where the files end
    up is.
    """
    strategy = PopulationStrategy(
        llm_client=None,
        filesystem_populator=FilesystemPopulator(base_path=temp_dir),
        honeytoken_store=honeytoken_store,
    )
    strategy.source_code_gen = _StubGenerator("source")
    strategy.config_gen = _StubGenerator("config")
    strategy.log_gen = _StubGenerator("log")
    strategy.doc_gen = _StubGenerator("doc")
    strategy.token_gen = _StubGenerator("token")
    return strategy


@pytest.mark.asyncio
async def test_filesystem_populator(temp_dir):
    """Test filesystem population."""
    populator = FilesystemPopulator(base_path=temp_dir)
    
    context = {
        "files": [
            {
                "path": "test.txt",
                "content": "Hello, World!",
                "permissions": 0o644,
            },
            {
                "path": "scripts/test.sh",
                "content": "#!/bin/bash\necho 'test'",
                "permissions": 0o755,
            },
        ]
    }
    
    result = await populator.populate("honeypot-001", context)
    
    assert result.success is True
    assert result.files_created == 2
    
    # Check files exist
    test_file = temp_dir / "honeypot-001" / "test.txt"
    assert test_file.exists()
    assert test_file.read_text() == "Hello, World!"
    
    script_file = temp_dir / "honeypot-001" / "scripts" / "test.sh"
    assert script_file.exists()
    assert script_file.stat().st_mode & 0o777 == 0o755


@pytest.mark.asyncio
async def test_build_returns_specs_without_writing_anything(temp_dir):
    """The split that lets generated content reach a container instead of disk.

    `build` exists because writing to this process's own filesystem was the
    wrong destination — the attacker's container is reachable through the
    session broker, not through a local path, so the caller needs the specs.
    """
    strategy = _strategy(temp_dir)

    files = await strategy.build("hp-1", {"profile": "developer_workstation"})

    assert isinstance(files, list) and files, "build must return the file specs"
    assert all({"path", "content"} <= set(f) for f in files)
    assert not (temp_dir / "hp-1").exists(), "build must not touch the filesystem"


@pytest.mark.asyncio
async def test_populate_still_writes_to_disk(temp_dir):
    """The existing local-deployment path must be unchanged by the split."""
    strategy = _strategy(temp_dir)

    result = await strategy.populate("hp-2", {"profile": "web_server"})

    assert result.success is True
    assert result.files_created > 0
    assert (temp_dir / "hp-2").exists()


@pytest.mark.asyncio
async def test_build_reports_the_credentials_it_embedded(temp_dir, honeytoken_store):
    """A generated secret nothing is told about has no tripwire behind it."""
    strategy = _strategy(temp_dir, honeytoken_store=honeytoken_store)

    await strategy.build("hp-3", {"profile": "developer_workstation"})

    tokens = strategy.embedded_tokens
    assert tokens, "the developer profile embeds honeytokens"
    assert all(t.get("token_value") for t in tokens), (
        "each embedded token must carry its value, or the sidecar cannot scan for it"
    )


@pytest.mark.asyncio
async def test_embedded_tokens_reset_between_builds(temp_dir, honeytoken_store):
    """One environment's credentials must not leak into another's scan set."""
    strategy = _strategy(temp_dir, honeytoken_store=honeytoken_store)

    await strategy.build("hp-4", {"profile": "developer_workstation"})
    first = len(strategy.embedded_tokens)
    await strategy.build("hp-5", {"profile": "developer_workstation"})

    assert len(strategy.embedded_tokens) == first, "tokens accumulated across builds"


class _FlakyGenerator:
    """Fails every Nth call, the way a stalling provider does."""

    def __init__(self, label: str, fail_every: int = 2):
        self.label = label
        self.fail_every = fail_every
        self.calls = 0

    async def generate(self, context):
        self.calls += 1
        if self.calls % self.fail_every == 0:
            raise TimeoutError(f"{self.label} stalled")
        kind = context.get("token_type") or context.get("config_type") or self.label
        return _StubGeneration(f"# generated {kind}\n")


class _DeadGenerator:
    async def generate(self, context):
        raise TimeoutError("provider down")


def _flaky_strategy(temp_dir, honeytoken_store=None, cls=_FlakyGenerator):
    strategy = PopulationStrategy(
        llm_client=None,
        filesystem_populator=FilesystemPopulator(base_path=temp_dir),
        honeytoken_store=honeytoken_store,
    )
    for attr, label in [("source_code_gen", "source"), ("config_gen", "config"),
                        ("log_gen", "log"), ("doc_gen", "doc"), ("token_gen", "token")]:
        setattr(strategy, attr, cls(label) if cls is _FlakyGenerator else cls())
    return strategy


@pytest.mark.asyncio
async def test_a_failed_step_costs_one_file_not_the_profile(temp_dir, honeytoken_store):
    """The whole point: one stalled call must not discard everything else.

    A profile is 6-10 sequential model calls. Against a provider where roughly
    one in three stalls, all-or-nothing meant a complete profile essentially
    never landed and the attacker saw only the offline bundle.
    """
    strategy = _flaky_strategy(temp_dir, honeytoken_store)

    files = await strategy.build("hp-flaky", {"profile": "developer_workstation"})

    assert files, "a partial profile must still return the files that succeeded"
    assert strategy.failures, "and must report which steps failed"
    assert all(f.get("content") for f in files), "no file may carry empty content"


@pytest.mark.asyncio
async def test_no_file_embeds_a_failed_credential(temp_dir, honeytoken_store):
    """A credentials file reading 'None' is a worse decoy than no file."""
    strategy = _flaky_strategy(temp_dir, honeytoken_store)

    for profile in ("developer_workstation", "production_server",
                    "database_server", "web_server"):
        files = await strategy.build("hp-x", {"profile": profile})
        for f in files:
            assert "None" not in f["content"], (
                f"{profile}:{f['path']} embedded a failed token as the literal 'None'"
            )


@pytest.mark.asyncio
async def test_total_provider_failure_yields_nothing_rather_than_junk(temp_dir, honeytoken_store):
    """When every call fails there is genuinely nothing to plant.

    The endpoint turns this empty list into a 503 so the caller falls back to
    its offline bundle, which is the correct outcome — as distinct from a
    partial profile, which is not.
    """
    strategy = _flaky_strategy(temp_dir, honeytoken_store, cls=_DeadGenerator)

    files = await strategy.build("hp-dead", {"profile": "developer_workstation"})

    assert files == []
    assert len(strategy.failures) >= 5


@pytest.mark.asyncio
async def test_failures_reset_between_builds(temp_dir, honeytoken_store):
    """One environment's failures must not be reported against the next."""
    strategy = _flaky_strategy(temp_dir, honeytoken_store)
    gens = [strategy.source_code_gen, strategy.config_gen, strategy.log_gen,
            strategy.doc_gen, strategy.token_gen]

    await strategy.build("hp-1", {"profile": "developer_workstation"})
    first = len(strategy.failures)
    assert first, "the flaky generator should have failed at least once"

    # Rewind the counters so the second build fails in the same places; without
    # this the comparison would be measuring the generator, not the reset.
    for g in gens:
        g.calls = 0

    await strategy.build("hp-2", {"profile": "developer_workstation"})

    assert len(strategy.failures) == first, (
        f"failures accumulated across builds: {first} then {len(strategy.failures)}"
    )


@pytest.mark.asyncio
async def test_deploy_single_file(temp_dir):
    """Test deploying a single file."""
    populator = FilesystemPopulator(base_path=temp_dir)
    
    file_path = await populator.deploy_file(
        honeypot_id="test-002",
        relative_path="config.yml",
        content="key: value\n",
        permissions=0o600,
    )
    
    assert file_path.exists()
    assert file_path.stat().st_mode & 0o777 == 0o600
