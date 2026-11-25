# AGENTS.md

Operational notes for agents working across the NTI repositories.

## Repository layout

| Repo | Package | Role |
|---|---|---|
| `Neutral-Trust-Infrastructure` | `ube-foundation` | Rust/PyO3 core (maturin, abi3) |
| `Openhands---nti` | `openhands-nti` | OpenHands SDK guardrail |
| `crewai-nti` | `crewai-nti` | CrewAI middleware |
| `langchain-nti` | `langchain-nti` | LangChain callback/layer |
| `autogen-nti` | `autogen-nti` | AutoGen wrapper |

## Release flow

Core publishes on tag push (`v*`). Wrappers publish on GitHub Release
(`release: types: [published]`); pushing a tag alone does **not** publish them.

Wrapper PyPI publishing uses OIDC trusted publishing. The PyPI publisher is
configured **without** an environment name, so `publish.yml` must not declare
`environment: pypi` — otherwise the OIDC `sub` claim gains an `:environment:pypi`
suffix and PyPI rejects it as `invalid-publisher`.

## Versioning

`pyproject.toml` is the **only** place a wrapper version is declared. Each
`__init__.py` derives `__version__` from installed metadata:

```python
try:
    __version__ = _version("crewai-nti")
except PackageNotFoundError:
    __version__ = "0.0.0+unknown"
```

Bumping a wrapper means editing `pyproject.toml` alone — never a version string
in `__init__.py`. The `0.0.0+unknown` sentinel only appears in a source tree that
was never installed; `tests/test_version.py` fails if it reaches a real install,
and `Openhands---nti`'s publish workflow asserts the same before uploading.

This replaced a hand-maintained duplicate string that silently diverged:
`crewai-nti` 0.1.1 and `langchain-nti` 0.1.2 shipped wheels reporting a version
one release behind their own dist-info.

## Core API surface (ube-foundation 0.1.9)

`PqcKeyPair` has **no** `generate()` — construct it directly. Keys are ML-DSA-87
(public key 2592 bytes). Identity binding goes through the engine, not the key:

```python
engine = TrustEngine()
engine.register_pqc_identity_key(actor, key_pair.get_public_key_bytes())
```

`canonical_json_bytes` is a Rust-internal helper, not a Python export.

Each wrapper exposes a different verification entry point, and all fail closed by
**raising `PermissionError`** in strict mode (the default) rather than returning
`False`:

| Wrapper | Method | Contract |
|---|---|---|
| crewai | `verify_tool_execution(tool, input)` | signs internally, evaluates capability |
| langchain | `verify_tool_response(payload)` | verify a payload from `sign_output()` |
| autogen | `verify_message(capability, msg, sig)` | caller must sign `json.dumps(msg, sort_keys=True)` |

autogen also refuses unsigned messages outright (`require_signature=True`), so a
signature must be passed explicitly. Do not assume a `check_capability()` method —
it does not exist on any of them.

## Testing

Wrappers install with `pip install -e ".[dev]"` and run `pytest -q`.
`Openhands---nti/tests/conftest.py` calls `pytest.importorskip` on
`openhands.sdk.tool.tool`, which skips the whole suite when the SDK is absent —
tests only meaningfully run under the `.[dev]` extra.

When verifying published artifacts, pass `--no-cache-dir` and pin exact versions:
PyPI's CDN can serve a stale `info.version` for a minute or two after upload.
