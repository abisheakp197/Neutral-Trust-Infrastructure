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

## Versioning pitfall

Each package's version lives in **two** places: `pyproject.toml` and
`__version__` in `src/<pkg>/__init__.py`. They are bumped independently and can
silently diverge, producing a wheel whose dist-info version disagrees with the
runtime constant (this shipped in `crewai-nti` 0.1.1 and `langchain-nti` 0.1.2).
`tests/test_version.py` in each wrapper now asserts they match.

## Core API surface (ube-foundation 0.1.9)

`PqcKeyPair` has **no** `generate()` — construct it directly. Keys are ML-DSA-87
(public key 2592 bytes). Identity binding goes through the engine, not the key:

```python
engine = TrustEngine()
engine.register_pqc_identity_key(actor, key_pair.get_public_key_bytes())
```

`canonical_json_bytes` is a Rust-internal helper, not a Python export.

## Testing

Wrappers install with `pip install -e ".[dev]"` and run `pytest -q`.
`Openhands---nti/tests/conftest.py` calls `pytest.importorskip` on
`openhands.sdk.tool.tool`, which skips the whole suite when the SDK is absent —
tests only meaningfully run under the `.[dev]` extra.

When verifying published artifacts, pass `--no-cache-dir` and pin exact versions:
PyPI's CDN can serve a stale `info.version` for a minute or two after upload.
