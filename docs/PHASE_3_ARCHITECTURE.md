# Phase 3 — Advanced Static-Analysis Architecture

Phase 3 introduces a deterministic, evidence-backed Android static-analysis engine. It inspects APK archive structure,
manifest attack surface, signing metadata, network-security configuration, code-risk indicators, secret-like strings,
native ELF metadata, third-party SDK fingerprints, a CycloneDX 1.5-style SBOM, bounded call graphs, and source-to-sink
candidates.

## Trust model

- Every primary finding is produced by deterministic code and references canonical evidence.
- Static evidence is never represented as runtime-observed behavior.
- Call paths and source/sink co-occurrence are explicitly labelled as candidates, not taint proof.
- Signing scheme detection is structural; cryptographic verification remains a later controlled-worker capability.
- Unknown dependency versions do not produce version-specific CVE claims.

## Main packages

- `app/static_analysis/archive.py` — bounded archive, signing-block, certificate, and ELF inventory.
- `app/static_analysis/manifest.py` — components, exported state, deep links, and network security.
- `app/static_analysis/code.py` — code/string rules, secret redaction, SDKs, call graph, and flow candidates.
- `app/static_analysis/sbom.py` — CycloneDX 1.5-style component inventory.
- `app/static_analysis/engine.py` — orchestration and canonical evidence/finding generation.

## Result fields

`advanced_static`, `signing`, `attack_surface`, `network_security`, `native_analysis`, `dependency_inventory`, `sbom`,
`call_graph`, and `data_flows` are part of schema version 1.2.
