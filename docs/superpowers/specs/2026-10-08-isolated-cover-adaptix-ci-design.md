# Isolated Cover Channels and Adaptix CI capture — 2026-10-08

## Purpose and scope

Generate new, verifiable, paired research PCAPs from selected already-implemented
Cover Channel techniques, then exercise the repository's existing bounded
Adaptix Gopher TCP/mTLS scenario/control fixture on an ephemeral GitHub Actions
Ubuntu VM. The beneficiary is a defensive NDR feature/label evaluator. This is
**not** an operational C2 deployment, arbitrary command launcher, attacker-PCAP
camouflage tool or proof that packets naturally match an office sensor.

The user has chosen GitHub Actions as the execution environment. Jobs must
prove actual execution and capture before reporting support. No listener may
be published on a public interface. No private keys, generated agents, raw
PCAPs, per-host office records, tokens or task output enter public artifacts.

## Existing boundaries

- Cover source: pinned `cover_runtime/registry.json`, reproducible `run_batch`
  with `--arm both`, native timing and `--mechanics`; network-none Docker
  namespaces. Initial matrix: one bounded HTTPS implementation and DNS,
  WebSocket and MQTT transports from pre-existing source profiles. No features
  are tuned on labels or an office-origin discriminator.
- Adaptix source: official `Adaptix-Framework/AdaptixC2` commit
  `e99535c9ef4642190f7ea125c2983d1611f1a3f3`, an existing pinned
  `framework_runtime/adaptix/Dockerfile`, and existing `capture.py`.
  The runner obtains source and Go dependencies in a **build-only** phase.
  Runtime is network-none, no published ports, veth between namespaces,
  API loopback, fixed `cat /fixture/item_N.txt` tasks only. Modes:
  Gopher TCP and mTLS, three existing predetermined profiles each.
- GitHub-hosted Ubuntu standard VM has finite disk and kernel capabilities.
  Preflight checks report missing resources or privileges without weakening
  the capture integrity requirements; no fallbacks to public networking.

## Research outputs and invariants

Each paired arm retains its original PCAP **only in ephemeral job workspace**.
Audit must verify byte hashes against immutable receipts, successful native
capture, real bidirectional wire traffic, nonempty measured sessions and pair
identity. The report distinguishes `verified`, `unsupported` and `failed`;
an unsupported or failed arm must never count as a generated capture.
Public artifacts contain a sanitized aggregate report only, with counts,
transport names, source pin, hashed image identities and scientific scope.

Do not publish payloads, agent binaries, credentials, endpoint details or
precise packet content. Preserve all source repo files and prior output; use
new runner-temp directories and explicit output non-overwrite guards.

Optional extractor validation must use the existing production session
pipeline without treating all traffic in an attack capture as positive. To
enter the defender corpus, positive session membership must be explicitly
corroborated. Matched controls remain separately identified. No generated
scenario qualifies for `technique_research_validated` or `production_ready`
merely because the pipeline and capture jobs succeed.

## Verification

Local unit tests exercise report fail-closed validation and the exact
profile/role contract. A new CI workflow performs the real capture on two
independent ephemeral Ubuntu jobs, so an unrelated runtime failure does not
conceal another experiment; each job emits fail-closed diagnostics and an
uploadable safe summary when available.
The agent independently checks its GitHub Actions job conclusions and the
resulting audit artifact; a green setup step or Docker build alone is not
proof of generated capture. `naturalness_status=not_passed` remains fixed.
