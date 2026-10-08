# Implementation plan — isolated Cover/Adaptix GH Actions smoke

Spec: `docs/superpowers/specs/2026-10-08-isolated-cover-adaptix-ci-design.md`

## Task 1 — Pure selection and evidence audit

Files: `code/natural_traffic/isolated_lab_evidence.py`,
`code/tests/test_natural_isolated_lab_evidence.py`.

1. RED: fail on missing role, unmatched profile, wrong hash, incomplete or
   unverified Adaptix receipt, unsafe published output shape.
2. GREEN: build a deterministic three-profile Cover registry and validate
   captures through existing hash and PCAP-quality helpers; validate Adaptix
   six paired arm receipts and original capture SHA. Export only aggregates.
3. Run focused unit tests and commit.

## Task 2 — Manual/branch-specific ephemeral CI experiment

Files: `.github/workflows/isolated-cover-adaptix-research.yml`,
`code/tests/test_natural_isolated_lab_workflow.py`.

1. RED: workflow contract tests require branch-only trigger, no public ports,
   pinned Adaptix commit, exact resource guard, Gopher-only fixed tasks, no
   PCAP/credential upload, and nonempty verified aggregate report.
2. GREEN: build pinned existing Cover image and run three predeclared native
   scenario/control pairs. For Adaptix, fetch/verify pinned source and Go
   dependencies, build existing isolated image, run existing fixed capture.
   Never use host networking for runtime. Upload only sanitized summaries.
3. Run focused workflow tests, YAML parser and full research regression;
   commit and publish via GitHub connector.

## Task 3 — Actual evidence and closeout

1. Observe new GitHub Actions workflows to terminal state.
2. Inspect full capture-stage logs and sanitized reports; distinguish
   generated/verified from build-only success, failed and unsupported.
3. If the runner lacks disk, required kernel capabilities, or the pinned
   upstream cannot build, record the exact blocker; never claim a new PCAP.
4. Keep PR draft and naturalness status blocked; report scope and evidence.

## Global constraints

- No real office endpoint, live external operator, arbitrary implant task,
  public C2 listener, covert-data concealment optimization or production
  NDR model modification.
- No leakage of raw captures, credentials, agent binaries or task output.
- No retiming/alteration of source captures to make them look like office.
- No coercion of unsupported runtime into `verified` or `success`.
