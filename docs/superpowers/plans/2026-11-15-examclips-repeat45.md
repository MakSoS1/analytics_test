# ExamClips Repeat 45 Verification Plan

**Goal:** Recheck the same 45 complete sources from the two prior audits against the current deployed v1.3.19 build and classify each previous defect from new evidence.

**Architecture:** Use the existing authorized full-source GitHub Actions harness on a new isolated QA branch. Keep production code unchanged. Collect encrypted complete evidence and a smaller encrypted review bundle with new source/output pairs, complete transcripts, project snapshots, checksums and full decode receipts.

**Tech Stack:** Existing Playwright/Chrome harness, Python, FFmpeg/FFprobe, RSA-OAEP/AES-GCM artifact encryption.

## Constraints

- Repository writes only to MakSoS1/analytics_test branch qa/examclips-retest45-2026-11-15.
- Live target https://examclips.dpdns.org/app/, expected commit 059bf36e42bb78f5bfc82e8777edc0ba894386d5.
- Same 25 original plus 20 long source identities; no trimming, replacement lectures, injected transcripts, accepted review gates or modified application logic.
- Credentials and private recipient key remain outside the repository and public artifacts.
- Preserve exportability decisions; distinguish errors, skipped review gates, source/network limitations and unverified results.
- Human visual checks are bounded; machine decode is not a claim of full human watching.

## Execution

- [x] Recover the two original reports, exact source manifest and recorded defect locations.
- [x] Verify current deployment identity and match durable private key to existing evidence recipient without printing private key bytes.
- [ ] Adapt isolated workflow, current progress parser and wait for camera plus sound analysis; verify existing transport tests.
- [ ] Refresh only expired public TIB asset URLs from the same source pages.
- [ ] Launch RU03 and RUL01 pilot; prove login, complete analysis and at least one actual export before starting remaining43.
- [ ] Add source-time regression capture and full AV decode to every new case; verify mapping with discontinuous intervals and missing-source cases.
- [ ] Process all remaining43 full sources, retaining source hashes, deployed commit, original decisions, exported files and per-stage failures.
- [ ] Review semantic anchors and actual images for each source; classify fixed, partially fixed, persists, new regression, or unverified.
- [ ] Independently reconcile45 counts and evidence scopes; save complete report and portable evidence summary.

## Review Focus

1. Source point removed by a new EDL must be recorded as absent, never mapped to an unrelated output frame.
2. Jump pairs need actual source correspondence; a cut in source time is not an added camera jump.
3. Correction, question, condition and practical action must be checked together when interpreting boundaries.
4. Site deployment changes during a case invalidate an unqualified same-version result.
5. Full decode, file existence and a successful workflow do not establish visual or semantic quality.
