# ExamClips repository organization

User-approved scope: keep ExamClips in its separate branch of `analytics_test`.
Do not merge into, rename, or change `main`; it belongs to another project.
Implement in this session without subagents.

## Design

Use `apps/examclips/` as the single application root. Keep the current public
domain, source branch and engine behavior. Put current guides next to the app,
and archive earlier reports/specifications/plans under its `docs/history/`.
GitHub workflows remain in `.github/workflows/` as GitHub requires, with paths
updated to the app root. Root README and AGENTS route an agent to the right app
and branch. Preserve the former root analytics README separately.

## Execution checklist

- [x] Move the app and its documentation; preserve source/test contents.
- [x] Write current README, agent handoff, architecture, development, deployment,
  quality and troubleshooting guides. Correct the stale editorial skill.
- [x] Update every ExamClips workflow path; keep publication limited to
  `feat/examclips-library-zoom-storyboard-20261017` and `gh-pages`.
- [ ] Validate local Markdown links, stale paths, moved file identity, tests and
  production build; run full GitHub browser/storage CI.
- [ ] Merge only into the ExamClips source branch, confirm publication and live
  HTTPS/UI, and confirm the remote `main` SHA is unchanged.

## Review focus

- Runtime source imports and optional local OCR worker resolve after relocation.
- Workflow filters, working directories and artifact uploads use the new paths.
- Current guides do not revive Docker-specific planning or obsolete layouts.
- Historical reports are labeled and cannot be mistaken for current instructions.
- Main and unrelated project files retain their original contents.

## Local verification

- 100 local Markdown links resolved after relocation.
- 113 existing app files (excluding replaced README and ignore rules) retain identical Git blob contents.
- 176 tests passed; relative-base production build passed.
- Original analytics README preserved byte-for-byte under `docs/legacy/`.
- Remote `main` before publication: `35812dd0ea2a98203f0f270337d359b3c8bcac08`.
- Ruling: four workflows tied to obsolete experimental branches are archived; three current app workflows remain active.
