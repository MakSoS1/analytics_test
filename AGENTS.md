# Agent routing for the ExamClips branch

- Repository: `MakSoS1/analytics_test`.
- This is an isolated product branch. `main` belongs to another project.
- Canonical ExamClips source/PR base:
  `feat/examclips-library-zoom-storyboard-20261017`.
- Create work branches with `codex/`. Target ExamClips PRs at that source
  branch; do not merge ExamClips into `main` or change the default branch.
- App root: [`apps/examclips/`](apps/examclips/README.md).
- Read [`apps/examclips/AGENTS.md`](apps/examclips/AGENTS.md) and
  [`apps/examclips/docs/README.md`](apps/examclips/docs/README.md) before editing.
- Live URL: `https://examclips.dpdns.org/`. Publishing branch: `gh-pages`.
- `examclips-local/` and root `docs/examclips/` are former paths, not additional
  applications. Reports/plans/specs now live in the app's `docs/history/`.
- The notebooks, Cover Channel, monitor and probe directories are unrelated.
  Keep their code and workflows out of ExamClips changes.
- A local checkout named `examclips` may be the separate
  `MakSoS1/examclips` / `forgeofeducation.ru` project. Verify `git remote -v`
  and the branch. Its Caddy/VM/Supabase deployment is not this site's deployment.
- Do not add secrets, private lecture media, model weights, generated MP4,
  caches, environments, `node_modules/`, or `dist/` to source commits.
