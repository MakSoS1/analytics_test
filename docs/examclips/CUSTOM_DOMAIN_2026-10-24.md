# ExamClips custom domain

The public ExamClips SPA in `MakSoS1/analytics_test` uses
`https://examclips.dpdns.org/` with GitHub Pages hosting. This deployment is
separate from the `examclips` checkout and `forgeofeducation.ru` VM.

## Build and publication

The source branch is `feat/examclips-library-zoom-storyboard-20261017`.
`.github/workflows/examclips-gh-pages-branch.yml` runs tests, builds with
`EXAMCLIPS_BASE=./`, and publishes `examclips-local/dist` to `gh-pages`.
Relative asset URLs support both the domain root and the former repository path.
`examclips-local/public/CNAME` is copied into each build so the orphaned
`gh-pages` publication retains the custom domain.

## DNS and HTTPS

The domain was registered using a free DigitalPlat slot on 2026-10-24.
DigitalPlat DNS is authoritative (`dns1.digitalplat.org`,
`dns2.digitalplat.org`). The zone apex needs GitHub Pages A records:

```
185.199.108.153
185.199.109.153
185.199.110.153
185.199.111.153
```

Use direct DNS without an HTTP proxy. Associate the domain with the repository
before adding its web-facing DNS records. Keep HTTPS enforcement enabled after
GitHub has issued the certificate. Verify the root document, referenced JS/CSS,
worker assets, and HTTP-to-HTTPS redirect after every relevant change.

Reference: https://docs.github.com/en/pages/configuring-a-custom-domain-for-your-github-pages-site/managing-a-custom-domain-for-your-github-pages-site

The registrar currently lists expiry as 2027-10-24. Free renewal becomes
available in the final 120 days before expiry; no paid advance renewal or
subscription is required for the chosen free slot. Recheck the registrar's
current terms when renewing.

## Browser project migration

IndexedDB and localStorage are scoped to the origin. Before switching the
GitHub Pages custom domain, export projects from the old address using
the JSON project save control. Keep original video files separately. On the
new domain, use `Открыть проект JSON` and attach the original video.
Changing domains does not delete the old origin's data, but GitHub's redirect
can prevent accessing its previous UI. The app does not automatically migrate
projects across origins.

## Rollback

To return to the former `https://maksos1.github.io/analytics_test/` URL, remove
the repository's Pages custom domain and remove `public/CNAME` from source
before publishing again. Keep the relative base so the same asset paths work.
Remove the domain's GitHub Pages A records if the domain is no longer associated
with the repository. Verify the old URL and its assets before reporting recovery.

Regional probes are evidence for the tested networks and time only; they do not
guarantee access on every Russian residential or mobile ISP, or availability of
external ASR model downloads.
