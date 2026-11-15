# Isolated ExamClips processing audit

The authorized implementation runs all 45 original full sources through an isolated localhost instance of the app's exact current private CI build. It uses normal UI ASR, planning, camera analysis, project export and every eligible MP4 export. Its results are labelled `test_instance`; they are never live-site passes.

## Chosen approach

Use the existing private `examclips-dist` artifact from successful app CI run 43751698466, commit c8358a6df86ca0f77d859ebe8481a876b3e1abd5. Its archive is 12,964,869 bytes, SHA256 4463e4e2b9a3f57ce215610f974f2162189a4c421bab6947191dd61c1c726940. It is the documented account-free local configuration, built without Supabase settings and without enabled billing. It avoids running optional Vite development bridges. Full local Supabase/PostgreSQL mock billing is documented but adds unrelated infrastructure to a processing audit. Production interception is excluded.

The preparation job receives a capability URL and a fresh per-run bundle recipient public key through the existing authenticated RSA envelope. It downloads and verifies the CI archive, then uses unchanged `crypto.mjs` `sealFile` to create a shared encrypted workflow artifact. Each case receives the matching recipient private key through its own ephemeral RSA handoff and decrypts with unchanged `openFile`. No production account credentials are used. No private source, compiled code, signed download URL, or key is committed or uploaded in plaintext.

## Boundaries and fidelity

Only declared `dist/app/` entries are extracted after archive SHA verification, with per-file SHA256 verification and safe ZIP checks. A server bound to 127.0.0.1 serves these immutable assets under `/app/`, mirrors production COOP/COEP/CSP for the app, and exposes explicit test-instance build provenance. It has no auth or billing service, no development bridges, and no public listener.

The browser permits only the localhost application and the documented public model/CDN hosts. Production app/auth/billing requests, local auth/billing requests, unexpected external origins, and unsafe redirects are blocked and fail the audit. No route fabricates a successful entitlement response. Each fresh browser uses language auto, full ASR, the ordinary OCR default, standard 720×1280/15 FPS exports, and the existing file-picker accommodation. Original sources and all actual outputs retain the existing encrypted evidence path.

Preparation and case handoffs have distinct purposes, exact repository/branch/run/attempt/case bindings, a 14-minute expiry and fresh RSA keys. The selected branch is `qa/examclips-stand45-2026-11-15`. Root owns URL/key creation and envelope publication, review, branch creation and dispatch. This directory contains only the local reviewable public harness overlay.

## Main differences from deployed-site testing

Authentication, quota/payment services, live deployment routing and the production network path are not exercised. Source processing/rendering code is unchanged. Localhost's manual OCR selector defaults to auto; the hosted selector defaults to tesseract. Neither audit invokes manual scene analysis. The automatic slide chapter pass calls recognizeEducationalFrame with its independent auto default in both builds; /api/local-ocr-capabilities returns 404 on both static hosts, so it falls back to browser Tesseract. No hidden control, product state or earlier analysis is modified. Models still download normally; sanitized model paths, input hashes, runner/browser versions and exact compiled engine asset hashes are recorded. Remote weight contents are not independently hashed by this harness, and unpinned upstream model files remain a fidelity limitation. The current commit is a direct billing-only child of 059bf36; selected processing and lockfile blobs match that parent. Actual semantic, visual and audio conclusions still require output review.


## Verification and retry contract

The local tests cover bundle/context/hash integrity, approved download origins and redirects, public-model HTTP methods, secret-free error formatting, safe ZIP extraction, static serving boundaries and isolation headers. The actual pinned CI archive was extracted successfully with all 18 app hashes verified. Local Chromium cannot start in this workspace because its singleton socket is denied with EPERM. The preparation job therefore runs a bounded normal-UI fixture before it uploads the shared encrypted bundle or releases the 45-case matrix. That fixture opens the app, imports a generated four-second H.264/AAC source, checks automatic language/full-ASR/standard output defaults, and reaches the ordinary start button without starting ASR. It is outside all lecture quality results.

The main entry bundle differs from production because this is the documented CI build without authentication configuration. Fourteen corresponding worker/runtime asset names were checked against the current live deployment: 12 were byte-identical, and two CI chunk names were absent at the production paths. The exact CI artifact and all served asset hashes are recorded; byte identity of the complete deployed application is not claimed.

The shared bundle AAD includes the preparation run attempt. A failed-case rerun with a different attempt cannot unlock an older preparation bundle. Retries require a fresh workflow run and fresh preparation handoff/key. The runner never relaxes this context binding or overwrites a prior shared artifact.
