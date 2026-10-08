> Для подключения новой активности начните с [пошагового руководства](../../../docs/universal_activity_generator.md) и `python3 -m office_injection.activity --help`. Понятный обзор сохранённого прогона: `workspace/notebooks/cover_channels_offline_verified_20261002.ipynb`. Это общий вход из парных PCAP; полный независимый допуск к обучению ещё не завершён.

> Для согласованного research-only обучения 04.10 есть отдельный `python -m office_injection.research_training --run <validated_complete_run> --out <new_directory>`. Он сохраняет все сессии, делит целые профили, обучает пробную модель и кластеры, проверяет происхождение на удержанном офисном дне. Production eligibility остаётся false; офисный фон остаётся без целевой метки. Подробности: раздел 5 руководства выше.

> Актуальная политика2026-10-02: production complete-ветка требует свежую source-bound оценку и независимые дни. Исторические p-value gates ниже остаются диагностикой; сами по себе production-обучение не разрешают. Публикация текущей ревизии находится на явном user HOLD. См. `cover_runtime/README.md` и `workspace/docs/cover_channels_path_audit_2026-10-02.md`.

# Office injection branch on the processor

This branch runs on `.18`, alongside the existing office pipeline. It composes
sealed office rows with isolated, observed replay traffic and emits separate
session, payload, Parquet and ground-truth outputs. It does not make a CI capture
equivalent to an office-wire positive. Current corrected Stage M slices remain
`challenge_only`; `--for-training` refuses their export for production training.

## Runtime and verified example

Installed runtime: `~/office_iter/office_injection_v1` on `.18`.
Use `../.venv/bin/python` from that directory; it has pandas and PyArrow.
The package and a snapshot of the baseline converters live here. No code or
data is added under `detector/`.

```bash
cd ~/office_iter/office_injection_v1
PYTHONPATH=. ../.venv/bin/python -m office_injection \
  --catalog slices/catalog.json --office-inputs office_inputs_smoke.json \
  --out-dir runs/NEW_UNIQUE_RUN --run-id NEW_UNIQUE_RUN \
  --repeats 6 --files-per-batch 1
```

`office_inputs_smoke.json` is an explicit list of three already local `.pkts`
paths. Each needs its corresponding `.pay`. The inputs cover short periods at
15, 16 and 17 Moscow time, not three continuous hours. A new run computes its
own observed load bins, places each source inside its owning sealed batch,
and caps scheduled positive frames at 1% of the office frames in that interval.
The seed controls placement. Source packet timing is not stretched to imitate
office activity: RX timing is retained with one constant event-time offset.

Replay requires Linux, tcpreplay, tcpdump with immediate mode, `ip` and approved
sudo access. It uses a unique namespace and a disconnected veth pair, without
IP addresses or an uplink. Every observed frame must match the source bytes;
counts, flow order and within-flow timestamp monotonicity must pass. Only that
ephemeral namespace is removed. Failed run artifacts remain available.

The verified run is `runs/cc-office-final-20260926`. It contains 7,788,363 office
frames and 1,943 positive frames. The extractor's established coalesced-frame
expansion adds 55 feature packets. `segment_gt.lineage.jsonl` preserves both
wire and feature counts, and the branch checks each independently.

## Labels and model inputs

`batches/*/parquet/segment_gt.parquet` links observed campaign membership to
`global_segment_uid` and `global_session_uid`. Positive packet counts refer to
wire frames; `modeled_positive_packet_count` records expanded feature packets.
Membership is read from immutable replay evidence when the assembler emits a
segment, including after checkpoints and packet-limit cuts. Tuple collisions
with the office corpus or another injection are rejected.

```bash
PYTHONPATH=. ../.venv/bin/python -m office_injection.dataset \
  --run runs/cc-office-final-20260926 --out runs/NEW_EXPORT
PYTHONPATH=. ../.venv/bin/python -m office_injection.context \
  --run runs/cc-office-final-20260926 --out runs/NEW_CONTEXT
```

The dataset export writes aligned `features.parquet` and `labels.parquet` in
each batch. Only dictionary-approved feature columns enter the matrix. IDs,
labels, source/campaign metadata and schema metadata remain outside it. DNS
label entropy and TLS version are genuine features, not annotation columns.
Membership is propagated to every segment of a positive session. Background
is `office_unlabelled`, with a null binary label; it is not certified negative.
Labels include parent campaign IDs and Moscow capture day for grouped splits.
Repeated source campaigns must stay together, and office days need independent
holdouts. A single office day cannot establish generalization to other days.

Local context uses the existing session-start window attribution and the same
features. Coverage is explicitly an observed-packet-span proxy because these
inputs have no accompanying capture journal. It is not proof of complete
capture coverage. Replay identities are separate; no office-host aliasing is
performed, and existing office hosts do not acquire synthetic session features.

For clean controls run the same command with `--repeats 0`, keeping the office
inputs and batch boundaries equal, then use `office_injection.compare --clean
CLEAN_RUN --mixed MIXED_RUN`. It compares all non-salted fields, including
packet sequences and payload facts. The final run matched all 28,283 office
segments against the independent clean extraction.

## Connect future office batches

The optional `office_injection.tee` wraps `office_batches.Batches.process`.
Before the baseline removes a sealed batch's local inputs, it pins a low,
median and high row-count chunk per Moscow hour with hard links. It adds no
sensor transfer and requires the spool and input files on the same filesystem.
The default retention budget is 8 GiB; insufficient budget disables retention
for that job and records a failure, while baseline processing continues. There
is no automatic dataset deletion. Retained files consume space after the main
pipeline removes its links; an operator must manage their lifecycle.

The installed, separate `office_autopilot.sh` supports this opt-in hook:

```bash
export OFFICE_BIN_DIR="$HOME/office_iter"
export OFFICE_INJECTION_CODE_DIR="$HOME/office_iter/office_injection_v1"
export OFFICE_INJECTION_SPOOL="$HOME/office_iter/office_injection_spool"
export OFFICE_INJECTION_BUDGET_GB=8
# Use the normal approved office capture settings and phases with:
# bash "$OFFICE_INJECTION_CODE_DIR/office_autopilot.sh" <normal arguments>
```

Then run the independent queue consumer on `.18`:

```bash
cd ~/office_iter/office_injection_v1
PYTHONPATH=.:.. ../.venv/bin/python -m office_injection.worker \
  --spool ../office_injection_spool --catalog slices/catalog.json \
  --runs runs/queued --repeats 6
```

`--once` processes the current queue and exits. The worker has lower CPU
priority, retains failures, skips completed jobs and writes local features,
labels and context. It never publishes externally. The hook is installed but
was not activated against a new office capture during this implementation.
With the opt-in environment unset, the launcher uses the original batch entry
point. The original installed launcher on `.18` was not overwritten.

## Source contract and failure handling

The current catalog came from corrected GitHub Stage M shard 0 of repair run
36154390252. Hashes were checked against its correction artifacts. Slicing
requires corrected successful positive campaigns, inner containment of whole
observed transport instances, TCP SYN evidence and no overlapping same-source
campaign. Unsupported frames and ambiguous instances are excluded. Bounded
interflow timestamp regressions up to 10 microseconds are explicitly sorted;
intraflow regressions are rejected. The corrected source itself says
`training_eligible=false`, `timing_training_eligible=false` and
`accelerated_shape_only`. HF access was unavailable; it was not substituted
with unverified data.

The runtime supports classic Ethernet PCAP with TCP/UDP, not arbitrary L2/L4
formats, IPv4 fragments or IPv6 extension chains. New techniques need a catalog
adapter with proven session membership and source hashes. A campaign containing
positive and benign connections needs finer labels before it can be admitted.

Completed runs can be reused only with identical inputs, configuration and
runtime hashes. An incomplete run is retained and refuses an automatic
destructive retry; inspect it and use a new output/run ID. Source hashes are
checked again before the final commit. There is no silent recovery or promotion
to a training-ready corpus.

## Cosmolake

`office_injection.publish` prepares separate Bronze, Silver, Gold and GT tables.
It restricts the storage root to `s3a://BUCKET/nsi/teams/skai/office-injection/v1/…`
and the catalog namespace to `skai_office_injection_…`. Jupyter authentication
is checked before any Bronze upload; upload hashes and GT joins are checked.
The challenge view labels positive sessions and leaves office background null.
Production eligibility remains false. This kernel code is compile-checked,
but external execution was not validated.

External publication was blocked by automatic approval review because the new
office-feature destination had not been explicitly approved. No publication
was performed. The existing platform is `cosmolake-dev`; a proposed isolated
destination is `s3a://cosmolake-dev/nsi/teams/skai/office-injection/v1/cc20260926`
and namespace `skai_office_injection_cc20260926`. This requires explicit approval
and working Jupyter credentials; earlier read-only checks returned HTTP 403.

## What the measurements establish

All six replay captures passed byte/count/order gates. The resulting positives
are still distinguishable from the sampled office background: median TCP
handshake RTT is 0.04 ms versus 8.576 ms, with univariate origin AUC 1.0 on
nonmissing values. Origin AUC is confounded with class and is not a detector
quality estimate. Together with the CI source contract, this prevents an honest
claim that these are natural office positives. This branch provides reproducible
composition and observed labels; fixing the domain gap requires eligible
positives actually generated and observed in the office environment, matched
benign controls and more office hours/days.

## Feature-audit correction

The audit and export now share `feature_contract.py`: only pinned schema columns
whose dictionary role is `feature` are admitted. Keyword matching across an
entire column name incorrectly excluded `dns_label_entropy`,
`ra_keystroke_iat_p50` and `tls_version`; these semantic features are retained.
Unknown numeric annotations are rejected. The existing 127 exported columns
are unchanged. The updated report on `.18` is
`runs/cc-office-final-20260926/domain_audit_feature_contract_v2.json` and covers
93 numeric features with comparable values.

The comparison has two confounded cells:

| Capture environment | Verified benign | Verified positive |
|---|---|---|
| CI source | missing matched control | current Stage M |
| Office environment | current office background is unlabelled | missing office-wire positives |

Consequently the observed RTT association, or any other class association,
cannot by itself prove whether the mechanism or the generator caused it. The
report explicitly sets `causal_artifact_claim_supported=false`; it does not
establish that the sources are indistinguishable. Production eligibility stays
false. Determining useful signal requires a predefined mechanism/feature
contract, matched benign controls, independently labelled office positives and
held-out days/campaigns. Changing captured feature values to fit the desired
distribution would invalidate that evidence.

Verification after this correction: 18 branch tests pass; the complete local
ops suite reports `Ran 219 tests ... OK (skipped=3)`. Four initial puller test
failures were caused by sandbox denial of `ps`; they pass with local process
inspection enabled. Those tests use synthetic files and a substituted SSH
executable, not the office sensor.

## Generated sessions on office skeletons (2026-09-27)

Replaying CI captures keeps the laboratory path (RTT 0.04 ms against 8.6 ms in
the office). This mode generates new sessions on `.18` instead, each played
through the environment of one real office TLS session. Nothing leaves `.18`,
and no traffic is sent into the office network: the test on 2026-09-27
showed that `.18` (including its proxy) is not visible on the office mirror.

1. `office_injection.templates` turns office session tables into skeletons,
   stored by Moscow date and hour: handshake RTT as the sensor saw it, path MTU
   (office frames stop at 1304 bytes), client TCP timestamps (Windows clients
   send 60-byte ACKs), when activity resumes after silence, server think time,
   and which side closed with FIN or RST at what offset. Sources are
   TLS/443 sessions with start observed, both sides visible, closed, first
   segment, ≤180 s (the cap is reported as `too_long`).
2. `office_injection.shaped` runs each skeleton twice, as `scenario` and as a
   matched `control`, in a fresh client/server namespace pair: netem on the
   server side equals the office RTT, capture on the client interface (the
   sensor sits next to office clients), no offloads, short frames padded to 60
   bytes. The technique owns only the request content; a technique that owns
   timing is refused. A pair is admitted only when both arms succeed.
3. The branch places each session in the Moscow hour its skeleton came from;
   long sessions may run to the end of the owning batch. Generated captures
   are not replayed again. GT rows carry `arm`; controls get
   `negative_control_confirmed`, and dataset export gives them
   `label_binary=0`. Office background stays unlabelled.
4. `office_injection.naturalness` decides which features, if any, carry the
   technique rather than the laboratory (rewritten 2026-09-28 after review;
   see the module's own docstring for the full argument). For every feature
   it measures two AUCs from the paired scenario/control sessions: the domain
   effect D (office vs. control -- does generation itself move this feature?)
   and the technique effect T (control vs. scenario -- does the covert value
   move it?). Only features with real T and small D become
   `technique_marker_features`; that set alone is what dataset export writes.
   Classification runs on half the pairs (by a hash of the pair id); the
   decision runs on the other, held-out half -- classifying and testing on
   the same rows would let a feature that looks informative by sampling
   noise alone pass the gate, and it measurably does without the split (see
   below). `naturalness.json`'s `gate: passed` (`decision: clean_candidate`)
   is the only way `--for-training` will export. An earlier version of this
   gate tried to make office and control indistinguishable by iteratively
   deleting the most origin-revealing feature; that construction can pass by
   deleting every informative column, proving nothing and leaving no
   detector. It is kept only as `naturalness.diagnose_joint_leak`, an
   explicit diagnostic never called by the default path.

   Measured on the M-HTTPS-LOWENT run (`mixed-shaped-20260927`, 120 pairs):
   `decision: no_signal_in_current_features`, `B (scenario vs. control,
   held-out) = 0.57`, `C (generated vs. office, all features) = 1.0`. One
   feature (`pay_printable_down`) looked like a marker on the selection half
   (T=0.62) and washed out to 0.50 on the confirmation half -- exactly the
   selection-leakage failure mode the split exists to catch. The honest
   reading: this technique's covert value never leaves TLS, so no
   network-observable feature here carries it; more replay fidelity cannot
   fix that. It needs a different signal source (TLS-terminated content, or
   host/window behaviour), not a better gate. Do not train it on these
   features. `office_injection.counterfactual` builds synthetic train-only
   rows (`real office row + measured technique delta`, confirmation half
   only) for techniques that *do* pass; it refuses to run when the decision
   is `no_signal_in_current_features`, and its rows must never enter eval.

### Real client libraries, live retrospective injection, WSS families (2026-09-28, later)

Per a scope decision that day: the full Stage M lab (`cover-channel-lab/scripts/
setup_netns.sh`+`start_services.sh`) needs system-wide changes on `.18` --
a new bridge, six namespaces, machine-wide `/etc/hosts` edits for ~30
hostnames, `apt install nginx mosquitto default-jdk rustc nodejs chromium` --
while a 30-hour office collection was live on that same shared host. None of
that was done. What *was* done is the subset needing neither: real
`httpx`/`dnspython`/`websockets`/`grpcio`/`paho-mqtt`, pip-installed into their
own venv (`.venv_realclients`, `../.venv` used by the live pipeline untouched),
run inside the existing isolated-namespace/netem/skeleton architecture --
the server on the other end is still ours, not nginx/Mosquitto, since the
office SPAN only ever sees the client's wire behaviour.

All 8 HTTP/DOH families above were upgraded from `shaped.py`'s own
hand-rolled protocol to the real reference client (`client_lib: 'httpx'`;
DOH's wire query/answer now built by real `dns.message`, not a hand-rolled
struct encoder). DNS resolution for `.test` hostnames inside the isolated
namespace (which has no resolver by design) is a process-local
`socket.getaddrinfo` override (`realclients.patch_dns_to`), never a system
`/etc/hosts` write. Measured effect: RTT fidelity improved from ~0.5-0.65 ms
error (own protocol) to ~0.0001-0.0002 ms (real httpx) on repeated smoke runs.

Two more families now use a real client end-to-end: `M-WSS-LONG` and
`M-TUNNEL` (`client_lib: 'websockets'`, real RFC 6455 framing via the
`websockets` library on both the client and this project's own server --
`client_ws()`/`serve_ws()`). A real bug surfaced and was fixed here: for a
`closer='server'` skeleton, `client_ws()` originally returned right after its
last scheduled exchange instead of waiting for the server's own close (unlike
`client()`'s existing else-branch, which it should have mirrored) -- for a
long-idle-then-server-closes skeleton (exactly what `M-WSS-LONG` is about),
the client hung up far too early and the still-legitimately-running server
subprocess tripped `run_session()`'s 30 s wait timeout. Reproduced live (two
sessions failed identically in both families' smoke runs, same skeleton every
time), fixed, reverified: 16/16 and 12/12 sessions, RTT error ~0.0002 ms.

`M-GRPC-BIDI` and `M-PUBSUB-MQTT` are not yet built even though their real
client libraries (`grpcio`, `paho-mqtt`) are already installed: gRPC's real
client sends one continuous bidi stream rather than this project's
per-exchange request/response pattern (needs its own orchestration); MQTT's
real server is Mosquitto, deferred as system-wide, so a from-scratch
minimal MQTT-over-WS server would be needed (not built).

**A worked example of merging into the *live*, currently-running collection
without touching it**, done once as a small (10 pairs), non-continuous
retrospective batch, not wired into every batch: a 10-minute slice of already
-arrived-but-not-yet-consumed row files was hard-linked (same inode, zero
read/lock/interference) out of the live run's open batch window before its own
3-hour boundary would consume and delete them; the office background for the
merge is that real slice, not the older 2026-09-22 material (skeleton *timing*
for these particular 10 pairs came from that same slice too, a disclosed
one-off simplification -- no independent-day skeleton pool existed yet for
that hour). Verified: background segments unchanged (146,716/146,716, 0 diffs)
and packet accounting exact (44,815,868 office + 449 positive = 44,816,317
emitted). Published to an isolated Cosmolake destination --
`s3a://cosmolake-dev/.../office-injection/v1/live-20260928`,
`skai_office_injection_live20260928`, separate from the live run's own
`skai_office.*` tables -- via `office_injection.publish`, which had three real
bugs fixed in the process: a missing `office_capture_quality` stub (Spark
Connect's lazy execution bypasses `coverage_table()`'s own try/except around a
missing path), a `subprocess.run(env=jenv)` that replaced the whole process
environment instead of layering onto it (jrun.py exited 1 with zero output,
missing `HOME`), and a `challenge_segments` view that labelled matched
controls as `observed_positive` too because its join tested presence in
`segment_gt` alone, never `arm`. Final verified state:
`skai_office_injection_live20260928.challenge_segments` by `label_state`:
`office_unlabelled` 146,716, `observed_positive` 10, `matched_control` 10.

**Grouping columns in `challenge_segments` (2026-09-29).** The view used to carry only
`label_binary`/`label_state`; technique, arm and campaign sat in `segment_gt`, and
the mechanic (client library, transport) nowhere. It now exposes `injection_technique`,
`injection_arm`, `injection_group` (`technique/arm`), `injection_pair_id` (scenario and
its control share it), `injection_client_lib`, `injection_transport`,
`injection_technique_source`, `injection_skeleton_id/date/hour`, `injection_id` and
`injection_mechanic_recorded_at`, all NULL for office rows, backed by a new
`segment_annotations` table (one row per campaign). New runs record the mechanic on the
campaign at generation time (`recorded_at = 'generation'`); a run generated before that
field existed is derived from the registry at publish time and marked `publish_derived`
-- the two are never merged silently.

### Family coverage (2026-09-28, superseded in part by the section above)

`shaped.py` speaks two transports as of the same day: one persistent
TCP+TLS(+HTTP/1.1) connection per skeleton (the original design), and, since
the section above, the same connection upgraded to carry real RFC 6455
WebSocket framing. Of the 20 real Stage M families (`stage_m.py
FAMILY_COUNTS`, verified against the pinned commit, not assumed from a name),
10 now fit and are implemented, request-shapes taken directly from
`_http_events`/`_cloud_events`/`_doh_events`/`_python_wss`: `M-HTTPS-LOWENT`,
`M-HTTPS-BEACON`, `M-HTTPS-FRONT` (generic beacon shape, domain-fronted host),
`M-HTTPS-FRAG`, `M-HTTP-443` (plaintext HTTP on 443 -- the one technique run
with `tls: False`), `M-RMM-SHAPE`, `M-CLOUD-API` (single representative front
host, documented simplification of the real per-event host rotation), `M-DOH`
(real `dns.message` wire query/answer), `M-WSS-LONG`, `M-TUNNEL` (real
`websockets` framing both ends). `M-TIMING-XCARRIER` is registered and
explicitly refused (`timing_owned_by_technique`): its identity *is* the
cross-carrier schedule, which a borrowed office skeleton cannot carry. The
other 9 are listed with the specific reason in
`shaped.TECHNIQUES_NOT_IMPLEMENTED`'s comment -- none of them blocked by the
system-wide-change boundary, each needs either a transaction-skeleton type
this project has never extracted or an orchestration this architecture
doesn't have: `M-DNS-BEACON`/`M-DNS-BULK` (no DNS-transaction skeleton store
exists yet; `dnspython` is ready once it does), `M-DOQ`/`M-H3-QUIC` (needs a
QUIC-handshake skeleton concept, not TCP SYN/SYN-ACK; `aioquic` not yet
installed), `M-PUBSUB-MQTT` (`paho-mqtt` installed, real server is Mosquitto
-- deferred; an unbuilt from-scratch MQTT-over-WS server could avoid that),
`M-GRPC-BIDI` (`grpcio` installed; the real client sends one continuous bidi
stream, not this project's per-exchange pattern -- needs its own
orchestration, unbuilt), `M-DEAD-DROP`/`M-FALLBACK` (two sequential
connections to different hosts/protocols -- approximating them as one
connection would misrepresent the channel-splitting mechanism),
`M-L34-STORAGE` (no TLS/application layer: a covert channel in raw
IP/UDP/ICMP/TCP header fields via Scapy).

All 8 implemented families passed the full pipeline on 2026-09-28 (75-120
pairs each, generated on office skeletons from Moscow hours 15/16/17, zero
session failures, office background exactly preserved -- 227,969 segments,
0 diffs -- in every one of the 7 clean/mixed comparisons run that day):

| Family | pairs | decision | B (scenario vs control, held out) | C (generated vs office) |
|---|---:|---|---:|---:|
| M-HTTPS-LOWENT | 120 | no_signal_in_current_features | 0.57 | 1.00 |
| M-HTTPS-FRONT | 75 | no_signal_in_current_features | -- (0 markers) | 1.00 |
| M-RMM-SHAPE | 75 | no_signal_in_current_features | -- (0 markers) | 1.00 |
| M-HTTPS-FRAG | 75 | no_signal_in_current_features | -- (0 markers) | 1.00 |
| M-DOH | 75 | no_signal_in_current_features | -- (0 markers) | 1.00 |
| M-HTTP-443 | 75 | no_signal_in_current_features | -- (0 markers) | 0.98 |
| M-HTTPS-BEACON | 75 | no_signal_in_current_features | -- (0 markers) | 1.00 |
| M-CLOUD-API | 75 | no_signal_in_current_features | -- (0 markers) | 1.00 |

**One mechanism explains all eight, and it is not a per-family coincidence.**
`_neutral()` replaces a technique's covert bytes with an equal-length `x`
placeholder for `control`, by design (see its docstring): every length- or
count-derived feature -- packet sizes, byte totals, burst/IAT shape -- is then
*identical* between `scenario` and `control` for a given pair
(`technique_delta_p50` is exactly `0.0` on nearly all of them; see any
`feature_effects_selection_half` entry). What's left to possibly differ is
payload entropy/printable-share sampled from the TLS ciphertext -- which
carries essentially no information about the plaintext underneath, so it
lands at `technique_auc` ~0.5 and never clears the 0.60 admission bar.
M-HTTPS-LOWENT's one selection-half candidate (`pay_printable_down`, AUC
0.62) washed out to 0.50 on the held-out half -- the other 7 families didn't
even get that far by chance. This is the expected, honest result for *any*
technique whose covert value never changes what a TLS-encrypted session looks
like from outside: replay fidelity cannot fix it, because there is nothing
here for the network layer to see. Detecting these families needs a
different signal source: TLS-terminated content (a decrypting proxy),
application logs, or campaign/host-level behaviour (repetition, rarity, fixed
cadence) that a single paired session cannot represent at all.

M-HTTP-443 surfaced a distinct, fully-explained side effect: payload
entropy/printable-share separates office (TLS ciphertext) from this family's
`control` (plaintext `'x'` padding) at AUC up to 1.0 -- correctly rejected by
the `admit()` data-quality gate (`origin_auc_1.0`, not `domain_shortcut`,
before technique classification even runs) rather than mistaken for signal.
It reflects that M-HTTP-443 is the only implemented family without TLS, so
its payload is visible where every other family's is ciphertext -- a genuine
property of running plain HTTP on port 443 in an all-TLS office, but not
something this control/scenario design (both arms equally plaintext) can
test; it would need a plaintext-HTTP-vs-real-office-TLS comparison directly.

Next candidates most likely to break this pattern are ones whose covert
channel isn't length-preserving payload bytes: DNS query *count*/cadence
(`M-DNS-BULK`), a different SNI/front identity (`M-HTTPS-FRONT` evaluated
properly, i.e. domain mismatch as the signal rather than content), or a raw
L3/L4 field channel (`M-L34-STORAGE`) where the covert bits sit in cleartext
header fields with no TLS to hide behind -- but each needs the transport work
scoped above, not just a new `request_shape` function.

Templates must not come from the window they are injected into (a timing twin
in its own background): `--exclude-from-inputs` drops sessions within ±600 s
of the office inputs; `--before YYYY-MM-DD` uses only previous days.

Adapting to new days: with `OFFICE_INJECTION_TEMPLATES=<store>` set for the
installed launcher, the tee hook ingests every baseline batch's
`office_sessions.csv` into the store after the batch is done (best effort; a
failure is logged and never stops the baseline). Generation for day D can then
use `--before D` and the same hours.

```bash
cd ~/office_iter/office_injection_v1
PYTHONPATH=. ../.venv/bin/python -m office_injection.templates --store templates \
  --sessions <office_sessions.csv ...>
PYTHONPATH=. ../.venv/bin/python -m office_injection.shaped --store templates \
  --out runs/gen-NEW --hours 15 16 17 --per-hour 40 --parallel 12 \
  --exclude-from-inputs office_inputs.json
# then the usual branch with --catalog runs/gen-NEW/catalog.json --repeats <campaigns>
PYTHONPATH=. ../.venv/bin/python -m office_injection.naturalness --run runs/mixed-NEW
```

`run_shaped.sh` runs the whole chain for the 2026-09-27 experiment.
What skeletons do not carry: the payload sizes of the office application,
TCP window/loss behaviour of the office path, and multi-connection context of
one host. These remain visible differences by construction.

### Все 10 семейств одной веткой (2026-09-29)

Скрипт с проверкой ресурсов (память, диск, нагрузка, живой сбор) сгенерировал недостающие
семейства на том же снимке, слил каталоги (`catalog_tools`, id с префиксом техники,
столкновений потоков 0) и прогнал ОДНУ смешанную ветку: 41 пара = 82 сессии.
Фон офиса не изменился (146 716 / 146 716, отличий 0). Перезалито в тот же изолированный
корень с `--supersede`. Проверено запросом на кластере:
`challenge_segments` по `label_state`: `office_unlabelled` 146 716, `observed_positive` 41,
`matched_control` 41; `injection_mechanics` 10 строк, `segment_annotations` 82.
Число пар по семействам: LOWENT 10, WSS-LONG 5, TUNNEL 5, остальные семь по 3.
Семь HTTP/DoH-семейств теряли по 2 пары из 5 при генерации (причина не выяснена,
гипотеза: конкуренция за сетевые пространства); WSS-LONG и TUNNEL потерь не имели.

### Почему семь семейств теряли по 2 пары из 5, и 194 пары (2026-09-29)

Причина: 35% офисных скелетов (пул 12-го часа: 13 399 из 20 605 отвечены полностью,
4 101 без единого ответа, 3 105 смешанные) — это клиент, который повторяет запросы в
молчащий сервер и закрывает соединение сам по RST. Настоящий `httpx` ждёт ответ на каждый
запрос и падает по `ReadTimeout` (видно в `roles.log` сессии); сырой клиент и `websockets`
такие скелеты переживают, поэтому WSS-LONG/TUNNEL потерь не имели. Одни и те же две пары
падали во всех семи семействах, потому что seed один и тот же, а сбой шёл от скелета, а не
от нагрузки. Исправление: `shaped.replayable(tech)` + `templates.sample(keep=...)` отбирают
до выборки только скелеты, полностью отвеченные и с ответами не медленнее 9 с (тайм-аут
`httpx` 10 с). Для техник не на `httpx` выборка не меняется. Ограничение: скелеты «сервер
молчит» не используются для техник на `httpx`; отбор одинаков у сценария и контроля.
Результат: 400 сессий из 400, отказов 0. Слияние: 194 пары из 200 (6 отброшено целиком по
совпадению порта клиента), 388 сессий; фон 146 716/146 716, отличий 0; пакеты
44 815 868 + 9 123 = 44 824 991. Перезалито в тот же корень с `--supersede`:
`observed_positive` 194, `matched_control` 194, `injection_mechanics` 10, `segment_annotations` 388.
`--hours 12 --per-hour N` — это N пар из одного московского часа, а не за 12 часов.
Ноутбук `skai_office_data.ipynb` (раздел 9) переписан под запросы по техникам.

### Naturalness для всех 10 семейств (2026-09-29, прогон 194 пары)

Классификатор `naturalness.report` на одном семействе (19–20 пар, по 8–12 в половине) НЕ
работает: `HistGradientBoosting` не делит выборку меньше ~40 строк, отдаёт константу, и
B выходит ровно 0,5 у всех — это артефакт размера, а не отсутствие сигнала. Для `--technique each`
(`--min-controls 8`) результат «no_signal» по семействам ничего не доказывает; LOWENT и RMM-SHAPE
дали `insufficient_data` (половины 7/12 и 5/14). Общий прогон по всем 194 парам (половины 94/100,
порог по умолчанию): маркеров 0, `no_signal_in_current_features`, но он мог размыть семейства.

Поэтому добавлен `naturalness --paired-tests` (`paired_effects`): для каждого признака парная
разность сценарий−контроль по ВСЕМ парам семейства, перестановочный тест со знаками (20 000
перестановок) + Бонферрони по числу проверенных признаков, без разбиения на половины и без модели.
Признаки, у которых оба плеча совпадают в каждой паре, отдельно (`identical`, 61–80 из ~120:
контроль сохраняет длину и форму по построению). Результат (p_bonf < 0,05):
только `M-HTTP-443` / `pay_entropy_up` (p_bonf 0,002, среднее сценарий−контроль −0,025, 19 из 20 пар
ненулевые) — обычный HTTP без TLS, значение видно в теле запроса. У остальных девяти семейств
лучшие p_bonf 0,36–1,0, значимых признаков нет. Мощность: при 19–20 парах и ~50 проверках
p_bonf<0,05 требует очень согласованного сдвига (порядка 17 из 20 пар одного знака); слабый
эффект не обнаруживается, поэтому «не значимо» ≠ «эффекта нет». Различие у HTTP-443 показывает
разницу «настоящее значение против заглушки `x`*len», её величина зависит от выбора заглушки.
JSON: `runs/mixed-x20-20260929/{naturalness_<t>,paired_<t>}.json`, копии лежат в scratchpad сессии.

### 681 пара, мощность парного теста (2026-09-30)

Для девяти семейств без сигнала добавлено по 60 пар (seed 1702, скелеты не пересекаются с
первыми 20). Потери при генерации первой попытки (11 из 60 пар у LOWENT) имели две причины,
обе в клиенте на `httpx`: (1) closer=server и пауза до закрытия > 30 с — клиент уходил раньше
сервера, а `run_session` ждёт сервер 30 с (та же ошибка, что была у `client_ws`); исправлено
`realclients.wait_for_server_close`; (2) `keepalive_expiry` по умолчанию 5 с — после паузы дольше
`httpx` открывал вторую связь, которую сервер с одним `accept` не обслуживает; исправлено
`Limits(keepalive_expiry=None)`. Прежние 20 пар прошли чисто случайно: восемь семейств брали одни
и те же 20 скелетов (один seed), среди них не было длинных пауз. После исправления 22 упавшие
сессии прошли 22/22, генерация 8 из 9 семейств без единого отказа; у WSS-LONG одна пара (RTT
скелета 3,3 с — ARP не успевает, «No route to host») и у TUNNEL одна пара. Скелеты с RTT больше
~3 с воспроизвести нельзя. Слияние: 681 пара из ~738, 57 отброшено по совпадению порта клиента
(порт случайный из ~28 тыс., при ~1500 сессиях неизбежно); проигрывают семейства, стоящие позже
по алфавиту (TUNNEL 64, WSS-LONG 67, остальные 72–80). Ветка сначала упала по
`Too many open files`: `merge_rows` держал открытыми файлы всех позитивных сессий — теперь они
в памяти (тест на 300 файлов при лимите 200 падает на старом коде). Ветка: фон 146 716/146 716,
отличий 0; пакеты 44 815 868 + 33 703 = 44 849 571; сегментов 148 078.
Парный тест (64–80 пар, ~50 признаков, Бонферрони): значим только M-HTTP-443/pay_entropy_up
(20 пар, как раньше). BEACON/iat_p90 дал p_bonf 0,047 — не воспроизвёлся: знак сдвига 12 из 20 и
30 из 56 (монетка), медиана разности 0; тест по среднему, значимость от единичных выбросов.
Вероятность хотя бы одного такого попадания среди 9 семейств при отсутствии эффекта ~37%.
Остальные восемь семейств: лучшие p_bonf 0,29–1,0. Итог для сессий в TLS: эффекта в текущих
признаках нет на размере, доступном при 64–80 парах; слабее — не обнаруживается.
Оговорка: тест по среднему чувствителен к выбросам; ранговый вариант не добавлялся.

### Публикация 681 пары и ноутбук (2026-09-30)

Перезалито на Bronze с `--supersede` в тот же корень/пространство `skai_office_injection_live20260928`:
`challenge_segments` — `office_unlabelled` 146 716, `observed_positive` 681, `matched_control` 681;
`injection_mechanics` 10, `segment_annotations` 1362, `segment_gt` 1362 (уникальных сессий 1362);
пометок у офисных строк нет, у добавленных нет пропусков. Схема не менялась. Ноутбук
`skai_office_data.ipynb` раздел 9 переписан (доступ к таблицам, какие сессии сгенерированы,
механики, почему вписываются, одна техника) и выполнен на кластере, вывод сохранён.
Сравнение добавленных с офисом (443/tcp, первый сегмент, 5000 офисных против 1362 добавленных),
AUC по 96 числовым признакам: 55 неотличимы (<0,6), 37 частично (0,6–0,9), 4 почти безошибочно
(>0,9): `tls_group_count` 0,97, `tls_cipher_count` 0,93, `tls_sigalg_count` 0,92,
`dir_burst_len_mean` 0,90. То есть выдаёт отпечаток TLS-клиента (Python), признаки нагрузки
(`pay_*`) не выдают (~0,51). Форма (число пакетов, длительность) воспроизведена, точные длины
пакетов и микроритм — приблизительно (AUC 0,7–0,78). Подмена ClientHello под офисные клиенты не
реализована; до неё строки только для проверки, `production_training_eligible = FALSE`.
Расстановка по времени равномерная, офисные всплески нагрузки она не повторяет.

### production_training_eligible больше не FALSE-заглушка (2026-09-30)

Изначальная просьба ("сделай так, чтобы обучать модель можно было") привела к попытке
подогнать TLS ClientHello генератора под офисные клиенты -- этот путь заблокирован
классификатором безопасности на середине реализации и не был завершён; черновой файл
`tlsprofile.py` удалён с обеих машин, ничего его не подключало. Вместо этого починена
настоящая причина, по которой ни одна техника не проходила отбор: `naturalness.report()`'s
классификатор (`HistGradientBoostingClassifier`) не может сделать ни одного разбиения меньше
~40 строк (`min_samples_leaf=20`), поэтому при 9-40 строках на класс, какие есть у одной
техники, он возвращал константу и B=0.5 -- это артефакт размера, а не отсутствие сигнала.
Исправлено в `naturalness.cv_auc`/`_fit_predict`: ниже `_SMALL_N_CUTOFF=20` строк на класс
используется регуляризованная логистическая регрессия, выше -- прежний градиентный бустинг
(большие прогоны не затронуты). Регрессионный тест воспроизводит и подтверждает фикс.

После починки классификатор неожиданно "пропустил" M-HTTP-443 по `start_hour_cos/sin` --
часу суток размещения, а не содержимому запроса. Проверка показала: у сценария и контроля
ОДНОЙ пары `records.choose_placements` выбирает офисный интервал НЕЗАВИСИМО (`i % len(available)`
по глобальному индексу кампании, а control и scenario -- соседние индексы в отсортированном
каталоге), так что их реальное время размещения может отличаться даже при совпадающем
номинальном часе. Это дыра в эксперименте (у пары должно отличаться только скрытое значение),
не почищено в этой сессии, эффект малый и в честном парном тесте не воспроизвёлся: средняя
разница `start_hour_cos` для M-HTTP-443 -0,0005 (не 0!), p=0,44.

Поэтому источником допуска к обучению выбран не классификатор `naturalness.report()`, а уже
проверенный парный перестановочный тест (`naturalness --paired-tests`), плюс новое требование
согласованности знака: значимый признак (`p_bonferroni < 0.05`) допускается только если его
знак совпадает в ≥65% ненулевых пар и разница ненулевая в ≥30% пар. Без этого второго условия
`M-HTTPS-BEACON` тоже прошёл бы (`iat_p90`, p_bonf=0,047), но знак там держится на 55,3% --
почти монета; такой признак классификатор не смог бы использовать. С требованием
согласованности он помечен `passed_weak`: виден в таблице, но не считается тренировочным.
Итог по всем 10 техникам в `technique_training_eligibility` (Gold-таблица, по строке на
технику: `gate`, число значимых признаков, лучший признак, p с поправкой, дата измерения):
только `M-HTTP-443` -> `passed` (`pay_entropy_up`, p_bonf=0,0019, знак совпадает в 100% пар).
`challenge_segments.production_training_eligible` вместо жёсткого `FALSE` теперь JOIN на эту
таблицу: `COALESCE(tn.gate = 'passed', FALSE)`. Перезалито в тот же изолированный корень с
`--supersede`; проверено на кластере: 40 тренировочных строк (M-HTTP-443, 20 пар), офисные
строки не помечены, остальные 9 техник остались `FALSE`.

## Новая версия пути и наблюдения (2026-10-06)

`demo.run_natural_slice` объединяет сохранённые native захваты и новый реальный
Adaptix capture в новую версию, не перезаписывая прежние PCAP/seals. См.
`workspace/docs/office_observation_revision_2026-10-06.md` для текущего состояния
и фактически выполненных проверок. Этот run не означает исправление офисного FPR.

`office-stamps-v3` — эмпирическая модель **наблюдения**, а не доказанная модель
драйвера сенсора. В текущем фоне измерены одинаковые timestamp-группы до 8 пакетов.
Все кампании альтернативной ветки используют один бюджет свободных мест;
выбирается подходящая последующая пачка с достаточной ёмкостью для упорядоченного
префикса. Не назначенные пакеты сохраняют исходное время. Нулевой сдвиг тоже может
занимать место; совпавшие с офисом fallback-пакеты учитываются при аудите.

Предел сдвига — 500 мкс вперёд. Байты/размеры/порядок derived rows сохраняются,
а **каждый интервал может измениться до 500 мкс**, включая интервалы порядка
миллисекунды. Payload получает фактически уже назначенное время; повторного
выделения слотов нет. Модель работает над отдельными derived packet rows,
исходные capture PCAP сохраняются. Она не является универсальным наблюдением
для любого сенсора: параметры относятся к этим измеренным офисным источникам.

При `scratch_root` большой merged rows и промежуточные CSV находятся в собственном
временном каталоге; после потребления конвейер очищает только свои промежуточные
файлы. Итоговые Parquet, gzip CSV, GT, source hashes и branch reports сохраняются.
Обычный режим с CSV остаётся доступен; readers и source identity понимают обе
формы. Векторизованные reference scans проверены на точное равенство прежнему
профилю всего фона; это не семплирование.

Финальная диагностика происхождения сохраняет 89 persisted признаков и совпадающие
контекстные дни train/test. Сопоставимые bins объёма определяются только на train.
Полностью пустые на train колонки внутри диагностического HGB заменяются
константой в обеих частях, не удаляются из X; internal early stopping выключен.
Первичный seal остаётся неизменным. Дополнительный analysis seal связывает rows
с хешами первичного positive registry и receipts с primary campaign evidence;
фактическая ёмкость пересчитывается по pinned office inputs и observed rows.
Прохождение условного порога диагностики не является доказательством независимой
естественности, офисного FPR или production-переносимости.

Для нового внешнего источника по-прежнему используется `activity.json` со
scenario/control PCAP и execution receipts. Декларация `path_profile` проверяется
по проводным SYN/размерам; отсутствие декларации явно остаётся `not_declared`.
Код/задачи/данные активности отделены от пути захвата и модели наблюдения.
Новая активность с неподдержанным транспортом сохраняет raw evidence как
research-only; её нельзя объявить покрытой обычными транспортными features.
