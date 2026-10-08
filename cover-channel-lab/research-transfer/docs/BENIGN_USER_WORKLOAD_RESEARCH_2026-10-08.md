# Office workload fidelity: literature, diagnosis, and an evidence-first implementation path

Date: 2026-10-08. Scope: **authorized benign background traffic**, not covert
transport adaptation, C2 camouflage, or an NDR-evasion benchmark optimizer.

## Why the existing controls fail

The 64-control experiment generates complete PCAPs using actual stacks, but
the control unit is still a network scenario/profile, not an office user's
multi-application work session. Tuning individual IAT, payload sizes or flow
durations does not recreate application-level causality. Better fidelity of
one feature does not imply joint-distribution fidelity. An AUC near 1 is a
hard failure, not a score to be hidden or reweighted.

Evidence:
- 64 controls passed PCAP structural audit.
- 2026-09-22 vs 2026-09-28: transport C2ST AUC 0.56138 (60 features).
- Generated controls vs those days: 0.9998255 and 0.9997360.
- All 8,002 released office rows passed sequence length vs packet-count audit.
- TLS data are absent for day 22; day 28 is partly measured.
- Office network mirror point, endpoint OS population and TLS-interception
  state are not documented. An unauthenticated GitHub-hosted Windows runner
  is therefore not a faithful office client.

## Literature

1. **User Behavior Based Traffic Emulator (UBE)**, Computer Networks (2016):
   derives scenarios from users' real application behavior, replays benign
   application actions, captures *real* resulting conversations, and
   validates against operational network traffic.
   https://www.sciencedirect.com/science/article/abs/pii/S1389128615003461

2. **NetShare**, ACM SIGCOMM 2022: GAN-generated packet/flow headers; focuses
   on scaling, realistic distributions and privacy. Not proof of true
   user actions, TLS sessions, or replayable application semantics.
   https://github.com/netsharecmu/NetShare

3. **NetDiffusion**, ACM SIGMETRICS/POMACS 2024: diffusion with protocol
   constraints to make packet-level synthetic traces compatible with network
   tools. Useful as a research comparator; not a substitute for having a
   real application's TLS stack and stateful transactions.
   https://arxiv.org/abs/2310.08543

4. **NetDPSyn**, ACM IMC 2024: privacy-aware synthesis with differential
   privacy; teaches that anonymization and synthetic output alone do not
   guarantee safety from record linkage.
   https://arxiv.org/abs/2409.05249

5. **D-ITG**: draws packet sizes and inter-departure times from configured
   statistical processes, useful for load testing, not by itself sufficient
   for office browser/cloud state and authentic TLS behavior.
   https://dis-srv01.dis.unina.it/software/ITG/manual/

## Architecture: benign user-workload emulator (UBE)

### 1. Capture and reference contract

Keep the existing read-only office extracts. Require capture topology,
OS/application inventory at **aggregate and consented** level, port/protocol
mix and annotation of whether TLS is observed before or after interception.
Store *only approved aggregate* app categories, not tokens, private URLs,
identifiers or office raw payloads. Never infer application shares from the
destination port alone.

### 2. Application activity, not synthetic packet injection

Isolated authorization-controlled fixtures should exercise ordinary,
stateful actions: web page navigation and follow-on assets; editing dummy
documents with version reads; collaboration interactions using test data;
authorized dummy file synchronization. Reuse real browser and OS HTTP/TLS
implementations. Record only responses, task completion and packet capture
integrity. No covert control channel, beacon profile or target-domain
impersonation belongs in this emulator.

Application workflow `open -> view -> edit -> save -> refresh` has causal
semantics that an independent packet/size/interval sampler cannot reproduce.
Use explicit human workload categories, and reject plans that name unapproved
external destinations or read real user content. All generated documents
and messages must be disposable fixtures.

### 3. Environment parity

Keep observed PCAP bytes and timing unchanged. Compare at the same capture
point and with the same extractor, retaining source-specific missingness
rather than imputing nonexistent TLS. Retain separate physical Ethernet
frame counts and normalized virtual-segment counts. Prevent capture-origin
metadata, sampling rules, OS version, proxy headers, and group ID leakage
from contaminating classifier results.

### 4. Evaluation sequence

- Verify benign task completion and genuine end-to-end TLS/HTTP processing.
- Verify TCP lifecycles and capture-to-feature measurement invariants.
- Compare real office day with another unseen real office day using disjoint
  host-level clusters, recording feature eligibility and confidence intervals.
- Compare a separate, frozen benign fixture corpus with office slices only
  after documenting support overlap and measurement parity. Never select
  candidate parameters using the final evaluation day.
- Report failures by independent measurement family, including identity
  context, TLS observability, network environment, traffic timing, and
  complete session boundaries.
- Run task-utility tests for the defender rather than optimizing only C2ST
  similarity. Preserve a pristine future office holdout.

### 5. Release gates

A green CI run means software/tests worked, **not** that office naturalness
was reached. Release stays blocked until all of the following have
independently passed:

- protocol and privacy checks;
- consistent extractors and capture points;
- sufficient group-disjoint observations for each compared stratum;
- external office-day confirmation on **new**, previously unused data;
- credible workload/task-utility coverage, not just flow-marginal similarity.

The present data cannot estimate office *application* mix reliably, cannot
establish that all office sessions are benign, and cannot prove Windows
runner equivalence to the corporate mirror.

## Pragmatic decision

Prioritize UBE with real, authorized applications over a GAN/copula that only
draws network features. NetShare/NetDiffusion are research comparators to
evaluate, **not** ways to convert a wrong workload into correct application
causality. Do not edit packets or secretly tune suspicious/attack scenarios
to defeat a detector.

Current status: `naturalness_status=not_passed`;
`production_ready=false`; `training_eligible=false`.
