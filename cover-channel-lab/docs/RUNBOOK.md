# Runbook

## GitHub Actions behavior

A normal push touching this lab runs Stage A parser/observability validation. A commit whose message contains `[coverlab-full]` requests the full sharded corpus. Full and mixed jobs run only when `HF_TOKEN` is present because large data must have a durable sink before expensive generation starts.

`workflow_dispatch` can also request a full run from the Actions UI.

## Required GitHub secret

Repository → Settings → Secrets and variables → Actions → New repository secret:

- Name: `HF_TOKEN`
- Value: a Hugging Face user access token belonging to `Maksim123321` with write permission to datasets.

The workflow creates the private dataset repository `Maksim123321/cover-channel-web-protocols` if absent.

## Failure recovery

Every full job is a deterministic `(stage, shard, seed)` unit. Re-running a failed job regenerates the same campaign/configuration IDs and writes to the same Hugging Face shard path. Hugging Face Xet deduplication avoids re-uploading identical chunks where possible.

The code and documentation never live only on a runner: they are committed to GitHub. Generated data never depends on GitHub artifact retention; artifacts contain only compact smoke/quality output. Full data is persisted to Hugging Face immediately per shard.

## Quality gates

A shard is rejected if the PCAP is absent/empty, campaign IDs duplicate, generation reports failures, an external dependency is marked true, checksums cannot be produced, or parser processing cannot complete sufficiently to create the expected normalized tables. Parser exit codes and versions are persisted even when a parser partially degrades so parser-version robustness can be evaluated explicitly.

## Rerunning locally

The exact Git commit SHA appears in every campaign record and `reproducibility.json`. Checkout that SHA and rerun the stage/shard using the commands from the root README.
