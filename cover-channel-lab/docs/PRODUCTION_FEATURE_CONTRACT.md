# Production Feature Contract

The target system is an NGFW/NDR ML module fed by Suricata/network telemetry. The corpus therefore keeps three feature domains separate.

## Content-visible branch

Candidate fields: HTTP method, normalized path shape, host category, request/response header length and structure, content type, status, body length, cache semantics, header grammar/compatibility, WebSocket handshake/frame metadata where exported, and transaction/session aggregates.

## Opaque branch

Candidate fields: destination/service novelty, SNI visibility/category, TLS version, ALPN, certificate properties, JA4/JA4S where exported, JA4T/transport fingerprint where exported, client/server bytes and packets, duration, packet-size sequence statistics, connection frequency, parallel connections, burst/retry patterns, time-of-day and persona/service baselines.

## Session branch

Candidate fields: transaction count, duration, inter-arrival statistics, periodicity/autocorrelation, jitter, burstiness, retry/backoff, upstream/downstream ratio, status/size sequences, path-schema cardinality, long-idle connection behavior and reconnect continuity.

## Promotion gate

A feature is not production-approved until all five are true:

1. the laboratory parser extracts it reliably;
2. the target NGFW exporter exposes an equivalent field;
3. truncation limits are measured;
4. packet-loss/partial-capture behavior is measured;
5. parser/NGFW upgrade stability is tested.

Use explicit missingness values such as `encrypted`, `inspection_bypassed`, `truncated`, `parser_unsupported`, `parser_failed`, `packet_loss`, `not_exported_by_ngfw`, and `unknown`; do not collapse them into one undifferentiated null.
