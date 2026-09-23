# DPI max100 Suricata rules — design

Date: 2026-08-25

## Goal

Replace the 11,164-rule experimental DPI corpus with one production-oriented Suricata 8 ruleset of at most 100 active rules covering all 39 original protocol/service labels, with reproducible traffic generation and a cross-protocol false-positive test in GitHub Actions.

## Inventory contract

The 39 source labels are:

1. MEK-60870-5-104
2. bgp-igp-open-adv-custom
3. bt-dht
4. bt-enterprise
5. dns
6. exchange-outlook
7. facebook-ios-chat-session
8. ftp
9. google-mail
10. http
11. imapv4
12. ldap
13. microsoft-azure-signup
14. microsoft-update
15. mqtt
16. netflix-get
17. netflix-player
18. ntpv4
19. opc
20. openvpn-ixia
21. pop3
22. postgresql
23. radius
24. rdp
25. rtsp
26. sap
27. sip
28. skype
29. snmp
30. syslog
31. teamviewer
32. telnet
33. tls
34. webex
35. youtube
36. quic
37. stun
38. dtls
39. ssh

`netflix-get` and `netflix-player` map to a single `netflix` service detector because encrypted network traffic cannot reliably distinguish catalogue retrieval from playback solely from DPI payload. Every source label remains represented in the inventory.

## Detection strategy

Use the strongest primitive available for each entity, in this order:

1. Suricata application protocol detection (`app-layer-protocol`) for protocols with a stable built-in parser/detector.
2. Compound protocol invariants in TCP stream or UDP payload for unsupported/disabled protocols.
3. TLS SNI suffixes for named Internet services. These rules are explicitly service detection, not protocol detection.

Rules must not depend on lab IP addresses, timestamps, random payload fragments, or fixed packet offsets unless the protocol specification itself fixes the field position.

Protocol rules are port-independent (`any any -> any any`). Service rules match domain boundaries in `tls.sni` and can coexist with the generic TLS detector.

## Protocol groups

### Built-in protocol detection

Use `app-layer-protocol` for DNS, FTP, HTTP, IMAP, LDAP, MQTT, NTP, POP3, RDP, SIP, SNMP, Telnet, TLS, SSH, BitTorrent DHT, and QUIC where the generated QUIC Initial is recognized. DNS and SIP have separate TCP/UDP rules where needed.

### Compound raw signatures

- IEC 60870-5-104: APCI U/S control frames beginning with `68 04` and protocol-defined control values.
- BGP: 16-byte `FF` marker plus valid BGP OPEN/UPDATE type position.
- BitTorrent peer protocol: exact stream prefix `\x13BitTorrent protocol`.
- PostgreSQL: StartupMessage protocol version 3.0 plus `user\0` parameter; do not rely on a parser being enabled in default YAML.
- RADIUS: Access-Request header plus a structurally positioned User-Name attribute.
- RTSP: `RTSP/1.0` together with `CSeq:` in one stream transaction.
- SAP (Session Announcement Protocol): SDP MIME marker plus SDP `v=0` payload.
- Syslog: anchored RFC 5424 / RFC 3164 message start.
- STUN: RFC 5389 magic cookie `0x2112A442` at byte offset 4.
- DTLS: DTLS handshake record version plus ClientHello handshake type at the protocol-defined offset.
- OPC: OPC UA `HELF` message prefix and OPC Classic IOPCServer DCE/RPC interface UUID.
- OpenVPN: client/server hard-reset opcode sequence tracked by flowbits, for UDP and TCP framing.

### TLS service detection

Use domain-boundary SNI matches for Exchange/Outlook, Facebook chat, Gmail, Azure signup, Microsoft Update, Netflix, Skype, TeamViewer, Webex, and YouTube. Multiple stable provider domains may be used when necessary. Service traffic is expected to also alert as `tls`.

## Rule identity

- SID range: 9,500,001 through 9,500,999, local-only namespace.
- Messages are machine-readable: `DPI|<detector_id>|protocol` or `DPI|<detector_id>|service`.
- No duplicate SID.
- No more than 100 active rules.

## Validation

GitHub Actions on Ubuntu must install Suricata 8.x and Scapy, then run:

1. Static contract tests: exactly 39 source labels, all mapped to a detector, <=100 active rules, unique SIDs, no lab-IP/date leakage.
2. `suricata -T` against the ruleset.
3. Deterministic PCAP generation for each detector plus negative/noise traffic.
4. Suricata replay for each PCAP.
5. Cross-protocol oracle: the expected detector must alert and no unrelated DPI detector may alert. Parent `tls` is allowed for SNI-based service samples.
6. Emit JSON and Markdown reports with per-case expected/observed alerts and summary TP/FP counts.

A CI pass proves zero false positives on this regression matrix, not zero false positives on all traffic in existence. The report must state this limitation explicitly.

## Deliverables

- `dpi-max100/rules/dpi_max100.rules`
- `dpi-max100/inventory.json`
- `dpi-max100/generate_corpus.py`
- `dpi-max100/validate_alerts.py`
- `dpi-max100/tests/test_contract.py`
- `.github/workflows/dpi-max100-suricata.yml`
- CI artifacts: generated PCAPs, EVE alert outputs, `report.json`, `report.md`
