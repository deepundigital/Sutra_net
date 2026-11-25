# Live Scenario Demo — Round 2 / Finale Walkthrough

**Scenario:** "Operation Frozen Trail" — a cyber-fraud ring runs Hinglish
extortion chats over a seized Android handset while its C2 infrastructure
beacons through an encrypted channel. One operator, one laptop, zero internet.

## How to run it live (60–90 seconds)

```bash
python3 demo/run_scenario.py --workdir data/demo
```

The command prints a six-stage JSON timeline and exits 0 only when every
stage — including cryptographic chain verification — succeeds. A full case
report lands in `data/demo/case_report.json`.

## Stage-by-stage narration (what to say while it runs)

1. **ACQUISITION** — "Two seized artifacts are hashed with SHA-256 *and*
   SHA-3 on ingestion; the hashes go straight into a hash-chained audit
   ledger. From this second on, any tampering is mathematically detectable."
2. **NETWORK_TRIAGE** — "92% of the malware traffic is encrypted — we never
   decrypt. Instead we profile behavior: inter-arrival jitter, burst entropy
   and JA3 fingerprints flag the beaconing C2 flows. MITRE T1071.001/T1573."
3. **MOBILE_TRIAGE** — "The chat dump is Hinglish. Western NLP sees noise;
   we see 'police case hoga', 'account freeze', 'OTP jaldi bhejo' — financial
   coercion, urgency and OTP-harvesting categories, plus every UPI VPA,
   phone number and bank reference extracted by regex tuned to the Indian
   payment ecosystem."
4. **CORRELATION** — "One temporal knowledge graph joins both worlds: the
   handset, the burner numbers, the mule VPAs and the C2 infrastructure.
   High-degree nodes are the cash-out points."
5. **CHAIN_OF_CUSTODY** — "Now the differentiator: the ledger's verified
   tail is sealed into an Ed25519-signed checkpoint — atomic write,
   owner-only permissions, immutable store. Watch the chain verification
   pass. If anyone rolls the history back or forks it tomorrow, this check
   turns red."
6. **CERTIFICATION** — "One click, a Section 63 Bharatiya Sakshya Adhiniyam
   certificate — the successor of Section 65B IEA — with the live hash
   verification recorded inside. Ready to file."

## Jury Q&A armor

- **"Why not just decrypt?"** — Illegal without warrant in many scenarios,
  impossible against TLS 1.3 + DoH in others; behavioral detection needs no
  payload access and scales.
- **"What stops someone editing the audit trail?"** — Every record is
  hash-chained; the tail is sealed into a signed checkpoint; verification
  needs only the pinned public key, not trust in the server.
- **"Does it need the internet?"** — No. Fully air-gapped: parsers, ML, NLP,
  graphing, signing and certification all run offline.
- **"How is this PS04 and not just a SIEM?"** — The mule-attribution graph
  and UPI/Hinglish entity extraction are built for the Indian fraud ecosystem;
  the SIEM-style correlation is only one layer.

## Recovery drill (if asked, 15 seconds)

Delete or edit a checkpoint file in `data/demo/trusted_checkpoints/` and
re-run stage 5 (or `python3 -m sutra_net.compliance.trusted_checkpoint
--store-dir data/demo/trusted_checkpoints --registry
data/demo/trusted_keys/trusted_keys.json --key-file
data/demo/trusted_keys/signing_key.pem verify --ledger-id
CASE-2026-SUTRAM-DEMO` — global flags come *before* the subcommand, though
the CLI also accepts them after it): the audit reports invalid and names
the file. Evidence-grade behavior is demonstrated, not claimed.
