# LEA Deployment Roadmap — Sutra-Net Forensics

From hackathon prototype to state police / FSL rollout, in four phases.

## Phase A — Pilot (Months 0–3): 2 FSL labs, 5 operators

- **Scope:** offline workstation install; PCAP + Android artifact ingestion;
  triage dashboards; BSA Sec-63 certificates.
- **Hardware:** commodity 16 GB RAM quad-core forensic laptop (existing
  cyber-cell hardware qualifies; no GPU, no cloud).
- **Success metrics:** time-to-first-triage < 10 min per case; 100% of
  certified evidence passing hash re-verification; operator training in one
  half-day session.
- **Exit criteria:** two real (training-mode) cases carried end-to-end,
  certificates accepted by the lab's legal reviewer.

## Phase B — State roll-out (Months 3–9): one state cybercrime wing

- **Scope:** 10–20 workstations; standard evidence-in workflow; checkpoint
  sealing enforced as SOP before case hand-over; nightly offline chain
  audits (`trusted_checkpoint verify` in cron).
- **Integrations:** export case reports to existing case-management systems
  via JSON; printers/court bundles from the certificate generator.
- **Governance:** dual-control key ceremony for signing keys (passphrase-
  protected PEMs, owner-only storage, fingerprint pinning in the trusted
  registry); quarterly key-inventory audit.
- **Exit criteria:** signed checkpoints present for every case; zero
  chain-verification failures unexplained.

## Phase C — Multi-state federation (Months 9–18)

- **Scope:** inter-lab checkpoint exchange: verified checkpoint exports move
  on seized media between labs; each lab re-verifies chains against the
  pinned key registry before accepting evidence lineage (the chain module
  already runs on any ordered set of checkpoints — live store, backup or
  replica).
- **Standards work:** align checkpoint envelope and certificate JSON with
  MHA/NFSA digital-evidence exchange formats as they emerge.
- **Exit criteria:** a case started in State A accepted by State B's FSL on
  the strength of verifiable checkpoints + Sec-63 certificate.

## Phase D — National capability (18+ months)

- **Scope:** C-DAC/MeitY packaging (RPM/DEB + hardened image), NIST-style
  tool validation study with NFSU, training curriculum with ISEA.
- **Research track:** expand behavioral C2 detection (more JA4 families,
  periodicity models), deepen Hinglish NLP coverage (more scripts, voice
  transcription), and federated — never cloud — analytics.

## Risk register (top 4)

| Risk | Mitigation |
| :--- | :--- |
| Key compromise | Passphrase-encrypted keys, owner-only files, fingerprint pinning, explicit rotation via registry rebuild |
| Operator error corrupting a store | Stores are immutable-by-convention; corruption is detected, reported and never silently healed; evidence re-acquisition is SOP |
| Legal challenge to tool output | Sec-63 certificates embed live hash re-verification; signed checkpoints provide independent mathematical lineage |
| Skill gap in labs | One-day training, scripted demo (demo/run_scenario.py) doubles as a self-teaching walkthrough |

## Cost model

100% open-source stack (Python, Apache Parquet, DuckDB, NetworkX,
`cryptography`, FastAPI). Zero recurring licence fees; the only deployment
cost is commodity hardware and one training day per lab.
