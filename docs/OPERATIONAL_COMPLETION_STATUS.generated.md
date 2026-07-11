# Marvain Operational Completion Status

This status is computed from the 85-row execution ledger and machine-readable evidence manifest. It is separate from the repository evidence-presence score.

Operational score: **47%**.
Capabilities at 100/SUCCESS: **0/85**.

## Category Summary

| Category | Score | Capabilities at 100 | Total |
|---|---:|---:|---:|
| `FND` | 54% | 0 | 8 |
| `AGT` | 37% | 0 | 10 |
| `MEM` | 49% | 0 | 13 |
| `IDN` | 39% | 0 | 9 |
| `LIV` | 49% | 0 | 9 |
| `TOP` | 54% | 0 | 5 |
| `ACT` | 59% | 0 | 3 |
| `INT` | 53% | 0 | 4 |
| `DAT` | 44% | 0 | 9 |
| `OPS` | 38% | 0 | 15 |

## Capability Evidence

| ID | Capability | Score | Evidence cap | Status | Owner | Gate |
|---|---|---:|---:|---|---|---:|
| `FND-01` | Product mission and domain model | 72% | 74% | `OPEN` | `A1` | 1 |
| `FND-02` | No-fallback/no-legacy architecture | 46% | 49% | `IN_PROGRESS` | `A1` | 1 |
| `FND-03` | Python and dependency contract | 38% | 49% | `OPEN` | `A2` | 1 |
| `FND-04` | CLI and explicit configuration | 68% | 74% | `OPEN` | `A2` | 1 |
| `FND-05` | Cognito browser and runtime auth | 62% | 74% | `OPEN` | `A4` | 1 |
| `FND-06` | Memberships and human roles | 70% | 74% | `OPEN` | `A4` | 1 |
| `FND-07` | Agent-to-agent authentication | 43% | 49% | `OPEN` | `A4` | 3 |
| `FND-08` | Multi-tenant isolation | 35% | 49% | `OPEN` | `A4` | 2 |
| `AGT-01` | Agent creation and durable identity | 72% | 74% | `OPEN` | `A6` | 3 |
| `AGT-02` | Persona creation and selection | 55% | 74% | `OPEN` | `A6` | 3 |
| `AGT-03` | Personality and constitution model | 34% | 49% | `OPEN` | `A6` | 3 |
| `AGT-04` | Agent self-update of constitution | 22% | 49% | `OPEN` | `A6` | 7 |
| `AGT-05` | Maturity rubric | 64% | 74% | `OPEN` | `A6` | 3 |
| `AGT-06` | Stasis and soft deletion | 42% | 49% | `OPEN` | `A6` | 3 |
| `AGT-07` | Agent-requested deletion review | 22% | 49% | `OPEN` | `A6` | 3 |
| `AGT-08` | Full agent backup/export | 38% | 49% | `OPEN` | `A6` | 3 |
| `AGT-09` | Restore and disaster recovery | 12% | 49% | `OPEN` | `A6` | 7 |
| `AGT-10` | Agent continuity across upgrades | 10% | 49% | `OPEN` | `A6` | 7 |
| `MEM-01` | Eight-kind memory taxonomy | 82% | 84% | `OPEN` | `A5` | 3 |
| `MEM-02` | Provenance classes | 72% | 74% | `OPEN` | `A5` | 3 |
| `MEM-03` | Model-assisted classification | 52% | 74% | `OPEN` | `A5` | 3 |
| `MEM-04` | Source evidence and candidate lifecycle | 66% | 74% | `OPEN` | `A5` | 3 |
| `MEM-05` | Agent ownership and immutable content | 61% | 74% | `OPEN` | `A5` | 3 |
| `MEM-06` | User annotation and disagreement | 55% | 74% | `OPEN` | `A5` | 3 |
| `MEM-07` | Embedding creation and durability | 34% | 49% | `OPEN` | `A5` | 3 |
| `MEM-08` | Recall ranking and explanation | 58% | 74% | `OPEN` | `A5` | 3 |
| `MEM-09` | Consent/privacy-aware recall | 25% | 49% | `OPEN` | `A4` | 3 |
| `MEM-10` | Cross-space/device/session/person recall | 56% | 74% | `OPEN` | `A5` | 3 |
| `MEM-11` | Cross-agent interaction memory | 28% | 49% | `OPEN` | `A5` | 7 |
| `MEM-12` | Self-inspired reflection and learning | 24% | 49% | `OPEN` | `A5` | 7 |
| `MEM-13` | Consolidation, forgetting, contradiction | 18% | 49% | `OPEN` | `A5` | 7 |
| `IDN-01` | People and account linkage | 65% | 74% | `OPEN` | `A4` | 3 |
| `IDN-02` | Consent grant/revoke lifecycle | 58% | 74% | `OPEN` | `A4` | 3 |
| `IDN-03` | Voice/face enrollment | 50% | 74% | `OPEN` | `A8` | 4 |
| `IDN-04` | Production recognition worker | 28% | 49% | `OPEN` | `A8` | 4 |
| `IDN-05` | Unknown/no-match retention | 32% | 49% | `OPEN` | `A8` | 4 |
| `IDN-06` | Recognition correction and revocation | 35% | 49% | `OPEN` | `A8` | 4 |
| `IDN-07` | Presence assertions | 38% | 49% | `OPEN` | `A8` | 4 |
| `IDN-08` | Recognition quality and bias evaluation | 15% | 49% | `OPEN` | `A8` | 7 |
| `IDN-09` | Biometric artifact governance | 30% | 49% | `OPEN` | `A8` | 4 |
| `LIV-01` | LiveKit room/token/session join | 68% | 74% | `OPEN` | `A7` | 4 |
| `LIV-02` | Typed chat loop | 62% | 74% | `OPEN` | `A7` | 4 |
| `LIV-03` | Speech transcription | 52% | 74% | `OPEN` | `A7` | 4 |
| `LIV-04` | Agent speech and speaker playback | 52% | 74% | `OPEN` | `A7` | 4 |
| `LIV-05` | Mic/speaker/camera controls | 70% | 74% | `OPEN` | `A7` | 4 |
| `LIV-06` | Camera observation and visual truthfulness | 60% | 74% | `OPEN` | `A7` | 4 |
| `LIV-07` | Session lifecycle and recovery | 25% | 49% | `OPEN` | `A7` | 4 |
| `LIV-08` | Worker packaging and supervision | 28% | 49% | `OPEN` | `A2` | 4 |
| `LIV-09` | Media telemetry | 22% | 49% | `OPEN` | `A7` | 6 |
| `TOP-01` | Locations, spaces, devices, sessions | 66% | 74% | `OPEN` | `A9` | 5 |
| `TOP-02` | Device token auth and scopes | 69% | 74% | `OPEN` | `A9` | 5 |
| `TOP-03` | Heartbeat and online state | 58% | 74% | `OPEN` | `A9` | 5 |
| `TOP-04` | Remote satellite/location node | 47% | 49% | `OPEN` | `A9` | 5 |
| `TOP-05` | Two-device/two-location routing | 28% | 49% | `OPEN` | `A9` | 5 |
| `ACT-01` | Action proposal and policy | 70% | 74% | `OPEN` | `A9` | 5 |
| `ACT-02` | Device command ack/result/timeout | 62% | 74% | `OPEN` | `A9` | 5 |
| `ACT-03` | Local host executors | 45% | 49% | `OPEN` | `A9` | 5 |
| `INT-01` | Integration account and message model | 70% | 74% | `OPEN` | `A9` | 5 |
| `INT-02` | Provider ingress | 63% | 74% | `OPEN` | `A9` | 5 |
| `INT-03` | Provider outbound actions | 55% | 74% | `OPEN` | `A9` | 5 |
| `INT-04` | Cross-channel conversation continuity | 25% | 49% | `OPEN` | `A9` | 7 |
| `DAT-01` | TapDB boundary conformance | 76% | 84% | `OPEN` | `A3` | 2 |
| `DAT-02` | TapDB native query/graph/admin surfaces | 62% | 74% | `OPEN` | `A3` | 2 |
| `DAT-03` | TapDB canonical production writes | 25% | 49% | `OPEN` | `A3` | 2 |
| `DAT-04` | TapDB write idempotency and retries | 22% | 49% | `OPEN` | `A3` | 2 |
| `DAT-05` | Typed external references and lineage | 38% | 49% | `OPEN` | `A3` | 2 |
| `DAT-06` | SQL projection consistency | 31% | 49% | `OPEN` | `A3` | 2 |
| `DAT-07` | Artifact storage and references | 43% | 49% | `OPEN` | `A3` | 2 |
| `DAT-08` | Audit chain and immutability | 58% | 74% | `OPEN` | `A3` | 2 |
| `DAT-09` | Retention and erasure | 40% | 49% | `OPEN` | `A3` | 7 |
| `OPS-01` | GUI page inventory | 80% | 84% | `OPEN` | `A10` | 6 |
| `OPS-02` | GUI workflow operability | 45% | 49% | `OPEN` | `A10` | 6 |
| `OPS-03` | GUI accessibility/responsiveness | 28% | 49% | `OPEN` | `A10` | 6 |
| `OPS-04` | Marvain-native discovery and health | 52% | 74% | `IN_PROGRESS` | `A10` | 6 |
| `OPS-05` | Operational observability | 36% | 49% | `OPEN` | `A10` | 6 |
| `OPS-06` | Queue failure handling | 34% | 49% | `OPEN` | `A2` | 5 |
| `OPS-07` | Static and unit regression suite | 78% | 84% | `OPEN` | `A10` | 6 |
| `OPS-08` | API/GUI route coverage measurement | 35% | 49% | `OPEN` | `A1` | 6 |
| `OPS-09` | Playwright workflow coverage | 40% | 49% | `OPEN` | `A10` | 6 |
| `OPS-10` | GUI smoke guide | 34% | 49% | `OPEN` | `A10` | 6 |
| `OPS-11` | Deployed v1-dev smoke | 20% | 49% | `OPEN` | `A2` | 8 |
| `OPS-12` | Fresh clean-room deployment | 10% | 49% | `OPEN` | `A2` | 8 |
| `OPS-13` | Worker/service supervision | 27% | 49% | `OPEN` | `A2` | 4 |
| `OPS-14` | Failure injection and recovery | 32% | 49% | `OPEN` | `A10` | 8 |
| `OPS-15` | Cost, quota, and capacity controls | 24% | 49% | `OPEN` | `A2` | 7 |

## Gates

- Operating well requires score >=85, every core V1 capability >=85, no P0/P1 findings, and fresh clean-room proof.
- 100% requires every capability at 100/SUCCESS and all final evidence classes.
- Test fixtures and source-token presence cannot satisfy deployed evidence.
