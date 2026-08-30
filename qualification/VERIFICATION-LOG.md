# Verification log

Dated record of checks run against this study's claims. This log is **not**
the independent verification MR-TQ-005 §4 requires — every entry here was
performed by the study's author. It exists so that whoever does the
independent pass knows the document-to-code consistency was already
checked, and can focus on re-deriving the results rather than hunting for
transcription errors.

---

## 2026-08-29 — author self-audit of MR-TQ-004

**Repo state:** `mcp-ratchet` at `907c8a9` (the qualified-candidate commit),
working tree clean. `mcp-ratchet-do330` at `5d78f79`.

**Environment:** Windows 10.0.19045 · CPython 3.13.5 · `mcp` 2.1.1 ·
`FINGERPRINT_SCHEMA_VERSION = 1` — matches MR-TQ-002 §2 and MR-TQ-004 §2.

| Check | Result |
|---|---|
| Full test suite, clean run (`pytest -p no:cacheprovider`) | 194 passed, 0 failed, 0 skipped |
| `git rev-parse HEAD` == `907c8a9` | pass |
| Commits `78d5971`, `a054e4a`, `907c8a9` exist with the subjects MR-TQ-004 §4 describes | pass |
| Every test named in MR-TQ-004 §3 exists and passes | pass — all names resolve in `test_fingerprint.py`, `test_drift.py`, `test_drift_classification.py`, `test_baseline_error.py`, `test_report_markers.py`, `test_forward.py`, `test_server_side.py` |
| MR-TQ-004 §3 "TOR-9 — 8 cases" | pass — `test_baseline_error.py` collects exactly 8 |
| MR-TQ-004 §3 result callout "44 cases across the seven cited test files" | pass — 14 + 4 + 5 + 8 + 7 + 2 + 4 = 44 |
| Spot-check: cited tests assert what the "Recorded result" column claims | pass — checked TOR-1 (`test_none_valued_optional_fields_do_not_leak_into_hash` asserts `None`-valued == absent), TOR-8 (`test_dashboard_and_machine_readable_flag_not_evaluated` asserts both the banner and `drift_evaluation: "not_performed"`), TOR-9 (`test_proxy_logs_baseline_error_and_never_claims_no_drift` asserts no `tools_list_snapshot` and no `drift_event`), TOR-10 (`test_baseline_error.py` asserts `result.tools` forwarded on the error path) |

**Conclusion:** MR-TQ-004's evidence table contains no internal errors —
every cited case and commit is real and current at `907c8a9`. This does
not discharge the independence condition; a reviewer other than the author
still needs to re-run the suite and confirm each TOR's case against its
stated verdict.

**Still open (MR-TQ-005 §4, §6):**
- Independent verification of the MR-TQ-004 results.
- Tag `907c8a9` in the `mcp-ratchet` repository as the qualified commit.
- Create and hash (SHA-256) the credited assistant's baseline file at the
  point a real program adopts the control.

---

## 2026-08-30 — independent re-execution and adversarial review of MR-TQ-004

**Reviewer:** a session with no prior involvement in this repository's code or
documents, working from a clean checkout of `907c8a9`. Not the author. This is
the independence step MR-TQ-005 §4 / §7 calls for — a cold re-execution, not a
self-check. (It is still not a named-human program QA sign-off, which a real
use of this material would additionally require.)

**Method:** verify §2's environment; run `python -m pytest -q`; for every TOR,
resolve each cited test, run it in isolation, and read its source to confirm it
asserts what the "Recorded result" column claims — looking specifically for
prose that outruns the evidence.

| Check | Result |
|---|---|
| Environment (§2) | Matches on every row |
| Full suite at `907c8a9` | `194 passed, 0 failed, 0 skipped` — as claimed |
| Counts (44 cited-file / 8 for `test_baseline_error.py`) | Confirmed via `pytest --co` |
| Commits `78d5971` / `a054e4a` / `907c8a9` | Real; file footprints as §4 describes |
| Per-TOR assertions | Every TOR has a genuine passing case. TOR-9 rated best-evidenced. No dishonesty — independence limitation and untested injection check both openly disclosed. |

**Verdict: holds with minor caveats.** Five places where the "Recorded result"
prose claimed more than the cited test literally asserted — each verified
correct by source inspection, none a correctness failure:

1. **TOR-10** — "byte-matches a direct connection" was backed only by a
   name+description comparison.
2. **TOR-3 / TOR-5** — "nothing else drifted" / "one event per field" were
   membership checks, not exact-count assertions.
3. **TOR-1** — the eight-field canonical enumeration is source-backed
   (`_TOOL_FIELDS`), not asserted by a test.
4. **TOR-11** — "the injection verdict never enters the drift result" is an
   architectural claim, not exercised by a test.
5. **§2 / §6** — the SDK 2.0.0→2.1.1 `Tool`-field re-check has no cited
   artifact; it is an author assertion.

**Follow-up applied (same day, Rev 2026-08-30):**
- Closed 1 and 2 with real assertions: added
  `test_forward_list_tools_is_byte_identical_to_direct` (canonical dump of all
  eight fields, byte-equal), strengthened `test_forward_call_tool_returns_real_result_unmodified`
  to compare against a real direct call, and tightened the TOR-3 / TOR-5
  multi-field tests to exact `len(events)` / exact event-set. Suite: 194 → 195.
- Accepted 3, 4, 5 as **source-backed, not test-backed**, and said so
  explicitly in MR-TQ-004 §7 and MR-TQ-005 §4.

**Bottom line for a QA record:** *MR-TQ-004's evidence table re-executes
faithfully at `907c8a9` (194/194, environment and commits as stated); an
independent adversarial review closed the evidence-precision gaps a test could
close and documented the three that remain source-backed; a named human QA
sign-off is the last item outstanding.*
