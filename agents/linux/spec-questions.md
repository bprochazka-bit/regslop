# Linux Agent: Open Spec Questions

Questions to raise with the spec agent (issue tag `spec`). Each notes the
provisional behavior the agent ships today so the harness stays green; none of
these invent wire endpoints or error codes beyond CONTRACTS.md.

1. **Error code for deleting a non-empty key without `recursive`.** RESOLVED in
   CONTRACTS 0.1.2: added `KEY_HAS_CHILDREN`. The agent now returns it (was the
   provisional `ACCESS_DENIED`). Confirmed live against offreg on the VM
   (2026-05-31): both agents return `KEY_HAS_CHILDREN`.

2. **Error code for a malformed request (missing field, bad JSON).** RESOLVED in
   CONTRACTS 0.1.4: added `BAD_REQUEST`. The agent now returns it for invalid
   JSON, a missing or wrong-typed required field, an unknown endpoint, an
   unknown value-type constant, and a leading-separator path (was `INTERNAL` /
   `TYPE_MISMATCH`). TYPE_MISMATCH is reserved for a well-formed value whose data
   does not fit the declared type. NOTE for the Windows agent: it still returns
   `INTERNAL`/`TYPE_MISMATCH` for these; conform to 0.1.4 so the two sides match
   if a malformed-request differential test is ever added.

3. **`/key/create` intermediate-key semantics.** RESOLVED in CONTRACTS 0.1.5:
   creates all missing intermediate components (RegCreateKeyEx-style), reuses
   existing intermediates, and returns `KEY_EXISTS` only when the leaf already
   exists, which is exactly the agent's behavior. Confirmed green on the live VM.

4. **Default security descriptor on a newly created key.** RESOLVED in CONTRACTS
   0.1.3 (issue #11, now closed): ratified the offreg-observed default
   `O:BAG:BAD:(A;CI;KA;;;SY)(A;CI;KA;;;BA)(A;CI;KR;;;WD)(A;CI;KR;;;RC)`, asserted
   by the `semantic` tag via O/G/D normalization. The agent's `DEFAULT_SDDL`
   matches; `semantic` is GREEN against the VM. The real libreg backend must
   emit the same descriptor (the MemBackend hardcodes it as a stand-in).

5. **GET requests with JSON bodies.** RESOLVED in CONTRACTS 0.1.6: reads are GET
   and carry parameters in the JSON request body, not the query string (see also
   ADR 0001). This is the agent's existing behavior; no change needed.

6. **`/key/security` GET vs POST disambiguation.** RESOLVED in CONTRACTS 0.1.2:
   read vs write is by HTTP method (GET reads, POST writes and requires `sddl`),
   not by the `sddl` field's presence. The agent now routes on method. Confirmed
   live against offreg on the VM (a GET carrying a stray `sddl` field still
   reads).

7. **Timestamp comparison (shared with the harness).** RESOLVED in CONTRACTS
   0.1.2: timestamps are excluded from semantic equality (and excluded under a
   renamed path). The harness drops `last_write` by default. See
   tests/harness/spec-questions.md.

---

All items above are resolved as of CONTRACTS 0.1.6. The agent conforms; the one
remaining cross-agent gap is that the Windows agent has not yet adopted
`BAD_REQUEST` (item 2), which is their conformance work, not a spec question.
