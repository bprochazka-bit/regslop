# Linux Agent: Open Spec Questions

Questions to raise with the spec agent (issue tag `spec`). Each notes the
provisional behavior the agent ships today so the harness stays green; none of
these invent wire endpoints or error codes beyond CONTRACTS.md.

1. **Error code for deleting a non-empty key without `recursive`.** RESOLVED in
   CONTRACTS 0.1.2: added `KEY_HAS_CHILDREN`. The agent now returns it (was the
   provisional `ACCESS_DENIED`). Confirmed live against offreg on the VM
   (2026-05-31): both agents return `KEY_HAS_CHILDREN`.

2. **Error code for a malformed request (missing field, bad JSON).**
   No BAD_REQUEST code exists. Provisional: `INTERNAL`. A dedicated code would
   let the harness distinguish caller bugs from agent bugs.

3. **`/key/create` intermediate-key semantics.**
   Provisional: creates all intermediate keys along the path (RegCreateKeyEx
   semantics) and returns `KEY_EXISTS` only when the final component already
   exists. offreg `ORCreateKey` may differ (single key, parents required).
   The differ will catch any mismatch; confirm the intended contract.

4. **Default security descriptor on a newly created key.** NEEDS SPEC
   RATIFICATION. CONTRACTS.md still does not specify the SDDL a fresh key
   inherits. The first live differential run (2026-05-31) showed the old
   placeholder (`O:BAG:BAD:(A;;KA;;;BA)(A;;KA;;;SY)`, 2 ACEs) diverging from the
   offreg oracle's default on every key. We captured offreg's actual default
   from the VM and set the agent's `DEFAULT_SDDL` to match it:
   `O:BAG:BAD:(A;CI;KA;;;SY)(A;CI;KA;;;BA)(A;CI;KR;;;WD)(A;CI;KR;;;RC)`
   (SYSTEM full, Administrators full, Everyone read, Restricted Code read, all
   container-inheritable). With that, `semantic` is GREEN against the VM. Please
   ratify this as the canonical default in CONTRACTS.md (or specify the intended
   one). This is a stand-in MemBackend default; the real libreg backend must
   produce the same descriptor.

5. **GET requests with JSON bodies.**
   CONTRACTS.md specifies GET for reads with a JSON body. The agent routes on
   path only and accepts a body on any method; the harness sends GET bodies via
   a low-level request builder. Confirm this is the intended transport, or
   whether read params should move to the query string.

6. **`/key/security` GET vs POST disambiguation.** RESOLVED in CONTRACTS 0.1.2:
   read vs write is by HTTP method (GET reads, POST writes and requires `sddl`),
   not by the `sddl` field's presence. The agent now routes on method. Confirmed
   live against offreg on the VM (a GET carrying a stray `sddl` field still
   reads).

7. **Timestamp comparison (shared with the harness).**
   `last_write` is in the canonical form but two implementations cannot agree
   to the second. See tests/harness/spec-questions.md item 1.
