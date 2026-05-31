# Linux Agent: Open Spec Questions

Questions to raise with the spec agent (issue tag `spec`). Each notes the
provisional behavior the agent ships today so the harness stays green; none of
these invent wire endpoints or error codes beyond CONTRACTS.md.

1. **Error code for deleting a non-empty key without `recursive`.**
   The error table has no KEY_NOT_EMPTY. Windows `RegDeleteKey` refuses a key
   with subkeys. Provisional: return `ACCESS_DENIED`. Confirm or add a code.

2. **Error code for a malformed request (missing field, bad JSON).**
   No BAD_REQUEST code exists. Provisional: `INTERNAL`. A dedicated code would
   let the harness distinguish caller bugs from agent bugs.

3. **`/key/create` intermediate-key semantics.**
   Provisional: creates all intermediate keys along the path (RegCreateKeyEx
   semantics) and returns `KEY_EXISTS` only when the final component already
   exists. offreg `ORCreateKey` may differ (single key, parents required).
   The differ will catch any mismatch; confirm the intended contract.

4. **Default security descriptor on a newly created key.**
   CONTRACTS.md does not specify the SDDL a fresh key inherits. The agent uses
   a placeholder (`O:BAG:BAD:(A;;KA;;;BA)(A;;KA;;;SY)`). offreg inherits a real
   descriptor, so `security` and `bytewise` parity needs the true default.

5. **GET requests with JSON bodies.**
   CONTRACTS.md specifies GET for reads with a JSON body. The agent routes on
   path only and accepts a body on any method; the harness sends GET bodies via
   a low-level request builder. Confirm this is the intended transport, or
   whether read params should move to the query string.

6. **`/key/security` GET vs POST disambiguation.**
   One path serves both. The agent treats a request with an `sddl` field as a
   write and one without as a read. Confirm this is acceptable.

7. **Timestamp comparison (shared with the harness).**
   `last_write` is in the canonical form but two implementations cannot agree
   to the second. See tests/harness/spec-questions.md item 1.
