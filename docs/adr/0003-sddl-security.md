# ADR 0003: SDDL on the wire, normalized binary for comparison

- Status: accepted
- Date: 2026-05-30
- Deciders: spec agent
- Scope: CONTRACTS.md "Security" and the security half of the canonical
  form; prompted by the Windows agent's offreg findings
  (agents/windows/STATE.md).

## Context

Registry keys carry a self-relative SECURITY_DESCRIPTOR (owner, group,
DACL, optional SACL). Two transport and two comparison questions had to be
settled:

- How does a descriptor cross the wire between the harness and the agents?
- How does the harness decide two descriptors are semantically equal when
  the Linux side (libreg) and the Windows side (offreg) produce them
  through completely different code?

Constraints surfaced while building the Windows agent:

- offreg returns a self-relative binary descriptor;
  `ConvertSecurityDescriptorToStringSecurityDescriptorW` produces SDDL but
  reported a length including trailing null padding, which leaked trailing
  whitespace into the SDDL string (now trimmed at the first null).
- Offline hives do not always expose a readable SACL. offreg may omit the
  SACL even when libreg emits one. A naive string compare would then fire
  on every secured key.
- SDDL string form is not canonical: ACE ordering and component spacing can
  differ between producers for descriptors that are semantically identical.

## Decision

1. **Transport is SDDL.** Both agents convert to/from SDDL at their edge.
   SDDL is human-readable (good for curl debugging), and the Windows side
   gets conversion for free from the OS. libreg implements the conversion
   itself.

2. **Semantic equality is decided on the normalized binary descriptor, not
   the SDDL string.** The harness parses each SDDL back into owner SID,
   group SID, and the DACL/SACL ACE lists, then compares:
   - owner SID and group SID for exact equality;
   - DACL as an ordered ACE list (canonical ACE order per Windows: explicit
     deny, explicit allow, inherited deny, inherited allow), each ACE
     compared by (type, flags, access mask, trustee SID);
   - control flags that affect meaning (e.g. DACL/SACL present, defaulted,
     protected/auto-inherited), ignoring bits that are pure serialization
     artifacts.

3. **SACL is compared only when both agents report one.** If exactly one
   side has a SACL, that is treated as "not comparable", not a difference,
   because offline-hive SACL readability is unreliable. When both report a
   SACL, it is compared like the DACL. This asymmetry is logged by the
   harness so a genuinely dropped SACL is still visible in the run output,
   it just does not fail the `semantic` tag.

4. **Canonical SDDL string form** (for the `sddl` field and the SDDL half
   of the comparison): components in the fixed order `O:` `G:` `D:` `S:`,
   no trailing whitespace or null padding, well-known SID aliases used
   where they exist (e.g. `BA`, `SY`), ACEs in canonical order.

## Alternatives considered

- **Binary descriptor on the wire (base64).** Rejected as the transport:
  opaque to curl, and it would push SID and ACE formatting into the
  harness for display anyway. The binary form is still where equality is
  decided; it just is not what travels.
- **Compare raw SDDL strings.** Rejected: not canonical, fires on benign
  ACE-order and spacing differences.
- **Always require a SACL match.** Rejected: makes offreg non-conformant
  for the common case of an unreadable offline SACL.

## Consequences

- The harness needs an SDDL parser and a descriptor comparator; this is
  harness work created by this ADR (tracked for the harness agent).
- libreg must produce SDDL whose parsed descriptor matches offreg's for the
  same logical security, including canonical ACE ordering.
- A one-sided SACL is a warning in the run log, never a `semantic` failure.
- CONTRACTS.md 0.1.2 records the normalization rules and points here.
- Open: whether to add a dedicated `security` test sub-tag so SACL-present
  cases can be exercised explicitly once a SACL-readable corpus hive
  exists. Deferred to the harness agent.
