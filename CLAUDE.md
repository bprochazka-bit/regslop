# libreg

Cross-platform Windows Registry library for Linux, with differential
testing against a Windows reference implementation.

## Project Layout

```
libreg/             Core library (C or Rust; see libreg/CLAUDE.md)
agents/linux/       HTTP agent wrapping libreg
agents/windows/     HTTP agent wrapping offreg.dll
tests/harness/      Differential test driver
tests/fuzz/         Fuzzers and crash triage
tests/corpus/       Reference hives (gitignored, downloaded separately)
docs/               Spec notes, format references
CONTRACTS.md        Inter-component interfaces (read-only for most agents)
```

## Universal Rules

These apply to every agent working in this repo.

1. **Read CONTRACTS.md before making any cross-component change.** If your
   change requires modifying it, stop and open a PR labeled `contracts`.
   Do not modify CONTRACTS.md and your implementation in the same PR.

2. **Stay in your subtree.** Each subdirectory has its own CLAUDE.md
   listing what files you may touch. Touching anything outside requires
   a coordination note in your PR description.

3. **The harness is the judge.** A feature is not done until the
   differential harness reports green on at least the `semantic` tag.
   Do not mark issues closed based on local unit tests alone.

4. **No em dashes in writing.** Use commas, parentheses, or sentence
   breaks. This applies to comments, commit messages, docs, and PR
   descriptions.

5. **Debian first.** Build artifacts target Debian 13. Use `.deb`
   packaging where applicable. Prefer apt over pip. Prefer native
   binaries over containers.

6. **Write a STATE.md** in your subtree at the end of every session.
   List what is done, what is in progress, what assumptions you are
   relying on, and what you would do next. The next session reads this
   first.

7. **Do not invent endpoints, types, or error codes** not listed in
   CONTRACTS.md. If you need one, raise it as an issue against the
   spec agent first.

## Multi-Agent Coordination

Multiple Claude Code sessions work on this repo concurrently in separate
git worktrees. To avoid collisions:

- Each agent has a primary subtree it owns (write access).
- Other subtrees are read-only for that agent.
- Cross-cutting changes go through PRs reviewed by the spec agent.
- The Windows VM is a shared resource; the harness queues access.

If you are unsure whether you may touch a file, the answer is no.
Open an issue and ask.

## Build and Test (Cheat Sheet)

```bash
# Library
cd libreg && cargo build --release    # or: make

# Linux agent
cd agents/linux && cargo build --release

# Windows agent (cross-compile from Linux)
cd agents/windows && cargo build --release --target x86_64-pc-windows-gnu

# Run harness against both agents
cd tests/harness && ./run.sh --linux-port 7878 --windows-host vmreg.lan
```

## When in Doubt

- Spec questions: ask the spec agent (open issue tagged `spec`).
- Library internals: see libreg/CLAUDE.md.
- Failing differ: harness output names the operation; reproduce manually
  with `curl` against both agents before reporting.
