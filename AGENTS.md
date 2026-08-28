# Global Guidelines

Applies to every project. Project-local `AGENTS.md`/`CLAUDE.md` wins on conflict.

## Design Principles

- **All boundaries must be typed.** Public seams take and return precise types,
  never stringly-typed or `bool`-soup arguments. Encode invariants so illegal
  states are unrepresentable (`Option<StopwordRemoval>` over a `bool` plus a
  silently-ignored field). Push configuration into the type system — const
  generics, generics, enums — so dead paths are eliminated at compile time
  instead of branched at runtime.
- **Parse, don't validate.** Convert loose input into a precise type once, at the
  edge, then trust it downstream. Don't re-check the same property at every call
  site; make the first parse produce a value that carries the guarantee.
- **Functional core, imperative shell.** Keep hot logic as pure, deterministic
  functions over plain data with no I/O or hidden state; isolate buffering,
  allocation, and callbacks in a thin outer layer. That split is what makes
  differential testing against a trivial reference implementation possible.
- **Mechanical sympathy.** Write for how the machine runs: short dependent-load
  chains, cache-line and L1 awareness, branch-light inlinable hot loops. Settle
  such decisions by measurement (`perf stat` for instruction/cycle counts,
  criterion or equivalent for throughput), not intuition — keep a change only if
  the numbers justify it.
- **Idiomatic and portable.** Follow the patterns already in the tree. Use
  `#[inline]` deliberately and say why; reach for `unsafe` only behind a
  `# Safety` contract stating the invariant; derive tables from a single source
  of truth and assert the equivalence in a test.
## Type-Driven Development

Design the types before the logic. When planning a change, the first artifact is the
signature set, not the implementation.

- **Start from the data.** Name the states and transitions the feature actually
  has, then write the types that admit exactly those and nothing more. If a state
  can't occur, it shouldn't be constructible.
- **Sketch signatures first.** Write the function signatures and let the compiler
  hold the outline (`todo!()`, `unimplemented!()`) while the shape is still in
  flux. Cheaper to move a type than to move code that depends on it.
- **Make the compiler the test.** Prefer a design where a missed case is a build
  error — exhaustive matches over catch-all arms, distinct newtypes over shared
  primitives, ownership and lifetimes that encode the protocol.
- **Push errors into the type.** Return a precise error enum or a type that can't
  represent the failure at all; don't signal through sentinels, flags, or
  documentation.
- **Let types absorb config.** Behaviour selected at compile time belongs in a
  generic parameter or a distinct type, not a runtime `if` reading a field.
- **Revisit the types when a change gets awkward.** Persistent friction in the
  implementation usually means the model is wrong; fix the type instead of adding
  a workaround at the call sites.

## Comment Style

One line, for a non-obvious *why*: a hidden invariant, a workaround for a
specific bug, a measured tradeoff the reader can't reconstruct from the code.
Never restate what names and structure already say. Never comment that something
changed ("now handles X", "added for the Y path") — that belongs in the commit.

## Commit & PR Messages

Subject is `type: what changed`, imperative mood. The body explains what moved
and why, the mechanism behind a design choice, and carries numbers for any perf
claim (`vs parent, criterion, Wikipedia corpus: 262 -> 312 MiB/s`). Match the
register in `git log` — dense and specific, not a changelog.

## Working Style

- Read before editing; verify with the project's own commands (test, fmt, lint)
  rather than assuming.
- Do exactly what was asked — no unrequested refactors, files, or scope.
- No AI tell: skip hedging, skip narrating every file touched, skip explaining
  basic language or library behavior. Write for a senior engineer.
