# Desktop admission — finite formal-methods exploration

This increment checks production Rust security gates, not just an abstract
model. The test module `formal_admission_tests` in `src/main.rs` enumerates
1,000 length-three path-component inputs over a mixed safe/unsafe alphabet,
checks the derived tenant/deployment artifact prefix, explores 64 ordered
binary-token pairs, and checks representative loopback/non-loopback binds.

Production behavior remains fail-closed: path segments must be portable and
non-traversing, token equality must match exact bytes, and daemon binding must
remain on loopback. The added `src/attolang/daemon_admission.atto` is a *pure*
source-level policy projection over parsed facts; no native AttoLang execution
or daemon plugin is claimed.

From an authorized checkout:

```sh
cargo test --bin isl-desktop-daemon formal_admission_tests
cargo test --all-targets
```

Additional acceptance requires exact-head nonzero executed CI steps,
an independent review, and compiler-backed guest receipts before claiming
AttoLang parity. This bounded exploration does not prove timing
noninterference of the token compare, OS filesystem symlink isolation, or
unbounded cell lifecycle correctness.
