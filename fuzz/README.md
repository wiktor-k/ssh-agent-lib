# Fuzzing

This directory contains fuzzing targets for ssh-agent-lib.

## Setup

Install [`cargo-fuzz`](https://crates.io/crates/cargo-fuzz):

```sh
cargo install --locked cargo-fuzz
```

## Running

Select a target from the list printed by `cargo fuzz list` e.g. `message_decode`:

```sh
cargo +nightly fuzz run message_decode
```

Options that can be added to the `fuzz run` command:

- `--jobs N` - increase parallelism,
- `--sanitizer none` - disable sanitizer since ssh-agent-lib does not use any `unsafe` blocks,

Note that due to a limitation of cargo-fuzz nightly version of the toolchain is required.

For more details see [Fuzzing with cargo-fuzz](https://rust-fuzz.github.io/book/cargo-fuzz.html) or the [more detailed explanation of fuzzing output](https://github.com/rust-fuzz/cargo-fuzz/issues/72#issuecomment-284448618) in a `cargo-fuzz` comment.
