# Setup

Miri can be installed through `rustup`, but only on nightly toolchains,
since it uses private `rustc` internals.

Install it like this:
```sh
rustup +nightly component add miri
```

Sometimes, `miri` is unavailable. In this case, check out [this website](https://rust-lang.github.io/rustup-components-history/)
to see the latest release with `miri` present. Then install it using
`rustup toolchain install nightly-YYYY-MM-DD`, and use it with
`rustup override set nightly-YYYY-MM-DD.`.

Let's try it out!

```sh
cargo new miri-test --lib
cd miri-test
cargo miri test
```

The first time you run Miri, it will perform some extra setup and install some
dependencies. It will ask you for confirmation before installing anything.

If everything went correctly, you'll see the following output:

```
running 1 test
test tests::it_works ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out

   Doc-tests miri-test

running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
```

You might have noticed that the tests took about a second, which is a lot slower
than the usual `cargo test`. This is the big downside of Miri being an interpreter,
it can be really slow. We'll see techniques to reduce the impact of this later.