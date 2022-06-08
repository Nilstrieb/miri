# Detecting

UB (short for undefined behvaiour), is behaviour exhibited by a program that violated
the rules, and anything is allowed to happen to such programs. Therefore, UB must be
avoided at all costs. Safe Rust ensures that UB does not happen using the borrow checker,
but unsafe Rust can violate those rules. Since Miris main pupose is to find programs 
that break the rules, let's write an invalid program.

```rust
#[test]
fn out_of_bounds() {
    // an array of 8 elements
    let array = [0; 8];
    // the index 9 is out of bounds!
    let oh_no = unsafe { array.get_unchecked(9) };
    // who knows what lies beyond, maybe not zero?
    assert_ne!(oh_no, 0);
}
```

Running `cargo test`, the test passes and everything seems fine.
But there is UB in our program, as the [documentation](https://doc.rust-lang.org/std/primitive.slice.html#method.get_unchecked)
for `get_unchecked` states:

> Calling this method with an out-of-bounds index is undefined behavior even if the resulting reference is not used.

Now let's run it using Miri.

```

running 1 test
test out_of_bounds ... error: Undefined Behavior: pointer arithmetic failed: alloc80508 has size 32, so pointer to 36 bytes starting at offset 0 is out-of-bounds
   --> /home/nilsh/.rustup/toolchains/miri/lib/rustlib/src/rust/library/core/src/ptr/const_ptr.rs:457:18
    |
457 |         unsafe { intrinsics::offset(self, count) }
    |                  ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ pointer arithmetic failed: alloc80508 has size 32, so pointer to 36 bytes starting at offset 0 is out-of-bounds
    |
    = help: this indicates a bug in the program: it performed an invalid operation, and caused Undefined Behavior
    = help: see https://doc.rust-lang.org/nightly/reference/behavior-considered-undefined.html for further information

    = note: inside `std::ptr::const_ptr::<impl *const i32>::offset` at /home/nilsh/.rustup/toolchains/miri/lib/rustlib/src/rust/library/core/src/ptr/const_ptr.rs:457:18
    = note: inside `std::ptr::const_ptr::<impl *const i32>::add` at /home/nilsh/.rustup/toolchains/miri/lib/rustlib/src/rust/library/core/src/ptr/const_ptr.rs:870:18
    = note: inside `<usize as std::slice::SliceIndex<[i32]>>::get_unchecked` at /home/nilsh/.rustup/toolchains/miri/lib/rustlib/src/rust/library/core/src/slice/index.rs:226:13
    = note: inside `core::slice::<impl [i32]>::get_unchecked::<usize>` at /home/nilsh/.rustup/toolchains/miri/lib/rustlib/src/rust/library/core/src/slice/mod.rs:405:20
note: inside `out_of_bounds` at src/lib.rs:6:26
   --> src/lib.rs:6:26
    |
6   |     let oh_no = unsafe { array.get_unchecked(9) };
    |                          ^^^^^^^^^^^^^^^^^^^^^^
note: inside closure at src/lib.rs:2:1
   --> src/lib.rs:2:1
    |
1   |   #[test]
    |   ------- in this procedural macro expansion
2   | / fn out_of_bounds() {
3   | |     // an array of 8 elements
4   | |     let array = [0; 8];
5   | |     // the index 9 is out of bounds!
...   |
8   | |     assert_ne!(*oh_no, 0);
9   | | }
    | |_^
    = note: this error originates in the attribute macro `test` (in Nightly builds, run with -Z macro-backtrace for more info)

note: some details are omitted, run with `MIRIFLAGS=-Zmiri-backtrace=full` for a verbose backtrace

error: aborting due to previous error

error: test failed, to rerun pass '--lib'
```

This is quite a mouthful, but the test fails with an error!

`error: Undefined Behavior: pointer arithmetic failed: alloc80508 has size 32, so pointer to 36 bytes starting at offset 0 is out-of-bounds`

Fixing the test to not do an out of bounds read like this:

```rust
#[test]
fn out_of_bounds() {
    // an array of 8 elements
    let array = [0; 8];
    // the index 7 is the last element!
    let oh_yes = unsafe { array.get_unchecked(7) };
    // it must be zero now
    assert_eq!(*oh_yes, 0);
}
```

Running it again, Miri seems to be happy with the code.