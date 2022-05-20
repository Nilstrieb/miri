// compile-flags: -Zmiri-check-number-validity

// This test is adapted from https://github.com/rust-lang/miri/issues/1340#issue-600900312.

fn main() {
    let _val = unsafe { std::mem::MaybeUninit::<f32>::uninit().assume_init() };
    //~^ ERROR type validation failed at .value: encountered uninitialized bytes, but expected initialized bytes
}