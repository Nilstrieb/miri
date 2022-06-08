# What is miri?

To put it simply, Miri is an interpreter for Rust code. While Rust is
usually compiled down to machine code by `rustc`, the Rust compiler,
interpreting Rust has numerous advantages.
Miri can check various forms of problems in Rust code that would be
a lot harder to find without it, mainly in `unsafe` code.

This allows Miri to determine many ways in which `unsafe` code has
[undefined behaviour](https://doc.rust-lang.org/reference/behavior-considered-undefined.html),
for example:

* Out-of-bounds memory accesses and use-after-free
* Invalid use of uninitialized data
* Violation of intrinsic preconditions (an unreachable_unchecked being 
  reached, calling copy_nonoverlapping with overlapping ranges, ...)
* Not sufficiently aligned memory accesses and references
* Violation of some basic type invariants (a bool that is not 0 or 1,
  for example, or an invalid enum discriminant)
* **Experimental:** Data races
* **Experimental:** Emulation of weak memory effects (i.e., reads can return outdated values)
* **Experimental:** Violations of the [Stacked Borrows](https://github.com/rust-lang/unsafe-code-guidelines/blob/master/wip/stacked-borrows.md)
   rules governing aliasing for reference types

Miri can also detenct memory leaks and emulate other architectures
(like big-endian) to help you find issues that only crop up there.

If you write `unsafe` code, it's recommended that you use Miri to
make sure that you uphold the rules, since it can be very difficult
to do this without assistance from such tools.

For those familiar with C/C++ sanitizers, Miri is like an even more
powerful sanitizer.