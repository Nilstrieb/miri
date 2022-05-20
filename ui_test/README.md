A smaller version of compiletest-rs

## Supported magic comment annotations

* `// ignore-XXX` avoids running the test on targets whose triple contains `XXX`
    * `XXX` can also be one of `64bit`, `32bit` or `16bit`
* `// only-XXX` avoids running the test on targets whose triple **does not** contain `XXX`
    * `XXX` can also be one of `64bit`, `32bit` or `16bit`
* `// stderr-per-bitwidth` produces one stderr file per bitwidth, as they max differ significantly sometimes
* `// error-pattern: XXX` make sure the stderr output contains `XXX`
* `//~ ERROR: XXX` make sure the stderr output contains `XXX` for an error in the line where this comment is written
    * Also supports `HELP` or `WARN` for different kind of message
    * if the all caps note is left out, defaults to `ERROR`
* `// revisions: XXX YYY` runs the test once for each space separated name in the list
    * emits one stderr file per revision
    * `//~` comments can be restricted to specific revisions by adding the revision name before the `~` in square brackets: `//[XXX]~`
* `// compile-flags: XXX` appends `XXX` to the command line arguments passed to the rustc driver
* `// rustc-env: XXX=YYY` sets the env var `XXX` to `YYY` for the rustc driver execution.
    * for miri this is equivalent to setting env vars for the program execution
* `// normalize-stderr-test "REGEX" "REPLACEMENT"` replaces all matches of `REGEX` in the stderr with `REPLACEMENT`. The replacement may specify `$1` and similar backreferences to paste captures.
