use std::env;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use colored::*;
use crossbeam::queue::SegQueue;
use regex::Regex;

fn miri_path() -> PathBuf {
    PathBuf::from(option_env!("MIRI").unwrap_or(env!("CARGO_BIN_EXE_miri")))
}

fn run_tests(mode: Mode, path: &str, target: Option<String>) {
    let in_rustc_test_suite = option_env!("RUSTC_STAGE").is_some();

    if in_rustc_test_suite {
        std::env::set_var("MIRI_SKIP_UI_CHECKS", "1");
    }

    // Add some flags we always want.
    let mut flags = Vec::new();
    flags.push("--edition".to_owned());
    flags.push("2018".to_owned());
    if in_rustc_test_suite {
        // Less aggressive warnings to make the rustc toolstate management less painful.
        // (We often get warnings when e.g. a feature gets stabilized or some lint gets added/improved.)
        flags.push("-Astable-features".to_owned());
    } else {
        flags.push("-Dwarnings".to_owned());
        flags.push("-Dunused".to_owned()); // overwrite the -Aunused in compiletest-rs
    }
    if let Ok(sysroot) = env::var("MIRI_SYSROOT") {
        flags.push("--sysroot".to_string());
        flags.push(sysroot);
    }
    if let Ok(extra_flags) = env::var("MIRIFLAGS") {
        for flag in extra_flags.split_whitespace() {
            flags.push(flag.to_string());
        }
    }
    flags.push("-Zui-testing".to_string());
    if let Some(target) = &target {
        flags.push("--target".to_string());
        flags.push(target.clone());
    }
    let target = target.unwrap_or_else(get_host);

    eprintln!("   Compiler flags: {:?}", flags);

    let grab_entries =
        |path: &Path| std::fs::read_dir(path).unwrap().map(|entry| entry.unwrap().path());
    let todo = SegQueue::new();
    todo.push(PathBuf::from(path));

    let failures = Mutex::new(vec![]);
    let total = AtomicUsize::default();
    let skipped = AtomicUsize::default();

    crossbeam::scope(|s| {
        for _ in 0..num_cpus::get() {
            s.spawn(|_| {
                while let Some(path) = todo.pop() {
                    // Collect everything inside directories
                    if path.is_dir() {
                        for entry in grab_entries(&path) {
                            todo.push(entry);
                        }
                        continue;
                    }
                    // Only look at .rs files
                    if let Some(ext) = path.extension() {
                        if ext != "rs" {
                            continue;
                        }
                    } else {
                        continue;
                    }
                    total.fetch_add(1, Ordering::Relaxed); // Read rules for skipping from file
                    if ignore_file(&path, &target) {
                        skipped.fetch_add(1, Ordering::Relaxed);
                        eprintln!("{} .. {}", path.display(), "skipped".yellow());
                        continue;
                    }
                    for revision in revisions(&path) {
                        let (m, errors) = run_test(&path, &target, &flags, mode, &revision);

                        eprint!("{} .. ", path.display());
                        if errors.is_empty() {
                            eprintln!("{}", "ok".green());
                        } else {
                            eprint!("{}", "FAILED".red().bold());
                            if !revision.is_empty() {
                                eprint!(" (revision `{}`)", revision);
                            }
                            eprintln!();
                            failures.lock().unwrap().push((path.clone(), m, revision, errors));
                        }
                    }
                }
            });
        }
    })
    .unwrap();

    let failures = failures.into_inner().unwrap();
    let total = total.load(Ordering::Relaxed);
    let skipped = skipped.load(Ordering::Relaxed);
    if !failures.is_empty() {
        for (path, miri, revision, errors) in &failures {
            eprintln!();
            eprint!("{} {}", path.display().to_string().underline(), "FAILED".red());
            if !revision.is_empty() {
                eprint!(" (revision `{}`) ", revision);
            }
            eprintln!();
            eprintln!("command: {:?}", miri);
            for error in errors {
                match error {
                    Error::ExitStatus(mode, exit_status) => eprintln!("{mode:?} got {exit_status}"),
                    Error::PatternNotFound { pattern, definition_line } => {
                        eprintln!("`{pattern}` not found in stderr output");
                        eprintln!(
                            "expected because of pattern here: {}:{definition_line}",
                            path.display()
                        );
                    }
                    Error::NoPatternsFound => eprintln!("no error patterns found in failure test"),
                    Error::OutputDiffers { path, actual, expected } =>
                        compare_output(path, actual, expected),
                }
                eprintln!();
            }
        }
        eprintln!(
            "{} tests failed, {} tests passed, {} skipped",
            failures.len().to_string().red().bold(),
            (total - failures.len() - skipped).to_string().green(),
            skipped.to_string().yellow()
        );
        std::process::exit(1);
    }
    eprintln!();
    eprintln!(
        "{} tests passed, {} skipped",
        (total - skipped).to_string().green(),
        skipped.to_string().yellow()
    );
}

#[derive(Debug)]
enum Error {
    /// Got an invalid exit status for the given mode.
    ExitStatus(Mode, ExitStatus),
    PatternNotFound {
        pattern: String,
        definition_line: usize,
    },
    NoPatternsFound,
    OutputDiffers {
        path: PathBuf,
        actual: String,
        expected: String,
    },
}

type Errors = Vec<Error>;

fn revisions(path: &Path) -> Vec<String> {
    let content = std::fs::read_to_string(path).unwrap();
    for line in content.lines() {
        if let Some(revisions) = line.strip_prefix("// revisions:") {
            return revisions.trim().split_whitespace().map(|s| s.to_string()).collect();
        }
    }
    vec![String::new()]
}

fn run_test(
    path: &Path,
    target: &str,
    flags: &[String],
    mode: Mode,
    revision: &str,
) -> (Command, Errors) {
    // Run miri
    let mut miri = Command::new(miri_path());
    miri.args(flags.iter());
    miri.arg(path);
    if !revision.is_empty() {
        miri.arg(format!("--cfg={revision}"));
    }
    miri.env("RUSTC_BACKTRACE", "0");
    extract_env(&mut miri, path);
    let output = miri.output().expect("could not execute miri");
    let mut errors = mode.ok(output.status);
    // Check output files (if any)
    let revised = |extension: &str| {
        if revision.is_empty() {
            extension.to_string()
        } else {
            format!("{}.{}", revision, extension)
        }
    };
    let stderr = check_output(&output.stderr, path, &mut errors, revised("stderr"), target);
    check_output(&output.stdout, path, &mut errors, revised("stdout"), target);
    let require = match mode {
        Mode::Pass => false,
        Mode::Panic => false, // Should we do anything here?
        Mode::UB => true,
    };
    check_annotations(path, &stderr, &mut errors, require, revision);
    (miri, errors)
}

fn check_annotations(
    path: &Path,
    stderr: &str,
    errors: &mut Errors,
    require: bool,
    revision: &str,
) {
    let content = std::fs::read_to_string(path).unwrap();
    let mut found_annotation = false;
    let regex =
        Regex::new("//(\\[(?P<revision>[^\\]]+)\\])?~[\\^|]*\\s*(ERROR|HELP|WARN)?:?(?P<text>.*)")
            .unwrap();
    for (i, line) in content.lines().enumerate() {
        if let Some(s) = line.strip_prefix("// error-pattern:") {
            let s = s.trim();
            if !stderr.contains(s) {
                errors.push(Error::PatternNotFound { pattern: s.to_string(), definition_line: i });
            }
            found_annotation = true;
        }
        if let Some(captures) = regex.captures(line) {
            // FIXME: check that the error happens on the marked line
            let matched = captures["text"].trim();

            if let Some(rev) = captures.name("revision") {
                if rev.as_str() != revision {
                    continue;
                }
            }

            if !stderr.contains(matched) {
                errors.push(Error::PatternNotFound {
                    pattern: matched.to_string(),
                    definition_line: i,
                });
            }
            found_annotation = true;
        }
    }
    if found_annotation != require {
        errors.push(Error::NoPatternsFound);
    }
}

fn check_output(
    output: &[u8],
    path: &Path,
    errors: &mut Errors,
    kind: String,
    target: &str,
) -> String {
    let output = std::str::from_utf8(&output).unwrap();
    let output = normalize(path, output);
    let path = output_path(path, kind, target);
    if env::var_os("MIRI_BLESS").is_some() {
        if output.is_empty() {
            let _ = std::fs::remove_file(path);
        } else {
            std::fs::write(path, &output).unwrap();
        }
    } else {
        let expected_output = std::fs::read_to_string(&path).unwrap_or_default();
        if env::var_os("MIRI_SKIP_UI_CHECKS").is_none() {
            if output != expected_output {
                errors.push(Error::OutputDiffers {
                    path,
                    actual: output.clone(),
                    expected: expected_output,
                });
            }
        }
    }
    output
}

fn output_path(path: &Path, kind: String, target: &str) -> PathBuf {
    let content = std::fs::read_to_string(path).unwrap();
    for line in content.lines() {
        if line.starts_with("// stderr-per-bitwidth") {
            return path.with_extension(format!("{}.{kind}", get_pointer_width(target)));
        }
    }
    path.with_extension(kind)
}

fn compare_output(path: &Path, actual: &str, expected: &str) {
    if actual == expected {
        return;
    }
    eprintln!("actual output differed from expected {}", path.display());
    eprintln!("{}", pretty_assertions::StrComparison::new(expected, actual));
    eprintln!()
}

fn ignore_file(p: &Path, target: &str) -> bool {
    let content = std::fs::read_to_string(p).unwrap();
    for line in content.lines() {
        if let Some(s) = line.strip_prefix("// ignore-") {
            let s =
                s.split_once(|c: char| c == ':' || c.is_whitespace()).map(|(s, _)| s).unwrap_or(s);
            if target.contains(s) {
                return true;
            }
            if get_pointer_width(target).contains(s) {
                return true;
            }
        }
        if let Some(s) = line.strip_prefix("// only-") {
            let s =
                s.split_once(|c: char| c == ':' || c.is_whitespace()).map(|(s, _)| s).unwrap_or(s);
            if !target.contains(s) {
                return true;
            }
            if !get_pointer_width(target).contains(s) {
                return true;
            }
        }
    }
    false
}

// Taken 1:1 from compiletest-rs
fn get_pointer_width(triple: &str) -> &'static str {
    if (triple.contains("64") && !triple.ends_with("gnux32") && !triple.ends_with("gnu_ilp32"))
        || triple.starts_with("s390x")
    {
        "64bit"
    } else if triple.starts_with("avr") {
        "16bit"
    } else {
        "32bit"
    }
}

fn extract_env(cmd: &mut Command, path: &Path) {
    let content = std::fs::read_to_string(path).unwrap();
    for line in content.lines() {
        if let Some(s) = line.strip_prefix("// compile-flags:") {
            cmd.args(s.split_whitespace());
        }
        if let Some(s) = line.strip_prefix("// rustc-env:") {
            for env in s.split_whitespace() {
                if let Some((k, v)) = env.split_once('=') {
                    cmd.env(k, v);
                }
            }
        }
    }
}

macro_rules! regexes {
    ($($regex:expr => $replacement:expr,)*) => {lazy_static::lazy_static! {
        static ref REGEXES: Vec<(Regex, &'static str)> = vec![
            $((Regex::new($regex).unwrap(), $replacement),)*
        ];
    }};
}

regexes! {
    // erase line and column info
    "\\.rs:[0-9]+:[0-9]+"            => ".rs:LL:CC",
    // erase alloc ids
    "alloc[0-9]+"                    => "ALLOC",
    // erase borrow stack indices
    "<[0-9]+>"                       => "<BORROW_IDX>",
    // erase whitespace that differs between platforms
    " +at (.*\\.rs)"                 => " at $1",
    // erase generics in backtraces
    "([0-9]+: .*)::<.*>"             => "$1",
    // erase addresses in backtraces
    "([0-9]+: ) +0x[0-9a-f]+ - (.*)" => "$1$2",
    // erase hexadecimals
    "0x[0-9a-fA-F]+(\\[a[0-9]+\\])?" => "$$HEX",
    // erase clocks
    "VClock\\(\\[[^\\]]+\\]\\)"      => "VClock",
    // erase specific alignments
    "alignment [0-9]+"               => "alignment ALIGN",
    // erase thread caller ids
    "\\(call [0-9]+\\)"              => "(call ID)",
    // erase platform module paths
    "sys::[a-z]+::"                  => "sys::PLATFORM::",
    // Windows file paths
    "\\\\"                           => "/",
    // erase platform file paths
    "sys/[a-z]+/"                    => "sys/PLATFORM/",
    // erase error annotations in tests
    "\\s*//~.*"                      => "",
}

fn normalize(path: &Path, text: &str) -> String {
    let content = std::fs::read_to_string(path).unwrap();

    // Useless paths
    let mut text = text.replace(&path.parent().unwrap().display().to_string(), "$DIR");
    if let Some(lib_path) = option_env!("RUSTC_LIB_PATH") {
        text = text.replace(lib_path, "RUSTLIB");
    }

    for (regex, replacement) in REGEXES.iter() {
        text = regex.replace_all(&text, *replacement).to_string();
    }

    for line in content.lines() {
        if let Some(s) = line.strip_prefix("// normalize-stderr-test") {
            let (from, to) = s.split_once("->").expect("normalize-stderr-test needs a `->`");
            let from = from.trim().trim_matches('"');
            let to = to.trim().trim_matches('"');
            let from = Regex::new(from).unwrap();
            text = from.replace_all(&text, to).to_string();
        }
    }
    text
}

fn ui(mode: Mode, path: &str) {
    let target = get_target();

    eprint!("{}", format!("## Running ui tests in {path} against miri for ").green().bold());

    if let Some(target) = &target {
        eprintln!("{target}");
    } else {
        eprintln!("host");
    }

    run_tests(mode, path, target);
}

fn get_host() -> String {
    let version_meta =
        rustc_version::VersionMeta::for_command(std::process::Command::new(miri_path()))
            .expect("failed to parse rustc version info");
    version_meta.host
}

fn get_target() -> Option<String> {
    env::var("MIRI_TEST_TARGET").ok()
}

#[derive(Copy, Clone, Debug)]
enum Mode {
    Pass,
    Panic,
    UB,
}

impl Mode {
    fn ok(self, status: ExitStatus) -> Errors {
        match (status.success(), self) {
            (false, Mode::UB) | (false, Mode::Panic) | (true, Mode::Pass) => vec![],
            (true, Mode::Panic) | (true, Mode::UB) | (false, Mode::Pass) =>
                vec![Error::ExitStatus(self, status)],
        }
    }
}

fn main() {
    // Add a test env var to do environment communication tests.
    env::set_var("MIRI_ENV_VAR_TEST", "0");
    // Let the tests know where to store temp files (they might run for a different target, which can make this hard to find).
    env::set_var("MIRI_TEMP", env::temp_dir());
    // Panic tests expect backtraces to be printed.
    env::set_var("RUST_BACKTRACE", "1");

    ui(Mode::Pass, "tests/run-pass");
    ui(Mode::Panic, "tests/run-fail");
    ui(Mode::UB, "tests/compile-fail");
}
