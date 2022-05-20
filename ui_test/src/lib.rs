use std::env;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use colored::*;
use crossbeam::queue::SegQueue;
use regex::Regex;

#[derive(Debug)]
pub struct Config {
    /// Arguments passed to the binary that is executed.
    pub args: Vec<String>,
    /// `None` to run on the host, otherwise a target triple
    pub target: Option<String>,
    /// Filters applied to stderr output before processing it
    pub stderr_filters: Filter,
    /// Filters applied to stdout output before processing it
    pub stdout_filters: Filter,
    /// The folder in which to start searching for .rs files
    pub root_dir: PathBuf,
    pub mode: Mode,
    pub program: PathBuf,
    /// Instead of erroring if the stderr/stdout differs from the expected
    /// automatically replace it with the found output (after applying filters).
    pub bless: bool,
    /// Ignore mismatches in the stderr/stdout files.
    pub skip_output_checks: bool,
}

pub type Filter = Vec<(Regex, &'static str)>;

pub fn run_tests(config: Config) {
    eprintln!("   Compiler flags: {:?}", config.args);

    let target = config.target.clone().unwrap_or_else(|| config.get_host());

    let grab_entries =
        |path: &Path| std::fs::read_dir(path).unwrap().map(|entry| entry.unwrap().path());
    let todo = SegQueue::new();
    todo.push(config.root_dir.clone());

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
                    total.fetch_add(1, Ordering::Relaxed);
                    // Read rules for skipping from file
                    if ignore_file(&path, &target) {
                        skipped.fetch_add(1, Ordering::Relaxed);
                        eprintln!("{} .. {}", path.display(), "skipped".yellow());
                        continue;
                    }
                    for revision in revisions(&path) {
                        let (m, errors) = run_test(&path, &config, &target, &revision);

                        // Using `format` to prevent messages from threads from getting intermingled.
                        let mut msg = format!("{} ", path.display());
                        if !revision.is_empty() {
                            msg = format!("{msg}(revision `{revision}`) ");
                        }
                        msg = format!("{msg} .. ");
                        if errors.is_empty() {
                            eprintln!("{msg}{}", "ok".green());
                        } else {
                            eprintln!("{msg}{}", "FAILED".red().bold());
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
            eprint!("{}", path.display().to_string().underline());
            if !revision.is_empty() {
                eprint!(" (revision `{}`)", revision);
            }
            eprint!("{}", " FAILED".red());
            eprintln!();
            eprintln!("command: {:?}", miri);
            eprintln!();
            for error in errors {
                match error {
                    Error::ExitStatus(mode, exit_status) => eprintln!("{mode:?} got {exit_status}"),
                    Error::PatternNotFound { pattern, definition_line } => {
                        eprintln!("`{pattern}` {} in stderr output", "not found".red());
                        eprintln!(
                            "expected because of pattern here: {}:{definition_line}",
                            path.display()
                        );
                    }
                    Error::NoPatternsFound => eprintln!("{}", "no error patterns found in failure test".red()),
                    Error::PatternFoundInPassTest => eprintln!("{}", "error pattern found in success test".red()),
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
    /// A ui test checking for failure does not have any failure patterns
    NoPatternsFound,
    /// A ui test checking for success has failure patterns
    PatternFoundInPassTest,
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

fn run_test(path: &Path, config: &Config, target: &str, revision: &str) -> (Command, Errors) {
    // Run miri
    let mut miri = Command::new(&config.program);
    miri.args(config.args.iter());
    miri.arg(path);
    if !revision.is_empty() {
        miri.arg(format!("--cfg={revision}"));
    }
    miri.env("RUSTC_BACKTRACE", "0");
    extract_env(&mut miri, path);
    let output = miri.output().expect("could not execute miri");
    let mut errors = config.mode.ok(output.status);
    // Check output files (if any)
    let revised = |extension: &str| {
        if revision.is_empty() {
            extension.to_string()
        } else {
            format!("{}.{}", revision, extension)
        }
    };
    let stderr = check_output(
        &output.stderr,
        path,
        &mut errors,
        revised("stderr"),
        target,
        &config.stderr_filters,
        &config,
    );
    check_output(
        &output.stdout,
        path,
        &mut errors,
        revised("stdout"),
        target,
        &config.stdout_filters,
        &config,
    );
    check_annotations(path, &stderr, &mut errors, config, revision);
    (miri, errors)
}

fn check_annotations(
    path: &Path,
    stderr: &str,
    errors: &mut Errors,
    config: &Config,
    revision: &str,
) {
    let content = std::fs::read_to_string(path).unwrap();
    let mut found_annotation = false;
    let regex =
        Regex::new(r"//(\[(?P<revision>[^\]]+)\])?~[\^|]*\s*(ERROR|HELP|WARN)?:?(?P<text>.*)")
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
    match (config.mode, found_annotation) {
        (Mode::Pass, true) |
        (Mode::Panic, true) => errors.push(Error::PatternFoundInPassTest),
        (Mode::UB, false) => errors.push(Error::NoPatternsFound),
        _ => {},
    };
}

fn check_output(
    output: &[u8],
    path: &Path,
    errors: &mut Errors,
    kind: String,
    target: &str,
    filters: &Filter,
    config: &Config,
) -> String {
    let output = std::str::from_utf8(&output).unwrap();
    let output = normalize(path, output, filters);
    let path = output_path(path, kind, target);
    if config.bless {
        if output.is_empty() {
            let _ = std::fs::remove_file(path);
        } else {
            std::fs::write(path, &output).unwrap();
        }
    } else {
        let expected_output = std::fs::read_to_string(&path).unwrap_or_default();
        if !config.skip_output_checks {
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

fn normalize(path: &Path, text: &str, filters: &Filter) -> String {
    let content = std::fs::read_to_string(path).unwrap();

    // Useless paths
    let mut text = text.replace(&path.parent().unwrap().display().to_string(), "$DIR");
    if let Some(lib_path) = option_env!("RUSTC_LIB_PATH") {
        text = text.replace(lib_path, "RUSTLIB");
    }

    for (regex, replacement) in filters.iter() {
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

impl Config {
    fn get_host(&self) -> String {
        rustc_version::VersionMeta::for_command(std::process::Command::new(&self.program))
                .expect("failed to parse rustc version info").host
    }
}

#[derive(Copy, Clone, Debug)]
pub enum Mode {
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
