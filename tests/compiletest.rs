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

fn run_tests(mode: Mode, path: &str, target: &str) {
    let in_rustc_test_suite = option_env!("RUSTC_STAGE").is_some();
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
        flags.push(extra_flags);
    }
    flags.push("-Zui-testing".to_string());
    flags.push("--target".to_string());
    flags.push(target.to_string());
    let target = target.to_string();

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
                    total.fetch_add(1, Ordering::Relaxed);
                    // Read rules for skipping from file
                    if ignore_file(&path, &target) {
                        skipped.fetch_add(1, Ordering::Relaxed);
                        eprintln!("{} .. {}", path.display(), "skipped".yellow());
                        continue;
                    }

                    // Run miri
                    let mut miri = Command::new(miri_path());
                    miri.args(flags.iter());
                    miri.arg(&path);
                    miri.env("RUSTC_BACKTRACE", "0");
                    extract_env(&mut miri, &path);
                    let output = miri.output().expect("could not execute miri");

                    let mut ok = mode.ok(output.status);

                    // Check output files (if any)
                    let (stderr, expected_stderr) = extract_output(&output.stderr, &path, &mut ok, "stderr", &target);
                    let (stdout, expected_stdout) = extract_output(&output.stdout, &path, &mut ok, "stdout", &target);

                    let require = match mode {
                        Mode::Pass => false,
                        Mode::Panic => false, // Should we do anything here?
                        Mode::UB => true,
                    };
                    check_annotations(&path, &stderr, &mut ok, require);

                    eprint!("{} .. ", path.display());
                    if ok {
                        eprintln!("{}", "ok".green());
                    } else {
                        eprintln!("{}", "FAILED".red().bold());
                        failures.lock().unwrap().push((
                            path,
                            output,
                            miri,
                            expected_stderr,
                            expected_stdout,
                            stderr,
                            stdout,
                        ));
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
        for (path, output, miri, expected_stderr, expected_stdout, stderr, stdout) in &failures {
            eprintln!("{} failed, {}", path.display(), output.status);
            eprintln!("command: {:?}", miri);
            compare_output("stdout", path, stdout, expected_stdout);
            compare_output("stderr", path, stderr, expected_stderr);
        }
        eprintln!(
            "{} tests failed, {} tests passed, {} skipped",
            failures.len().to_string().red().bold(),
            (total - failures.len() - skipped).to_string().green(),
            skipped.to_string().yellow()
        );
        std::process::exit(1);
    }
    eprintln!(
        "{} tests passed, {} skipped",
        (total - skipped).to_string().green(),
        skipped.to_string().yellow()
    );
}

fn check_annotations(path: &Path, stderr: &str, ok: &mut bool, require: bool) {
    let content = std::fs::read_to_string(path).unwrap();
    let mut found_annotation = false;
    for line in content.lines() {
        if let Some(s) = line.strip_prefix("// error-pattern:") {
            if !stderr.contains(s.trim()) {
                *ok = false;
            }
            found_annotation = true;
        }
    }
    if found_annotation != require {
        *ok = false;
    }
}

fn extract_output(output: &[u8], path: &PathBuf, ok: &mut bool, kind: &str, target: &str) -> (String, String) {
    let output = std::str::from_utf8(&output).unwrap();
    let output = normalize(path, output);
    let path = output_path(path, kind, target);
    let expected_output = if let Ok(_) = env::var("MIRI_BLESS") {
        if output.is_empty() {
            let _ = std::fs::remove_file(path);
        } else {
            std::fs::write(path, &output).unwrap();
        }
        output.clone()
    } else {
        let expected_output =
            std::fs::read_to_string(path)
                .unwrap_or_default();
        *ok &= output == expected_output;
        expected_output
    };
    (output, expected_output)
}

fn output_path(path: &Path, kind: &str, target: &str) -> PathBuf {
    let content = std::fs::read_to_string(path).unwrap();
    for line in content.lines() {
        if line.starts_with("// stderr-per-bitwidth") {
            return path.with_extension(format!("{}.{kind}", get_pointer_width(target)));
        }
    }
    path.with_extension(kind)
}

fn compare_output(kind: &str, path: &Path, actual: &str, expected: &str) {
    if actual == expected {
        return;
    }
    eprintln!("{kind} differed from expected {}", path.with_extension(kind).display());
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

fn normalize(path: &Path, text: &str) -> String {
    let content = std::fs::read_to_string(path).unwrap();

    // Useless paths
    let mut text = text.replace(&path.parent().unwrap().display().to_string(), "$DIR");
    if let Some(lib_path) = option_env!("RUSTC_LIB_PATH") {
        text = text.replace(lib_path, "RUSTLIB");
    }

    // Line endings
    let from = Regex::new("\\.rs:[0-9]+:[0-9]+").unwrap();
    text = from.replace_all(&text, ".rs:LL:CC").to_string();

    // alloc ids
    let from = Regex::new("alloc[0-9]+").unwrap();
    text = from.replace_all(&text, "ALLOC").to_string();

    // borrow stack indices
    let from = Regex::new("<[0-9]+>").unwrap();
    text = from.replace_all(&text, "<BORROW_IDX>").to_string();

    // backtrace noise
    let from = Regex::new(" +at (.*\\.rs)").unwrap();
    text = from.replace_all(&text, " at $1").to_string();
    let from = Regex::new("([0-9]+: .*)::<.*>").unwrap();
    text = from.replace_all(&text, "$1").to_string();
    let from = Regex::new("([0-9]+: ) +0x[0-9a-f]+ - (.*)").unwrap();
    text = from.replace_all(&text, "$1$2").to_string();
    let from = Regex::new("0x[0-9a-fA-F]+").unwrap();
    text = from.replace_all(&text, "$$HEX").to_string();

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

fn ui(mode: Mode, path: &str, target: &str) {
    eprintln!(
        "{}",
        format!("## Running ui tests in {} against miri for target {}", path, target)
            .green()
            .bold()
    );

    run_tests(mode, path, target);
}

fn get_host() -> String {
    let version_meta =
        rustc_version::VersionMeta::for_command(std::process::Command::new(miri_path()))
            .expect("failed to parse rustc version info");
    version_meta.host
}

fn get_target() -> String {
    env::var("MIRI_TEST_TARGET").unwrap_or_else(|_| get_host())
}

#[derive(Copy, Clone)]
enum Mode {
    Pass,
    Panic,
    UB,
}

impl Mode {
    fn ok(self, status: ExitStatus) -> bool {
        match (status.success(), self) {
            (false, Mode::UB) | (false, Mode::Panic) | (true, Mode::Pass) => true,
            (true, Mode::Panic) | (true, Mode::UB) | (false, Mode::Pass) => false,
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

    let target = get_target();
    ui(Mode::Pass, "tests/run-pass", &target);
    ui(Mode::Panic, "tests/run-fail", &target);
    ui(Mode::UB, "tests/compile-fail", &target);
}
