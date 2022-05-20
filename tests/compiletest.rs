use colored::*;
use regex::Regex;
use std::env;
use std::path::PathBuf;
use ui_test::{Config, Mode};

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

    let config = Config {
        args: flags,
        target,
        stderr_filters: REGEXES.clone(),
        stdout_filters: REGEXES.clone(),
        root_dir: PathBuf::from(path),
        mode,
        program: miri_path(),
    };
    ui_test::run_tests(config)
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

fn get_target() -> Option<String> {
    env::var("MIRI_TEST_TARGET").ok()
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
