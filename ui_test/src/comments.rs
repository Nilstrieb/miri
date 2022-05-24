use std::path::Path;

/// This crate supports various magic comments that get parsed as file-specific
/// configuration values. This struct parses them all in one go and then they
/// get processed by their respective use sites.
#[derive(Default)]
pub struct Comments {
    /// List of revision names to execute. Can only be speicified once
    pub revisions: Option<Vec<String>>,
    /// Don't run this test if any of these filters apply
    pub ignore: Vec<String>,
    /// Only run this test if all of these filters apply
    pub only: Vec<String>,
    pub stderr_per_bitwidth: bool,
}

impl Comments {
    pub fn parse(path: &Path) -> Self {
        let mut this = Self::default();
        let content = std::fs::read_to_string(path).unwrap();
        for (l, line) in content.lines().enumerate() {
            if let Some(revisions) = line.strip_prefix("// revisions:") {
                assert_eq!(
                    this.revisions,
                    None,
                    "{}:{l}, cannot specifiy revisions twice",
                    path.display()
                );
                this.revisions =
                    Some(revisions.trim().split_whitespace().map(|s| s.to_string()).collect());
            }
            if let Some(s) = line.strip_prefix("// ignore-") {
                let s = s
                    .split_once(|c: char| c == ':' || c.is_whitespace())
                    .map(|(s, _)| s)
                    .unwrap_or(s);
                this.ignore.push(s.to_owned());
            }
            if let Some(s) = line.strip_prefix("// only-") {
                let s = s
                    .split_once(|c: char| c == ':' || c.is_whitespace())
                    .map(|(s, _)| s)
                    .unwrap_or(s);
                this.only.push(s.to_owned());
            }
            if line.starts_with("// stderr-per-bitwidth") {
                assert!(
                    !this.stderr_per_bitwidth,
                    "{}:{l}, cannot specifiy stderr-per-bitwidth twice",
                    path.display()
                );
                this.stderr_per_bitwidth = true;
            }
        }
        this
    }
}
