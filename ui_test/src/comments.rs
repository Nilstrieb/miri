use std::path::Path;

/// This crate supports various magic comments that get parsed as file-specific
/// configuration values. This struct parses them all in one go and then they
/// get processed by their respective use sites.
#[derive(Default)]
pub struct Comments {
    /// List of revision names to execute. Can only be speicified once
    pub revisions: Option<Vec<String>>,
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
        }
        this
    }
}
