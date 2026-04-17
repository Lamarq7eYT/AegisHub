/// One-based source code location.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceLocation {
    /// One-based line number.
    pub line: usize,
    /// One-based column number.
    pub column: usize,
}

/// Source file passed to analyzers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceFile {
    path: String,
    language: Option<String>,
    content: String,
    line_starts: Vec<usize>,
}

impl SourceFile {
    /// Creates a source file with precomputed line offsets.
    pub fn new(
        path: impl Into<String>,
        language: Option<&str>,
        content: impl Into<String>,
    ) -> Self {
        let content = content.into();
        let line_starts = compute_line_starts(&content);

        Self {
            path: path.into(),
            language: language.map(str::to_owned),
            content,
            line_starts,
        }
    }

    /// Repository-relative or virtual path for this source file.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Optional language hint for the source file.
    pub fn language(&self) -> Option<&str> {
        self.language.as_deref()
    }

    /// Full source contents.
    pub fn content(&self) -> &str {
        &self.content
    }

    /// Number of lines in the file.
    pub fn line_count(&self) -> usize {
        self.content.lines().count().max(1)
    }

    /// Converts a byte index into a one-based line and column location.
    pub fn line_col(&self, byte_index: usize) -> SourceLocation {
        let clamped = byte_index.min(self.content.len());
        let line_index = match self.line_starts.binary_search(&clamped) {
            Ok(index) => index,
            Err(index) => index.saturating_sub(1),
        };
        let line_start = self.line_starts.get(line_index).copied().unwrap_or(0);
        let column = self.content[line_start..clamped].chars().count() + 1;

        SourceLocation {
            line: line_index + 1,
            column,
        }
    }

    /// Returns one line by one-based line number.
    pub fn line_at(&self, line_number: usize) -> Option<&str> {
        self.content.lines().nth(line_number.saturating_sub(1))
    }

    /// Returns source context around a one-based line number.
    pub fn snippet_around(&self, line_number: usize, radius: usize) -> String {
        let start = line_number.saturating_sub(radius).max(1);
        let end = line_number.saturating_add(radius);

        self.content
            .lines()
            .enumerate()
            .filter_map(|(index, line)| {
                let current = index + 1;

                if (start..=end).contains(&current) {
                    Some(format!("{current:>4} | {line}"))
                } else {
                    None
                }
            })
            .collect::<Vec<_>>()
            .join("\n")
    }
}

fn compute_line_starts(content: &str) -> Vec<usize> {
    let mut starts = vec![0];

    for (index, byte) in content.bytes().enumerate() {
        if byte == b'\n' {
            starts.push(index + 1);
        }
    }

    starts
}

#[cfg(test)]
mod tests {
    use super::SourceFile;

    #[test]
    fn maps_byte_offsets_to_line_and_column() {
        let file = SourceFile::new("example.js", Some("javascript"), "one\nthree\nfive");

        assert_eq!(file.line_col(0).line, 1);
        assert_eq!(file.line_col(0).column, 1);
        assert_eq!(file.line_col(4).line, 2);
        assert_eq!(file.line_col(4).column, 1);
    }

    #[test]
    fn returns_context_snippet() {
        let file = SourceFile::new("example.js", None, "a\nb\nc\nd\ne");

        assert_eq!(file.snippet_around(3, 1), "   2 | b\n   3 | c\n   4 | d");
    }
}
