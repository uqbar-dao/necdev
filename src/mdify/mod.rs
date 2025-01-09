use anyhow::{Context, Result};
use glob::Pattern;
use log::{error, info};
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

pub struct RepoExtractor {
    repo_path: PathBuf,
    output: Vec<String>,
    ignored_patterns: HashSet<String>,
}

impl RepoExtractor {
    fn new(repo_path: &str) -> Result<Self> {
        let repo_path = PathBuf::from(repo_path);
        let mut extractor = RepoExtractor {
            repo_path,
            output: Vec::new(),
            ignored_patterns: HashSet::new(),
        };
        extractor.load_gitignore()?;
        Ok(extractor)
    }

    fn load_gitignore(&mut self) -> Result<()> {
        let gitignore_path = self.repo_path.join(".gitignore");
        if gitignore_path.exists() {
            let content = fs::read_to_string(&gitignore_path)
                .with_context(|| format!("Failed to read .gitignore at {:?}", gitignore_path))?;
            for line in content.lines() {
                let line = line.trim();
                if !line.is_empty() && !line.starts_with('#') {
                    self.ignored_patterns.insert(line.to_string());
                }
            }
        }

        // Add common build artifacts and system files
        let common_patterns = [
            "*.pyc",
            "__pycache__",
            "node_modules",
            "dist",
            "build",
            ".git",
            ".DS_Store",
            "*.so",
            "*.dll",
            "*.dylib",
            "target/",
            "bin/",
            "obj/",
            ".idea/",
            ".vscode/",
        ];
        self.ignored_patterns
            .extend(common_patterns.iter().map(|s| s.to_string()));
        Ok(())
    }

    fn should_include_file(&self, file_path: &Path) -> bool {
        // Exclude files in hidden directories (starting with .)
        if file_path.components().any(|c| {
            if let std::path::Component::Normal(os_str) = c {
                os_str.to_string_lossy().starts_with('.')
            } else {
                false
            }
        }) {
            return false;
        }

        // Common build and output directory names to exclude
        let build_dirs: HashSet<_> = [
            "build",
            "dist",
            "target",
            "out",
            "output",
            "bin",
            "release",
            "debug",
            "builds",
            "deploy",
            "compiled",
            "coverage",
            "site-packages",
            "artifacts",
            "obj",
            "node_modules",
        ]
        .iter()
        .map(|s| s.to_lowercase())
        .collect();

        for component in file_path.components() {
            if let std::path::Component::Normal(os_str) = component {
                let part = os_str.to_string_lossy().to_lowercase();
                if build_dirs.contains(&part) {
                    return false;
                }
                if ["build", "dist", "target"]
                    .iter()
                    .any(|prefix| part.contains(prefix))
                {
                    return false;
                }
            }
        }

        let rel_path = file_path.strip_prefix(&self.repo_path).unwrap_or(file_path);
        let rel_path_str = rel_path.to_string_lossy();
        let file_name = file_path
            .file_name()
            .map(|s| s.to_string_lossy())
            .unwrap_or_default();

        for pattern in &self.ignored_patterns {
            if let Ok(glob_pattern) = Pattern::new(pattern) {
                if glob_pattern.matches(&rel_path_str) || glob_pattern.matches(&file_name) {
                    return false;
                }
            }
        }

        true
    }

    fn extract_content(&mut self) -> Result<String> {
        self.output
            .push("# Repository Content Summary\n".to_string());

        // Process documentation
        self.output.push("## Documentation\n".to_string());
        self.process_documentation()?;

        // Process source code
        self.output.push("\n## Source Code\n".to_string());
        self.process_source_code()?;

        Ok(self.output.join("\n"))
    }

    fn process_documentation(&mut self) -> Result<()> {
        let readme_path = self.repo_path.join("README.md");
        if readme_path.exists() && self.should_include_file(&readme_path) {
            if let Ok(content) = fs::read_to_string(&readme_path) {
                let content = content.trim();
                if !content.is_empty() {
                    self.output.push("\n### README.md\n".to_string());
                    self.output.push(content.to_string());
                }
            } else {
                error!("Error reading README.md");
            }
        }
        Ok(())
    }

    fn process_source_code(&mut self) -> Result<()> {
        let code_extensions = [
            "py", "js", "ts", "jsx", "tsx", "java", "cpp", "hpp", "h", "c", "cs", "go", "rs",
            "swift", "kt", "rb", "php", "scala", "clj", "ex", "exs",
        ];

        let mut source_files = Vec::new();
        for extension in code_extensions.iter() {
            let pattern = format!("**/*.{}", extension);
            if let Ok(paths) = glob::glob(&self.repo_path.join(&pattern).to_string_lossy()) {
                for entry in paths.flatten() {
                    if self.should_include_file(&entry) {
                        source_files.push(entry);
                    }
                }
            }
        }

        source_files.sort();

        for source_file in source_files {
            if let Ok(content) = fs::read_to_string(&source_file) {
                let content = content.trim();
                if !content.is_empty() {
                    let rel_path = source_file
                        .strip_prefix(&self.repo_path)
                        .unwrap_or(&source_file)
                        .display();
                    self.output.push(format!("\n### {}\n", rel_path));

                    let extension = source_file
                        .extension()
                        .and_then(|ext| ext.to_str())
                        .unwrap_or("");
                    self.output.push(format!("```{}", extension));
                    self.output.push(content.to_string());
                    self.output.push("```\n".to_string());
                }
            } else {
                error!("Error reading file: {:?}", source_file);
            }
        }

        Ok(())
    }
}

pub async fn execute(repo_path: &str, output: &str) -> Result<()> {
    let mut extractor = RepoExtractor::new(repo_path)?;
    let content = extractor.extract_content()?;

    fs::write(output, content).with_context(|| format!("Failed to write output to {}", output))?;

    info!("Content extracted successfully to: {}", output);
    Ok(())
}
