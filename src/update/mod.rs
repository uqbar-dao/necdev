use std::process::Command;

use color_eyre::Result;
use fs_err as fs;
use tracing::instrument;

use crate::build::run_command;
use crate::KIT_CACHE;

#[instrument(level = "trace", skip_all)]
pub fn execute(mut user_args: Vec<String>, branch: &str) -> Result<()> {
    let mut args: Vec<String> = vec![
        "install",
        "--git",
        "https://github.com/hyperware-ai/kit",
        "--locked",
        "--branch",
        branch,
        "--color=always",
    ]
    .iter()
    .map(|v| v.to_string())
    .collect();
    args.append(&mut user_args);

    run_command(Command::new("cargo").args(&args[..]), true)?;

    let cache_path = format!("{}/hyperware-ai-kit-commits", KIT_CACHE);
    let cache_path = std::path::Path::new(&cache_path);
    if cache_path.exists() {
        fs::remove_dir_all(&cache_path)?;
    }
    Ok(())
}
