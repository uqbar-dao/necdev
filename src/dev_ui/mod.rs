use std::path::Path;
use std::process::{Command, Stdio};

use super::build::run_command;
use super::setup::{check_js_deps, get_deps, set_newest_valid_node_version, OldNodeVersion};

#[autocontext::autocontext]
pub fn execute(package_dir: &Path, url: &str, skip_deps_check: bool) -> anyhow::Result<()> {
    let _old_node_version =
        if skip_deps_check {
            OldNodeVersion::none()
        } else {
            let (deps, old_node_version) = check_js_deps()?;
            if deps.is_empty() {
                old_node_version
            } else {
                get_deps(deps)?;
                set_newest_valid_node_version(None, None)?
                    .unwrap_or(OldNodeVersion::none())
            }
        };
    let ui_path = package_dir.join("ui");
    println!("Starting development UI in {:?}...", ui_path);

    if ui_path.exists() && ui_path.is_dir() && ui_path.join("package.json").exists() {
        println!("UI directory found, running npm install...");

        run_command(Command::new("npm")
            .arg("install")
            .current_dir(&ui_path)
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
        )?;

        println!("Running npm start...");

        run_command(Command::new("npm")
            .arg("start")
            .env("VITE_NODE_URL", url)
            .current_dir(&ui_path)
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
        )?;
    } else {
        println!("'ui' directory not found or 'ui/package.json' does not exist");
    }

    Ok(())
}
