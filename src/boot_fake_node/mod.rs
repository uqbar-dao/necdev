use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::io::{FromRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::Duration;
use zip::read::ZipArchive;

use color_eyre::{
    eyre::{eyre, Result, WrapErr},
    Section,
};
use fs_err as fs;
use semver::Version;
use serde::Deserialize;
use tokio::process::{Child, Command as TCommand};
use tokio::sync::Mutex;
use tracing::{info, instrument, warn};

use crate::build;
use crate::chain;
use crate::run_tests::cleanup::{cleanup, cleanup_on_signal};
use crate::run_tests::types::*;
use crate::KIT_CACHE;

const HYPERDRIVE_RELEASE_BASE_URL: &str =
    "https://github.com/hyperware-ai/hyperdrive/releases/download";
pub const HYPERWARE_OWNER: &str = "hyperware-ai";
const HYPERDRIVE_REPO: &str = "hyperdrive";
const LOCAL_PREFIX: &str = "hyperdrive-";
pub const CACHE_EXPIRY_SECONDS: u64 = 300;

#[derive(Deserialize, Debug)]
pub struct Release {
    pub tag_name: String,
    pub assets: Vec<Asset>,
}

#[derive(Deserialize, Debug)]
pub struct Asset {
    pub name: String,
}

#[instrument(level = "trace", skip_all)]
pub fn extract_zip(archive_path: &Path) -> Result<()> {
    let file = fs::File::open(archive_path)?;
    let mut archive = ZipArchive::new(file)?;

    let archive_dir = archive_path.parent().unwrap_or_else(|| Path::new(""));

    for i in 0..archive.len() {
        let mut file = archive.by_index(i)?;
        let outpath = match file.enclosed_name() {
            Some(path) => path.to_owned(),
            None => continue,
        };
        let outpath = archive_dir.join(outpath);

        if file.name().ends_with('/') {
            fs::create_dir_all(&outpath)?;
        } else {
            if let Some(p) = outpath.parent() {
                if !p.exists() {
                    fs::create_dir_all(&p)?;
                }
            }
            let mut outfile = fs::File::create(&outpath)?;
            io::copy(&mut file, &mut outfile)?;
        }
    }

    fs::remove_file(archive_path)?;

    Ok(())
}

#[instrument(level = "trace", skip_all)]
pub fn compile_runtime(path: &Path, release: bool, is_simulation_mode: bool) -> Result<()> {
    info!("Compiling Hyperdrive...");

    // build the packages
    let mut args = vec!["run", "-p", "build-packages"];
    if is_simulation_mode {
        args.extend_from_slice(&["--", "--features", "simulation-mode"]);
    }
    build::run_command(Command::new("cargo").args(&args).current_dir(path), false)?;

    // build the runtime
    let mut args = vec!["build", "-p", "hyperdrive", "--color=always"];
    if release {
        args.push("--release");
    }
    if is_simulation_mode {
        args.extend_from_slice(&["--features", "simulation-mode"]);
    }

    let mut command = Command::new("cargo");
    command.args(&args).current_dir(path);
    if is_simulation_mode {
        command.env(
            "PATH_TO_PACKAGES_ZIP",
            "target/packages-simulation-mode.zip",
        );
    }
    build::run_command(&mut command, false)?;

    info!("Done compiling Hyperdrive.");
    Ok(())
}

#[instrument(level = "trace", skip_all)]
async fn get_runtime_binary_inner(
    version: &str,
    zip_name: &str,
    runtime_dir: &PathBuf,
) -> Result<()> {
    let url = format!("{HYPERDRIVE_RELEASE_BASE_URL}/{version}/{zip_name}");

    let runtime_zip_path = runtime_dir.join(zip_name);
    let runtime_path = runtime_dir.join("hyperdrive");

    build::download_file(&url, &runtime_zip_path).await?;
    extract_zip(&runtime_zip_path)?;

    // Add execute permission
    let metadata = fs::metadata(&runtime_path)?;
    let mut permissions = metadata.permissions();
    permissions.set_mode(permissions.mode() | 0o111);
    fs::set_permissions(&runtime_path, permissions)?;

    Ok(())
}

#[instrument(level = "trace", skip_all)]
pub fn get_platform_runtime_name(is_simulation_mode: bool) -> Result<String> {
    let uname = Command::new("uname").output()?;
    if !uname.status.success() {
        return Err(eyre!("Could not determine OS."));
    }
    let os_name = std::str::from_utf8(&uname.stdout)?.trim();

    let uname_m = Command::new("uname").arg("-m").output()?;
    if !uname_m.status.success() {
        return Err(eyre!("Could not determine architecture."));
    }
    let architecture_name = std::str::from_utf8(&uname_m.stdout)?.trim();

    // TODO: update when have binaries
    let zip_name_midfix = match (os_name, architecture_name) {
        ("Linux", "x86_64") => "x86_64-unknown-linux-gnu",
        ("Linux", "aarch64") => "aarch64-unknown-linux-gnu",
        ("Darwin", "arm64") => "arm64-apple-darwin",
        ("Darwin", "x86_64") => "x86_64-apple-darwin",
        _ => {
            return Err(eyre!(
                "OS/Architecture {}/{} not amongst pre-built [Linux/x86_64, Linux/aarch64, Apple/arm64, Apple/x86_64].",
                os_name,
                architecture_name,
            ).with_suggestion(|| "Use the `--runtime-path` flag to build a local copy of the https://github.com/hyperware-ai/hyperdrive repo")
            );
        }
    };
    Ok(format!(
        "hyperdrive-{}{}.zip",
        zip_name_midfix,
        if is_simulation_mode {
            "-simulation-mode"
        } else {
            ""
        },
    ))
}

#[instrument(level = "trace", skip_all)]
pub async fn get_runtime_binary(
    version: &str,
    is_simulation_mode: bool,
) -> Result<(PathBuf, String)> {
    let zip_name = get_platform_runtime_name(is_simulation_mode)?;

    let version = if version != "latest" {
        version.to_string()
    } else {
        find_releases_with_asset_if_online(
            Some(HYPERWARE_OWNER),
            Some(HYPERDRIVE_REPO),
            &get_platform_runtime_name(is_simulation_mode)?,
        )
        .await
        .unwrap_or_default()
        .first()
        .ok_or_else(|| eyre!("No releases found"))?
        .clone()
    };

    let runtime_dir = PathBuf::from(KIT_CACHE).join(format!(
        "{}{}{}",
        LOCAL_PREFIX,
        version,
        if is_simulation_mode {
            "-simulation-mode"
        } else {
            ""
        },
    ));
    let runtime_path = runtime_dir.join("hyperdrive");

    if !runtime_dir.exists() {
        fs::create_dir_all(&runtime_dir)?;
    }
    if !runtime_path.exists() {
        get_runtime_binary_inner(&version, &zip_name, &runtime_dir).await?;
    }

    Ok((runtime_path, version))
}

#[instrument(level = "trace", skip_all)]
pub async fn get_from_github(owner: &str, repo: &str, endpoint: &str) -> Result<Vec<u8>> {
    let cache_path = format!("{}/{}-{}-{}.bin", KIT_CACHE, owner, repo, endpoint);
    let cache_path = Path::new(&cache_path);
    if cache_path.exists() {
        if let Some(local_bytes) = fs::metadata(&cache_path)
            .ok()
            .and_then(|m| m.modified().ok())
            .and_then(|m| m.elapsed().ok())
            .and_then(|since_modified| {
                if since_modified < Duration::from_secs(CACHE_EXPIRY_SECONDS) {
                    fs::read(&cache_path).ok()
                } else {
                    None
                }
            })
        {
            return Ok(local_bytes);
        }
    }

    let url = format!("https://api.github.com/repos/{owner}/{repo}/{endpoint}");
    let client = reqwest::Client::new();
    match client
        .get(url)
        .header("User-Agent", "request")
        .send()
        .await?
        .bytes()
        .await
    {
        Ok(v) => {
            let v = v.to_vec();
            if let Ok(s) = String::from_utf8(v.clone()) {
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(&s) {
                    if let serde_json::Value::String(ref s) = json["message"] {
                        if s.contains("API rate limit exceeded") {
                            warn!("GitHub throttled: can't fetch {owner}/{repo}/{endpoint}");
                            return Ok(vec![]);
                        }
                    }
                }
                if s.contains("No server is currently available to service your request.") {
                    warn!("Couldn't reach GitHub");
                    return Ok(vec![]);
                }
            }
            fs::create_dir_all(
                cache_path
                    .parent()
                    .ok_or_else(|| eyre!("path doesn't have parent"))?,
            )?;
            fs::write(&cache_path, &v)?;
            return Ok(v);
        }
        Err(_) => {
            warn!("GitHub throttled: can't fetch {owner}/{repo}/{endpoint}");
            return Ok(vec![]);
        }
    };
}

#[instrument(level = "trace", skip_all)]
pub async fn fetch_releases(owner: &str, repo: &str) -> Result<Vec<Release>> {
    let bytes = get_from_github(owner, repo, "releases").await?;
    if bytes.is_empty() {
        return Ok(vec![]);
    }
    Ok(serde_json::from_slice(&bytes)?)
}

#[instrument(level = "trace", skip_all)]
pub async fn find_releases_with_asset(
    owner: Option<&str>,
    repo: Option<&str>,
    asset_name: &str,
) -> Result<Vec<String>> {
    let owner = owner.unwrap_or(HYPERWARE_OWNER);
    let repo = repo.unwrap_or(HYPERDRIVE_REPO);
    let Ok(releases) = fetch_releases(owner, repo).await else {
        warn!("Failed to fetch releases from {owner}/{repo}. Using empty");
        return Ok(vec![]);
    };
    let filtered_releases: Vec<String> = releases
        .into_iter()
        .filter(|release| release.assets.iter().any(|asset| asset.name == asset_name))
        .map(|release| release.tag_name)
        .collect();
    Ok(filtered_releases)
}

pub async fn find_releases_with_asset_if_online(
    owner: Option<&str>,
    repo: Option<&str>,
    asset_name: &str,
) -> Result<Vec<String>> {
    let remote_values = match find_releases_with_asset(owner, repo, asset_name).await {
        Ok(v) => v,
        Err(e) => match e.downcast_ref::<reqwest::Error>() {
            None => return Err(e),
            Some(ee) => {
                if ee.is_connect() {
                    get_local_versions_with_prefix(&format!("{}v", LOCAL_PREFIX))?
                        .iter()
                        .map(|v| format!("v{}", v))
                        .collect()
                } else {
                    return Err(e);
                }
            }
        },
    };
    Ok(remote_values)
}

#[instrument(level = "trace", skip_all)]
fn get_local_versions_with_prefix(prefix: &str) -> Result<Vec<String>> {
    let mut versions = Vec::new();

    let path = Path::new(KIT_CACHE);
    for entry in fs::read_dir(&path)? {
        let entry = entry?;
        let path = entry.path();
        if let Some(str_path) = path.to_str() {
            if str_path.starts_with(prefix) {
                let version = str_path.replace(prefix, "");
                versions.push(version);
            }
        }
    }

    let mut sorted_versions: Vec<Version> = versions
        .into_iter()
        .filter_map(|s| Version::parse(&s).ok())
        .collect();
    sorted_versions.sort();

    let versions = sorted_versions
        .into_iter()
        .rev()
        .map(|v| v.to_string())
        .collect();

    Ok(versions)
}

#[instrument(level = "trace", skip_all)]
pub fn run_runtime(
    path: &Path,
    home: &Path,
    port: u16,
    args: &[String],
    verbose: bool,
    detached: bool,
    verbosity: u8,
) -> Result<(Child, OwnedFd)> {
    let mut full_args = vec![
        home.to_str().unwrap().into(),
        "--port".into(),
        format!("{port}"),
        "--verbosity".into(),
        format!("{verbosity}"),
    ];

    if !args.is_empty() {
        full_args.extend_from_slice(args);
    }

    let fds = nix::pty::openpty(None, None)?;

    let process = TCommand::new(path)
        .args(&full_args)
        .stdin(if !detached {
            Stdio::inherit()
        } else {
            unsafe { Stdio::from_raw_fd(fds.slave.as_raw_fd()) }
        })
        .stdout(if verbose {
            Stdio::inherit()
        } else {
            Stdio::piped()
        })
        .stderr(if verbose {
            Stdio::inherit()
        } else {
            Stdio::piped()
        })
        .spawn()
        .wrap_err_with(|| format!("Couldn't open binary at path {:?}", path))?;

    Ok((process, fds.master))
}

#[instrument(level = "trace", skip_all)]
pub async fn execute(
    runtime_path: Option<PathBuf>,
    version: String,
    node_home: PathBuf,
    node_port: u16,
    fakechain_port: u16,
    rpc: Option<&str>,
    mut fake_node_name: String,
    password: &str,
    is_persist: bool,
    release: bool,
    verbosity: u8,
    mut args: Vec<String>,
) -> Result<()> {
    println!("a");
    let detached = false; // TODO: to argument?
                          // TODO: factor out with run_tests?
    let (runtime_path, version) = match runtime_path {
        None => get_runtime_binary(&version, true).await?,
        Some(runtime_path) => {
            println!("b");
            if !runtime_path.exists() {
                return Err(eyre!("--runtime-path {:?} does not exist.", runtime_path));
            }
            let runtime_path = if runtime_path.is_dir() {
                // Compile the runtime binary
                compile_runtime(&runtime_path, release, true)?;
                runtime_path
                    .join("target")
                    .join(if release { "release" } else { "debug" })
                    .join("hyperdrive")
            } else {
                runtime_path
            };
            let Some((output, _)) = build::run_command(
                Command::new("bash").args(["-c", &format!("{} --version", runtime_path.display())]),
                false,
            )?
            else {
                return Err(eyre!("couldn't get Hyperdrive version"));
            };
            let version = output
                .split('\n')
                .nth(0)
                //.rev()
                //.nth(1)
                .unwrap()
                .split(' ')
                .last()
                .unwrap();
            (runtime_path, version.to_string())
        }
    };
    let version = version.strip_prefix("v").unwrap_or_else(|| &version);

    let mut task_handles = Vec::new();

    let node_cleanup_infos = Arc::new(Mutex::new(Vec::new()));

    let (send_to_cleanup, recv_in_cleanup) = tokio::sync::mpsc::unbounded_channel();
    let (send_to_kill, _recv_kill) = tokio::sync::broadcast::channel(1);
    let recv_kill_in_cos = send_to_kill.subscribe();
    let recv_kill_in_start_chain = send_to_kill.subscribe();

    let node_cleanup_infos_for_cleanup = Arc::clone(&node_cleanup_infos);
    let handle = tokio::spawn(cleanup(
        recv_in_cleanup,
        send_to_kill,
        node_cleanup_infos_for_cleanup,
        None,
        detached,
        !is_persist,
    ));
    task_handles.push(handle);
    let send_to_cleanup_for_signal = send_to_cleanup.clone();
    let handle = tokio::spawn(cleanup_on_signal(
        send_to_cleanup_for_signal,
        recv_kill_in_cos,
    ));
    task_handles.push(handle);
    let send_to_cleanup_for_cleanup = send_to_cleanup.clone();
    let _cleanup_context = CleanupContext::new(send_to_cleanup_for_cleanup);

    if !fake_node_name.contains(".") {
        fake_node_name.push_str(".dev");
    }

    // boot fakechain
    let version = version.parse()?;
    let anvil_process = chain::start_chain(
        fakechain_port,
        recv_kill_in_start_chain,
        Some(version),
        false,
    )
    .await?;

    if let Some(rpc) = rpc {
        args.extend_from_slice(&["--rpc".into(), rpc.into()]);
    };

    args.extend_from_slice(&[
        "--password".into(),
        password.into(),
        "--fake-node-name".into(),
        fake_node_name,
        "--fakechain-port".into(),
        format!("{fakechain_port}"),
    ]);

    let (mut runtime_process, master_fd) = run_runtime(
        &runtime_path,
        &node_home,
        node_port,
        &args[..],
        true,
        detached,
        verbosity,
    )?;

    let mut node_cleanup_infos = node_cleanup_infos.lock().await;
    node_cleanup_infos.push(NodeCleanupInfo {
        master_fd,
        process_id: runtime_process.id().unwrap() as i32,
        home: node_home.clone(),
        anvil_process: anvil_process.map(|ap| ap.id() as i32),
        other_processes: vec![],
    });
    drop(node_cleanup_infos);

    runtime_process.wait().await.unwrap();
    let _ = send_to_cleanup.send(true);
    for handle in task_handles {
        handle.await.unwrap();
    }

    Ok(())
}
