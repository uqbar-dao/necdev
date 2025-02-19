use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use color_eyre::{eyre::eyre, Result, Section};
use dirs::home_dir;
use fs_err as fs;
use tokio::sync::Mutex;
use tokio::time::{sleep, Duration};
use tracing::{debug, info, instrument};

use hyperware_process_lib::kernel_types::PackageManifestEntry;

use crate::boot_fake_node;
use crate::build;
use crate::chain;
use crate::inject_message;
use crate::start_package;

use crate::hyperware::process::tester::{FailResponse, Response as TesterResponse};

pub mod cleanup;
use cleanup::{cleanup, cleanup_on_signal, drain_print_runtime};
pub mod types;
use types::*;

impl Config {
    fn expand_home_paths(mut self: Config, config_path: &Path) -> Config {
        let config_path = config_path.parent().unwrap();
        self.runtime = match self.runtime {
            Runtime::FetchVersion(version) => Runtime::FetchVersion(version),
            Runtime::RepoPath(runtime_path) => {
                Runtime::RepoPath(expand_home_path(&runtime_path).unwrap_or_else(|| {
                    fs::canonicalize(config_path.join(&runtime_path))
                        .unwrap_or_else(|_| runtime_path)
                }))
            }
        };
        for test in self.tests.iter_mut() {
            test.test_package_paths = test
                .test_package_paths
                .iter()
                .map(|p| expand_home_path(&p).unwrap_or_else(|| p.clone()))
                .collect();
            for node in test.nodes.iter_mut() {
                node.home = expand_home_path(&node.home).unwrap_or_else(|| {
                    fs::canonicalize(config_path.join(&node.home))
                        .unwrap_or_else(|_| node.home.clone())
                });
            }
        }
        self
    }
}

#[instrument(level = "trace", skip_all)]
fn load_config(config_path: &Path) -> Result<(PathBuf, Config)> {
    // existence of path has already been checked in src/main.rs

    // cases:
    // 1. given `.toml` file
    // 2. given dir in which `tests.toml` exists
    // 3. given dir in which `test/tests.toml` exists
    let config_path = if config_path.is_file() {
        // case 1
        config_path.into()
    } else {
        let possible_config_path = config_path.join("tests.toml");
        if possible_config_path.exists() {
            // case 2
            possible_config_path
        } else {
            let possible_config_path = config_path.join("test").join("tests.toml");
            if !possible_config_path.exists() {
                return Err(eyre!(
                    "Could not find `tests.toml within given path {config_path:?}"
                ));
            }
            if possible_config_path.is_file() {
                // case 3
                possible_config_path
            } else {
                return Err(eyre!(
                    "Could not find `tests.toml within given path {config_path:?}"
                ));
            }
        }
    };

    let content = fs::read_to_string(&config_path)?;
    Ok((
        config_path.clone(),
        toml::from_str::<Config>(&content)?.expand_home_paths(&config_path),
    ))
}

fn get_basename(file_path: &Path) -> Option<&str> {
    file_path
        .file_name()
        .and_then(|file_name| file_name.to_str())
}

fn expand_home_path_string(path: &str) -> Option<String> {
    if path.starts_with("~/") {
        if let Some(home_path) = home_dir() {
            return Some(path.replacen("~", &home_path.to_string_lossy(), 1));
        }
    }
    None
}

fn expand_home_path(path: &PathBuf) -> Option<PathBuf> {
    path.as_os_str()
        .to_str()
        .and_then(|s| expand_home_path_string(s))
        .map(|s| PathBuf::from(&s))
}

#[instrument(level = "trace", skip_all)]
fn make_node_names(nodes: Vec<Node>) -> Result<Vec<String>> {
    nodes
        .iter()
        .map(|node| {
            get_basename(&node.home)
                .and_then(|base| Some(base.to_string()))
                .and_then(|mut base| {
                    if !base.contains(".") {
                        base.push_str(".dev");
                    }
                    Some(base)
                })
                .ok_or_else(|| {
                    eyre!(
                        "run_tests:make_node_names: did not find basename for {:?}",
                        node.home
                    )
                })
        })
        .collect()
}

#[instrument(level = "trace", skip_all)]
async fn setup_cleanup(detached: &bool, persist_home: &bool) -> Result<SetupCleanupReturn> {
    // Initialize variables for master node and nodes list
    let master_node_port = None;
    let mut task_handles = Vec::new();
    let node_handles = Arc::new(Mutex::new(Vec::new()));
    let node_cleanup_infos = Arc::new(Mutex::new(Vec::new()));

    // Cleanup, boot check, test loading, and running
    let (send_to_cleanup, recv_in_cleanup) = tokio::sync::mpsc::unbounded_channel();
    let (send_to_kill, _recv_kill) = tokio::sync::broadcast::channel(1);
    let recv_kill_in_cos = send_to_kill.subscribe();
    let node_cleanup_infos_for_cleanup = Arc::clone(&node_cleanup_infos);
    let node_handles_for_cleanup = Arc::clone(&node_handles);
    let send_to_kill_for_cleanup = send_to_kill.clone();
    let handle = tokio::spawn(cleanup(
        recv_in_cleanup,
        send_to_kill_for_cleanup,
        node_cleanup_infos_for_cleanup,
        Some(node_handles_for_cleanup),
        detached.clone(),
        !persist_home,
    ));
    task_handles.push(handle);
    let send_to_cleanup_for_signal = send_to_cleanup.clone();
    let handle = tokio::spawn(cleanup_on_signal(
        send_to_cleanup_for_signal,
        recv_kill_in_cos,
    ));
    task_handles.push(handle);
    let cleanup_context = CleanupContext::new(send_to_cleanup.clone());
    Ok(SetupCleanupReturn {
        send_to_cleanup,
        send_to_kill,
        task_handles,
        cleanup_context,
        master_node_port,
        node_cleanup_infos,
        node_handles,
    })
}

#[instrument(level = "trace", skip_all)]
async fn boot_nodes(
    nodes: &Vec<Node>,
    fakechain_router: &u16,
    runtime_path: &Path,
    detached: &bool,
    master_node_port: &mut Option<u16>,
    anvil_process: &Option<i32>,
    setup_scripts: &Vec<i32>,
    node_cleanup_infos: NodeCleanupInfos,
    send_to_kill: &BroadcastSendBool,
    node_handles: NodeHandles,
) -> Result<()> {
    for node in nodes {
        fs::create_dir_all(&node.home)?;
        let node_home = fs::canonicalize(&node.home)?;
        for dir in &["kernel", "kv", "sqlite", "vfs"] {
            let dir = node_home.join(dir);
            if dir.exists() {
                fs::remove_dir_all(&node_home.join(dir)).unwrap();
            }
        }

        let mut args = vec![];
        if let Some(ref rpc) = node.rpc {
            args.extend_from_slice(&["--rpc".into(), rpc.clone()]);
        };
        if let Some(ref password) = node.password {
            args.extend_from_slice(&["--password".into(), password.clone()]);
        };

        let mut name = node.fake_node_name.clone();
        if !name.contains(".") {
            name.push_str(".dev");
        }

        args.extend_from_slice(&[
            "--fake-node-name".into(),
            name,
            "--fakechain-port".into(),
            format!("{}", fakechain_router),
        ]);

        let (mut runtime_process, master_fd) = boot_fake_node::run_runtime(
            runtime_path,
            &node_home,
            node.port,
            &args[..],
            false,
            detached.clone(),
            node.runtime_verbosity.unwrap_or_else(|| 0u8),
        )?;

        let mut anvil_cleanup: Option<i32> = None;
        let mut other_processes = vec![];

        if master_node_port.is_none() {
            anvil_cleanup = anvil_process.clone();
            *master_node_port = Some(node.port);
            other_processes.extend_from_slice(setup_scripts);
        };

        {
            let mut node_cleanup_infos = node_cleanup_infos.lock().await;
            node_cleanup_infos.push(NodeCleanupInfo {
                master_fd,
                process_id: runtime_process.id().unwrap() as i32,
                home: node_home.clone(),
                anvil_process: anvil_cleanup,
                other_processes,
            });
        }

        let recv_kill_in_dpr = send_to_kill.subscribe();
        tokio::spawn(drain_print_runtime(
            runtime_process.stdout.take().unwrap(),
            runtime_process.stderr.take().unwrap(),
            recv_kill_in_dpr,
        ));

        {
            let mut node_handles = node_handles.lock().await;
            node_handles.push(runtime_process);
        }

        let recv_kill_in_wait = send_to_kill.subscribe();
        wait_until_booted(&node.home, node.port, 10, recv_kill_in_wait).await?;
    }
    Ok(())
}

#[instrument(level = "trace", skip_all)]
async fn build_packages(
    test: &Test,
    test_dir_path: &Path,
    detached: &bool,
    persist_home: &bool,
    runtime_path: &Path,
    version: &str,
) -> Result<(Vec<SetupPackage>, Vec<PathBuf>)> {
    let dependency_package_paths: Vec<PathBuf> = test
        .dependency_package_paths
        .iter()
        .cloned()
        .map(|p| match expand_home_path(&p) {
            Some(p) => p,
            None => test_dir_path.join(&p).canonicalize().unwrap(),
        })
        .collect();
    let setup_packages: Vec<SetupPackage> = test
        .setup_packages
        .iter()
        .cloned()
        .map(|s| SetupPackage {
            path: test_dir_path.join(s.path).canonicalize().unwrap(),
            run: s.run,
        })
        .collect();
    let test_package_paths: Vec<PathBuf> = test
        .test_package_paths
        .iter()
        .cloned()
        .map(|p| test_dir_path.join(p).canonicalize().unwrap())
        .collect();

    info!("Starting node to host dependencies...");
    let port = test.nodes[0].port.clone();
    let home = PathBuf::from("/tmp/hyperware-fake-node");
    let nodes = vec![Node {
        port: port.clone(),
        home,
        fake_node_name: "fake.dev".into(),
        password: None,
        rpc: None,
        runtime_verbosity: Some(2),
    }];

    let SetupCleanupReturn {
        send_to_cleanup,
        send_to_kill,
        task_handles,
        cleanup_context: _cleanup_context,
        mut master_node_port,
        node_cleanup_infos,
        node_handles,
    } = setup_cleanup(detached, persist_home).await?;

    // boot fakechain
    let recv_kill_in_start_chain = send_to_kill.subscribe();
    let version = Some(version.parse()?);
    let anvil_process = chain::start_chain(
        test.fakechain_router,
        recv_kill_in_start_chain,
        version,
        false,
    )
    .await?;

    boot_nodes(
        &nodes,
        &test.fakechain_router,
        &runtime_path,
        &detached,
        &mut master_node_port,
        &anvil_process.as_ref().map(|ap| ap.id() as i32),
        &vec![],
        Arc::clone(&node_cleanup_infos),
        &send_to_kill,
        Arc::clone(&node_handles),
    )
    .await?;
    info!("Done starting node to host dependencies.");

    let url = format!("http://localhost:{port}");

    for dependency_package_path in &test.dependency_package_paths {
        let path = match expand_home_path(&dependency_package_path) {
            Some(p) => p,
            None => test_dir_path
                .join(&dependency_package_path)
                .canonicalize()?,
        };
        debug!("Build {path:?}");
        build::execute(
            &path,
            false,
            false,
            &HashSet::new(),
            &HashSet::new(),
            false,
            "test",
            Some(url.clone()),
            None,
            None,
            dependency_package_paths.clone(),
            vec![], // TODO
            false,
            false,
            false,
            false,
            false,
        )
        .await?;
        debug!("Start {path:?}");
        start_package::execute(&path, &url).await?;
    }

    for setup_package in &setup_packages {
        build::execute(
            &setup_package.path,
            false,
            false,
            &HashSet::new(),
            &HashSet::new(),
            false,
            "test",
            Some(url.clone()),
            None,
            None,
            dependency_package_paths.clone(),
            vec![], // TODO
            false,
            false,
            false,
            false,
            false,
        )
        .await?;
    }
    for test_package_path in &test_package_paths {
        build::execute(
            &test_package_path,
            false,
            false,
            &HashSet::new(),
            &HashSet::new(),
            false,
            "test",
            Some(url.clone()),
            None,
            None,
            dependency_package_paths.clone(),
            vec![], // TODO
            false,
            false,
            false,
            false,
            false,
        )
        .await?;
    }

    info!("Cleaning up node to host dependencies.");
    let _ = send_to_cleanup.send(false);
    for handle in task_handles {
        handle.await.unwrap();
    }

    Ok((setup_packages, test_package_paths))
}

#[instrument(level = "trace", skip_all)]
async fn wait_until_booted(
    node: &PathBuf,
    port: u16,
    max_waits: u16,
    mut recv_kill_in_wait: BroadcastRecvBool,
) -> Result<()> {
    info!(
        "Waiting for node {:?} on port {} to be ready...",
        node, port
    );
    for _ in 0..max_waits {
        let request = inject_message::make_message(
            "vfs:distro:sys",
            Some(15),
            &serde_json::to_string(&serde_json::json!({
                "path": "/tester:sys/tests",
                "action": "ReadDir",
            }))
            .unwrap(),
            None,
            None,
            None,
        )?;

        match inject_message::send_request_inner(&format!("http://localhost:{}", port), request)
            .await
        {
            Ok(response) => match inject_message::parse_response(response).await {
                Ok(_) => {
                    info!("Done waiting for node {:?} on port {}.", node, port);
                    return Ok(());
                }
                _ => (),
            },
            _ => (),
        }

        tokio::select! {
            _ = sleep(Duration::from_secs(1)) => {}
            _ = recv_kill_in_wait.recv() => {
                return Err(eyre!("received exit"));
            }
        };
    }
    Err(eyre!("kit run-tests: could not connect to node"))
}

#[instrument(level = "trace", skip_all)]
async fn load_setups(setup_paths: &Vec<SetupPackage>, port: u16) -> Result<()> {
    info!("Loading setup packages...");

    for setup_path in setup_paths {
        if setup_path.run {
            start_package::execute(&setup_path.path, &format!("http://localhost:{}", port)).await?;
        }
        load_process(&setup_path.path, "setup", &port).await?;
    }

    info!("Done loading setup packages.");
    Ok(())
}

#[instrument(level = "trace", skip_all)]
async fn load_process(path: &Path, drive: &str, port: &u16) -> Result<()> {
    for entry in fs::read_dir(path.join("pkg"))? {
        let entry = entry?;
        let path = entry.path();
        if Some("wasm") == path.extension().and_then(|s| s.to_str()) {
            debug!("include path {:?}", path);
            let file_name = path
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or_default();
            let request = inject_message::make_message(
                "vfs:distro:sys",
                Some(15),
                &serde_json::to_string(&serde_json::json!({
                    "path": format!("/tester:sys/{drive}/{file_name}"),
                    "action": "Write",
                }))
                .unwrap(),
                None,
                None,
                path.to_str(),
            )?;

            let response =
                inject_message::send_request(&format!("http://localhost:{}", port), request)
                    .await?;
            match inject_message::parse_response(response).await {
                Ok(_) => {}
                Err(e) => return Err(eyre!("Failed to load test {path:?}: {}", e)),
            }
        }
    }
    Ok(())
}

#[instrument(level = "trace", skip_all)]
async fn load_caps(test_package_paths: &Vec<PathBuf>, port: u16) -> Result<()> {
    let mut caps = std::collections::HashMap::new();
    for test_package_path in test_package_paths {
        let manifest_path = test_package_path.join("pkg").join("manifest.json");

        let manifest = fs::File::open(manifest_path)
            .with_suggestion(|| "Missing required manifest.json file. See discussion at https://book.hyperware.ai/my_first_app/chapter_1.html?highlight=manifest.json#pkgmanifestjson")?;
        let manifest: Vec<PackageManifestEntry> = serde_json::from_reader(manifest)
            .with_suggestion(|| "Failed to parse required manifest.json file. See discussion at https://book.hyperware.ai/my_first_app/chapter_1.html?highlight=manifest.json#pkgmanifestjson")?;
        if manifest.len() != 1 {
            return Err(eyre!(""));
        }
        let manifest = manifest.iter().next().unwrap();
        caps.insert(
            test_package_path.file_name().map(|f| f.to_str()).unwrap(),
            serde_json::json!({
                "request_capabilities": manifest.request_capabilities,
                "grant_capabilities": manifest.grant_capabilities,
            }),
        );
    }
    let caps = serde_json::to_vec(&caps)?;

    let request = inject_message::make_message(
        "vfs:distro:sys",
        Some(15),
        &serde_json::to_string(&serde_json::json!({
            "path": format!("/tester:sys/tests/capabilities.json"),
            "action": "Write",
        }))
        .unwrap(),
        None,
        Some(&caps),
        None,
    )?;

    let response =
        inject_message::send_request(&format!("http://localhost:{}", port), request).await?;
    match inject_message::parse_response(response).await {
        Ok(_) => {}
        Err(e) => return Err(eyre!("Failed to load tests capabilities: {}", e)),
    }

    Ok(())
}

#[instrument(level = "trace", skip_all)]
async fn load_tests(test_package_paths: &Vec<PathBuf>, port: u16) -> Result<()> {
    info!("Loading tests...");

    for test_package_path in test_package_paths {
        load_process(&test_package_path, "tests", &port).await?;
    }

    load_caps(test_package_paths, port).await?;

    info!("Done loading tests.");
    Ok(())
}

#[instrument(level = "trace", skip_all)]
async fn run_tests(
    test_package_paths: &Vec<PathBuf>,
    mut ports: Vec<u16>,
    node_names: Vec<String>,
    test_timeout: u64,
) -> Result<()> {
    let master_port = ports.remove(0);

    // Set up non-master nodes.
    for port in ports {
        let request = inject_message::make_message(
            "tester:tester:sys",
            Some(15),
            &serde_json::to_string(&serde_json::json!({
                "Run": {
                    "input_node_names": node_names,
                    "test_names": test_package_paths
                        .iter()
                        .map(|p| p.to_str().unwrap())
                        .collect::<Vec<&str>>(),
                    "test_timeout": test_timeout,
                }
            }))
            .unwrap(),
            None,
            None,
            None,
        )?;
        let response =
            inject_message::send_request(&format!("http://localhost:{}", port), request).await?;

        if response.status() != 200 {
            return Err(eyre!("Failed with status code: {}", response.status()));
        }
    }

    // Set up master node & start tests.
    info!("Running tests...");
    let request = inject_message::make_message(
        "tester:tester:sys",
        Some(15),
        &serde_json::to_string(&serde_json::json!({
            "Run": {
                "input_node_names": node_names,
                "test_names": test_package_paths
                    .iter()
                    .map(|p| p.file_name().and_then(|s| s.to_str()).unwrap())
                    .collect::<Vec<&str>>(),
                "test_timeout": test_timeout,
            }
        }))
        .unwrap(),
        None,
        None,
        None,
    )?;
    let response =
        inject_message::send_request(&format!("http://localhost:{}", master_port), request).await?;

    match inject_message::parse_response(response).await {
        Ok(inject_message::Response { ref body, .. }) => {
            let TesterResponse::Run(result) = serde_json::from_str(body)?;
            match result {
                Ok(()) => {}
                Err(FailResponse {
                    test,
                    file,
                    line,
                    column,
                }) => {
                    return Err(eyre!("FAIL: {} {}:{}:{}", test, file, line, column));
                }
            }
        }
        Err(e) => {
            return Err(eyre!("FAIL: {}", e));
        }
    };

    Ok(())
}

#[instrument(level = "trace", skip_all)]
async fn handle_test(
    detached: bool,
    runtime_path: &Path,
    version: &str,
    test: Test,
    test_dir_path: &Path,
    persist_home: bool,
    always_print_node_output: bool,
) -> Result<()> {
    let (setup_packages, test_package_paths) = build_packages(
        &test,
        test_dir_path,
        &detached,
        &persist_home,
        runtime_path,
        version,
    )
    .await?;

    let SetupCleanupReturn {
        send_to_cleanup,
        send_to_kill,
        task_handles,
        cleanup_context: _cleanup_context,
        mut master_node_port,
        node_cleanup_infos,
        node_handles,
    } = setup_cleanup(&detached, &persist_home).await?;

    let setup_scripts: Vec<i32> = test
        .setup_scripts
        .iter()
        .map(|script| {
            let command = script
                .split_whitespace()
                .map(|item| {
                    test_dir_path
                        .join(&item)
                        .canonicalize()
                        .ok()
                        .and_then(|p| p.to_str().map(|s| s.to_string()))
                        .unwrap_or_else(|| item.to_string())
                })
                .collect::<Vec<String>>()
                .join(" ");
            Command::new("bash")
                .args(["-c", &command])
                .spawn()
                .expect("")
                .id() as i32
        })
        .collect();

    // boot fakechain
    let recv_kill_in_start_chain = send_to_kill.subscribe();
    let version = Some(version.parse()?);
    let anvil_process = chain::start_chain(
        test.fakechain_router,
        recv_kill_in_start_chain,
        version,
        false,
    )
    .await?;

    // Process each node
    boot_nodes(
        &test.nodes,
        &test.fakechain_router,
        &runtime_path,
        &detached,
        &mut master_node_port,
        &anvil_process.as_ref().map(|ap| ap.id() as i32),
        &setup_scripts,
        Arc::clone(&node_cleanup_infos),
        &send_to_kill,
        Arc::clone(&node_handles),
    )
    .await?;

    for node in &test.nodes {
        load_setups(&setup_packages, node.port.clone()).await?;
    }

    load_tests(&test_package_paths, master_node_port.unwrap().clone()).await?;

    let ports = test.nodes.iter().map(|n| n.port).collect();

    let tests_result = run_tests(
        &test.test_package_paths,
        ports,
        make_node_names(test.nodes)?,
        test.timeout_secs,
    )
    .await;

    for script in test.test_scripts {
        let command = script
            .split_whitespace()
            .map(|item| {
                test_dir_path
                    .join(&item)
                    .canonicalize()
                    .ok()
                    .and_then(|p| p.to_str().map(|s| s.to_string()))
                    .unwrap_or_else(|| item.to_string())
            })
            .collect::<Vec<String>>()
            .join(" ");
        build::run_command(Command::new("bash").args(["-c", &command]), false)?;
    }

    if tests_result.is_ok() {
        info!("PASS");
    }

    let _ = send_to_cleanup.send(always_print_node_output || tests_result.is_err());
    for handle in task_handles {
        handle.await.unwrap();
    }

    tests_result?;
    Ok(())
}

#[instrument(level = "trace", skip_all)]
pub async fn execute(config_path: PathBuf) -> Result<()> {
    let detached = true; // TODO: to arg?

    let (config_path, config) = load_config(&config_path)?;

    debug!("{:?}", std::env::current_dir());
    debug!("{:?}", config);

    // TODO: factor out with boot_fake_node?
    let (runtime_path, version) = match config.runtime {
        Runtime::FetchVersion(ref version) => {
            boot_fake_node::get_runtime_binary(version, true).await?
        }
        Runtime::RepoPath(runtime_path) => {
            if !runtime_path.exists() {
                return Err(eyre!("RepoPath {:?} does not exist.", runtime_path));
            }
            let runtime_path = if runtime_path.is_dir() {
                // Compile the runtime binary
                boot_fake_node::compile_runtime(&runtime_path, config.runtime_build_release, true)?;
                runtime_path
                    .join("target")
                    .join(if config.runtime_build_release {
                        "release"
                    } else {
                        "debug"
                    })
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
                .unwrap()
                .split(' ')
                .last()
                .unwrap();
            (runtime_path, version.to_string())
        }
    };
    let version = version.strip_prefix("v").unwrap_or_else(|| &version);

    let test_dir_path = PathBuf::from(config_path).canonicalize()?;
    let test_dir_path = test_dir_path.parent().unwrap();
    for test in config.tests {
        handle_test(
            detached,
            &runtime_path,
            &version,
            test,
            &test_dir_path,
            config.persist_home,
            config.always_print_node_output,
        )
        .await?;
    }

    Ok(())
}
