use std::path::PathBuf;
use std::sync::Arc;

use color_eyre::eyre::{eyre, Result};
use tokio::sync::Mutex;
use tracing::instrument;

use crate::boot_fake_node::{compile_runtime, get_runtime_binary, run_runtime};
use crate::run_tests::cleanup::{cleanup, cleanup_on_signal};
use crate::run_tests::types::*;

#[instrument(level = "trace", skip_all)]
pub async fn execute(
    runtime_path: Option<PathBuf>,
    version: String,
    node_home: PathBuf,
    node_port: u16,
    rpc: Option<&str>,
    // password: &str, // TODO: with develop 0.8.0
    release: bool,
    verbosity: u8,
    mut args: Vec<String>,
) -> Result<()> {
    let detached = false; // TODO: to argument?
                          // TODO: factor out with run_tests?
    let runtime_path = match runtime_path {
        None => {
            let (runtime_path, _) = get_runtime_binary(&version, false).await?;
            runtime_path
        }
        Some(runtime_path) => {
            if !runtime_path.exists() {
                return Err(eyre!("--runtime-path {:?} does not exist.", runtime_path));
            }
            if runtime_path.is_dir() {
                // Compile the runtime binary
                compile_runtime(&runtime_path, release, false)?;
                runtime_path
                    .join("target")
                    .join(if release { "release" } else { "debug" })
                    .join("hyperdrive")
            } else {
                runtime_path
            }
        }
    };

    let mut task_handles = Vec::new();

    let node_cleanup_infos = Arc::new(Mutex::new(Vec::new()));

    let (send_to_cleanup, recv_in_cleanup) = tokio::sync::mpsc::unbounded_channel();
    let (send_to_kill, _recv_kill) = tokio::sync::broadcast::channel(1);
    let recv_kill_in_cos = send_to_kill.subscribe();

    let node_cleanup_infos_for_cleanup = Arc::clone(&node_cleanup_infos);
    let handle = tokio::spawn(cleanup(
        recv_in_cleanup,
        send_to_kill,
        node_cleanup_infos_for_cleanup,
        None,
        detached,
        false,
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

    if let Some(rpc) = rpc {
        args.extend_from_slice(&["--rpc".into(), rpc.into()]);
    };

    // args.extend_from_slice(&["--password", password]); // TODO: with develop 0.8.0

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
        anvil_process: None,
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
