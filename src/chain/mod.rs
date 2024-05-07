use color_eyre::eyre::{eyre, Result};
use fs_err as fs;
// use std::io::BufRead;
use std::net::TcpListener;
use std::process::{Child, Command};

use crate::run_tests::cleanup::{cleanup_on_signal, clean_process_by_pid};
use crate::{KIT_CACHE, KIT_KINOSTATE_PATH_DEFAULT};

pub const KINOSTATE_JSON: &str = include_str!("./kinostate.json");

pub async fn fetch_kinostate() -> Result<()> {
    let json_path = KIT_KINOSTATE_PATH_DEFAULT;

    if fs::metadata(json_path).is_ok() {
    } else {
        fs::write(&json_path, KINOSTATE_JSON)?;
    }
    Ok(())
}

pub async fn start_chain(port: u16) -> Result<Child> {
    let child = match TcpListener::bind(("127.0.0.1", port)) {
        Ok(_) => {
            let child = Command::new("anvil")
                .arg("--port")
                .arg(port.to_string())
                .arg("--load-state")
                .arg(KIT_KINOSTATE_PATH_DEFAULT)
                .stdout(std::process::Stdio::piped())
                .spawn()?;

            // CURRENTLY BREAKING PIPES:....
            // let stdout = child.stdout.take().ok_or_else(|| eyre!("Failed to capture stdout"))?;
            // let reader = std::io::BufReader::new(stdout);
            // tokio::spawn(async move {
            //     for line in reader.lines() {
            //         if let Ok(line) = line {
            //             if line.contains("Listening") {
            //                 println!("anvil spawned properly");
            //                 break;
            //             }                    
            //         }
            //     }
            // }).await?;
            Ok(child)
        }
        Err(e) => Err(eyre!("Port {} is already in use: {}", port, e)),
    };

    std::thread::sleep(std::time::Duration::from_millis(1000));
    child
}

/// kit chain, alias to anvil
pub async fn execute(port: u16) -> Result<()> {
    fetch_kinostate().await?;

    let mut child = Command::new("anvil")
        .arg("--port")
        .arg(port.to_string())
        .current_dir(KIT_CACHE)
        .arg("--load-state")
        .arg("./kinostate.json")
        .spawn()?;    
    let child_id = child.id() as i32;

    let (send_to_cleanup, mut recv_in_cleanup) = tokio::sync::mpsc::unbounded_channel();
    let (send_to_kill, _recv_kill) = tokio::sync::broadcast::channel(1);
    let recv_kill_in_cos = send_to_kill.subscribe();

    let handle_signals = tokio::spawn(cleanup_on_signal(send_to_cleanup.clone(), recv_kill_in_cos));

    let cleanup_anvil = tokio::spawn(async move {
        let status = child.wait();
        clean_process_by_pid(child_id);
        status
    });

    tokio::select! {
        _ = handle_signals => {}
        _ = cleanup_anvil => {}
        _ = recv_in_cleanup.recv() => {}
    }

    let _ = send_to_kill.send(true);

    Ok(())
}
