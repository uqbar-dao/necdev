use std::process::{Child, Command, Stdio};

use color_eyre::{
    eyre::{eyre, Result},
    Section,
};
use reqwest::Client;
use tokio::time::{sleep, Duration};
use tracing::{info, instrument};

use crate::run_tests::cleanup::{clean_process_by_pid, cleanup_on_signal};
use crate::run_tests::types::BroadcastRecvBool;
use crate::setup::{check_foundry_deps, get_deps};
use crate::KIT_CACHE;

const OWNER_ADDRESS: &str = "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"; // first account on anvil
const DOT_OS_TBA: &str = "0xbE46837617f8304Aa5E6d0aE62B74340251f48Bf"; // dot OS TBA

const DEFAULT_MAX_ATTEMPTS: u16 = 16;

const PREDEPLOY_CONTRACTS: &[(&str, &str)] = &[
    (
        "0x000000006551c19487814612e58FE06813775758", // ERC6551Registry
        include_str!("./bytecode/erc6551_registry.txt"),
    ),
    (
        "0xcA11bde05977b3631167028862bE2a173976CA11", // Multicall3
        include_str!("./bytecode/multicall.txt"),
    ),
    (
        "0x000000000012d439e33aAD99149d52A5c6f980Dc", // KinoAccount
        include_str!("./bytecode/kinoaccount.txt"),
    ),
    // public minter should be at: 0xa470f15b504f025ce24ed3dbb417b367d3def72f
    (
        "0x000000000033e5CCbC52Ec7BDa87dB768f9aA93F", // Kimap proxy
        include_str!("./bytecode/erc1967proxy.txt"),
    ),
    (
        "0x969cAbCE3625224BA3d340ea4dC2f929301188Ad", // Kimap impl
        include_str!("./bytecode/kimap.txt"),
    ),
];

const STORAGE_SLOTS: &[(&str, &str, &str)] = &[
    // Implementation slot
    (
        "0x000000000033e5CCbC52Ec7BDa87dB768f9aA93F", // Kimap proxy
        "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc", // implementation slot
        "0x000000000000000000000000969cAbCE3625224BA3d340ea4dC2f929301188Ad", // implementation address
    ),
    // KIMAP immutable (set to proxy's own address)
    (
        "0x000000000033e5CCbC52Ec7BDa87dB768f9aA93F", // Kimap proxy
        "0x0000000000000000000000000000000000000000000000000000000000000000", // storage slot
        "0x000000000000000000000000000000000033e5ccbc52ec7bda87db768f9aa93f", // kimap proxy address
    ),
];

const TRANSACTIONS: &[(&str, &str)] = &[
    // initialize Kimap
    // cast calldata "initialize(address)" 0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266
    (
        "0x000000000033e5CCbC52Ec7BDa87dB768f9aA93F",
        "0xc4d66de8000000000000000000000000f39fd6e51aad88f6f4ce6ab8827279cfffb92266",
    ),
    // CREATE2 deploy KinoAccountMinter (deployed at 0xa470f15b504f025ce24ed3dbb417b367d3def72f)
    (
        "0x4e59b44847b379578588920cA78FbF26c0B4956C",
        include_str!("./bytecode/deploykinoaccountminter.txt"),
    ),
    // mint .os
    // cast calldata "execute(address,uint256,bytes,uint8)" 0x000000000033e5CCbC52Ec7BDa87dB768f9aA93F 0 $(cast calldata "mint(address,bytes,bytes,address)" 0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266 $(cast --from-ascii "os") $(cast calldata "initialize()") 0xa470f15b504f025ce24ed3dbb417b367d3def72f) 0
    (
        "0x4bb0778bb92564bf8e82d0b3271b7512443fb060", // zeroth TBA
        "0x51945447000000000000000000000000000000000033e5ccbc52ec7bda87db768f9aa93f0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000104094cefed000000000000000000000000f39fd6e51aad88f6f4ce6ab8827279cfffb92266000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000c0000000000000000000000000a470f15b504f025ce24ed3dbb417b367d3def72f00000000000000000000000000000000000000000000000000000000000000026f7300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000048129fc1c0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    ),
    // mint .dev
    // cast calldata "execute(address,uint256,bytes,uint8)" 0x000000000033e5CCbC52Ec7BDa87dB768f9aA93F 0 $(cast calldata "mint(address,bytes,bytes,address)" 0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266 $(cast --from-ascii "dev") $(cast calldata "initialize()") 0xa470f15b504f025ce24ed3dbb417b367d3def72f) 0
    (
        "0x4bb0778bb92564bf8e82d0b3271b7512443fb060", // zeroth TBA
        "0x51945447000000000000000000000000000000000033e5ccbc52ec7bda87db768f9aa93f0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000104094cefed000000000000000000000000f39fd6e51aad88f6f4ce6ab8827279cfffb92266000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000c0000000000000000000000000a470f15b504f025ce24ed3dbb417b367d3def72f0000000000000000000000000000000000000000000000000000000000000003646576000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000048129fc1c0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    ),
];

#[instrument(level = "trace", skip_all)]
async fn initialize_contracts(port: u16) -> Result<()> {
    let client = Client::new();
    let url = format!("http://localhost:{}", port);

    // impersonate owner account
    let request_body = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "anvil_impersonateAccount",
        "params": [OWNER_ADDRESS],
        "id": 1
    });
    let _: serde_json::Value = client
        .post(&url)
        .json(&request_body)
        .send()
        .await?
        .json()
        .await?;

    // set storage slots
    for (address, slot, value) in STORAGE_SLOTS {
        let request_body: serde_json::Value = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "anvil_setStorageAt",
            "params": [address, slot, value],
            "id": 1
        });
        let _: serde_json::Value = client
            .post(&url)
            .json(&request_body)
            .send()
            .await?
            .json()
            .await?;
    }

    // get current nonce
    let request_body = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "eth_getTransactionCount",
        "params": [OWNER_ADDRESS, "latest"],
        "id": 1
    });
    let response: serde_json::Value = client
        .post(&url)
        .json(&request_body)
        .send()
        .await?
        .json()
        .await?;

    let nonce_hex = response["result"]
        .as_str()
        .ok_or_else(|| eyre!("Invalid nonce response"))?
        .trim_start_matches("0x");

    let mut nonce = u64::from_str_radix(nonce_hex, 16)?;

    // execute all transactions
    for (to, data) in TRANSACTIONS {
        let request_body = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "eth_sendTransaction",
            "params": [{
                "from": OWNER_ADDRESS,
                "to": to,
                "data": data,
                "nonce": format!("0x{:x}", nonce),
                "gas": "0x500000",
            }],
            "id": 1
        });

        let res: serde_json::Value = client
            .post(&url)
            .json(&request_body)
            .send()
            .await?
            .json()
            .await?;

        if let Some(error) = res.get("error") {
            info!("Transaction failed: {:?}", error);
        }
        nonce += 1;
    }

    // stop impersonating
    let request_body = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "anvil_stopImpersonatingAccount",
        "params": [OWNER_ADDRESS],
        "id": 1
    });
    let _: serde_json::Value = client
        .post(&url)
        .json(&request_body)
        .send()
        .await?
        .json()
        .await?;

    Ok(())
}

#[instrument(level = "trace", skip_all)]
async fn check_dot_os_tba(port: u16) -> Result<bool> {
    let client = Client::new();
    let url = format!("http://localhost:{}", port);

    let request_body = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "eth_getCode",
        "params": [DOT_OS_TBA, "latest"],
        "id": 1
    });

    let response = client.post(&url).json(&request_body).send().await?;
    let result: serde_json::Value = response.json().await?;
    let code = result["result"].as_str().unwrap_or("0x");
    Ok(code != "0x")
}

#[instrument(level = "trace", skip_all)]
pub async fn start_chain(
    port: u16,
    mut recv_kill: BroadcastRecvBool,
    _fakenode_version: Option<semver::Version>,
    verbose: bool,
) -> Result<Option<Child>> {
    let deps = check_foundry_deps(None, None)?;
    get_deps(deps, &mut recv_kill, verbose).await?;

    info!("Checking for Anvil on port {}...", port);
    if wait_for_anvil(port, 1, None).await.is_ok() {
        if !check_dot_os_tba(port).await? {
            predeploy_contracts(port).await?;
            initialize_contracts(port).await?;
        }
        return Ok(None);
    }

    let mut child = Command::new("anvil")
        .arg("--port")
        .arg(port.to_string())
        .current_dir(KIT_CACHE)
        .stdout(if verbose {
            Stdio::inherit()
        } else {
            Stdio::piped()
        })
        .spawn()?;

    info!("Waiting for Anvil to be ready on port {}...", port);
    if let Err(e) = wait_for_anvil(port, DEFAULT_MAX_ATTEMPTS, Some(recv_kill)).await {
        let _ = child.kill();
        return Err(e);
    }

    if !check_dot_os_tba(port).await? {
        if let Err(e) = predeploy_contracts(port).await {
            let _ = child.kill();
            return Err(e.wrap_err("Failed to pre-deploy contracts"));
        }

        if let Err(e) = initialize_contracts(port).await {
            let _ = child.kill();
            return Err(e.wrap_err("Failed to initialize contracts"));
        }
    }

    Ok(Some(child))
}

#[instrument(level = "trace", skip_all)]
async fn wait_for_anvil(
    port: u16,
    max_attempts: u16,
    mut recv_kill: Option<BroadcastRecvBool>,
) -> Result<()> {
    let client = Client::new();
    let url = format!("http://localhost:{}", port);

    for _ in 0..max_attempts {
        let request_body = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "eth_blockNumber",
            "params": [],
            "id": 1
        });

        let response = client.post(&url).json(&request_body).send().await;

        match response {
            Ok(resp) if resp.status().is_success() => {
                let result: serde_json::Value = resp.json().await?;
                if let Some(block_number) = result["result"].as_str() {
                    if block_number.starts_with("0x") {
                        info!("Anvil is ready on port {}.", port);
                        return Ok(());
                    }
                }
            }
            _ => (),
        }

        if let Some(ref mut recv_kill) = recv_kill {
            tokio::select! {
                _ = sleep(Duration::from_millis(250)) => {}
                _ = recv_kill.recv() => {
                    return Err(eyre!("Received kill: bringing down anvil."));
                }
            }
        } else {
            sleep(Duration::from_millis(250)).await;
        }
    }

    Err(eyre!(
        "Failed to connect to Anvil on port {} after {} attempts",
        port,
        max_attempts
    )
    .with_suggestion(|| "Is port already occupied?"))
}

#[instrument(level = "trace", skip_all)]
async fn predeploy_contracts(port: u16) -> Result<()> {
    let client = Client::new();
    let url = format!("http://localhost:{}", port);

    for (address, bytecode) in PREDEPLOY_CONTRACTS {
        let request_body = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "eth_getCode",
            "params": [address, "latest"],
            "id": 1
        });

        let response = client.post(&url).json(&request_body).send().await?;
        let result: serde_json::Value = response.json().await?;
        let code = result["result"].as_str().unwrap_or("0x");

        if code == "0x" {
            let request_body = serde_json::json!({
                "jsonrpc": "2.0",
                "method": "anvil_setCode",
                "params": [address, bytecode.trim()],
                "id": 1
            });
            let _: serde_json::Value = client
                .post(&url)
                .json(&request_body)
                .send()
                .await?
                .json()
                .await?;
        }
    }

    Ok(())
}

/// kit chain, alias to anvil
#[instrument(level = "trace", skip_all)]
pub async fn execute(port: u16, version: &str, verbose: bool) -> Result<()> {
    let (send_to_cleanup, mut recv_in_cleanup) = tokio::sync::mpsc::unbounded_channel();
    let (send_to_kill, _recv_kill) = tokio::sync::broadcast::channel(1);
    let recv_kill_in_cos = send_to_kill.subscribe();

    let handle_signals = tokio::spawn(cleanup_on_signal(send_to_cleanup.clone(), recv_kill_in_cos));

    let recv_kill_in_start_chain = send_to_kill.subscribe();
    let version = if version == "latest" {
        None
    } else {
        Some(version.parse()?)
    };
    let child = start_chain(port, recv_kill_in_start_chain, version, verbose).await?;
    let Some(mut child) = child else {
        return Err(eyre!(
            "Port {} is already in use by another anvil process",
            port
        ));
    };
    let child_id = child.id() as i32;

    let cleanup_anvil = tokio::spawn(async move {
        recv_in_cleanup.recv().await;
        clean_process_by_pid(child_id);
    });

    let _ = child.wait();

    let _ = handle_signals.await;
    let _ = cleanup_anvil.await;

    let _ = send_to_kill.send(true);

    Ok(())
}
