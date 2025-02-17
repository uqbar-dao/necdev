use crate::hyperware::process::file_transfer::{
    FileInfo, Request as TransferRequest, Response as TransferResponse,
};
use crate::hyperware::process::file_transfer_worker::{
    start_download, DownloadRequest, ProgressRequest, Request as WorkerRequest,
    Response as WorkerResponse,
};
use crate::hyperware::process::standard::{Address as WitAddress, ProcessId as WitProcessId};
use hyperware_process_lib::logging::{error, info, init_logging, Level};
use hyperware_process_lib::{
    await_message, call_init, get_capability, println,
    vfs::{create_drive, metadata, open_dir, open_file, Directory, FileType},
    Address, Message, ProcessId, Response,
};

wit_bindgen::generate!({
    path: "target/wit",
    world: "file-transfer-template-dot-os-v0",
    generate_unused_types: true,
    additional_derives: [serde::Deserialize, serde::Serialize, process_macros::SerdeJsonInto],
});

#[derive(Debug, serde::Deserialize, serde::Serialize, process_macros::SerdeJsonInto)]
#[serde(untagged)] // untagged as a meta-type for all incoming messages
enum Msg {
    // requests
    TransferRequest(TransferRequest),
    WorkerRequest(WorkerRequest),

    // responses
    TransferResponse(TransferResponse),
    WorkerResponse(WorkerResponse),
}

impl From<Address> for WitAddress {
    fn from(address: Address) -> Self {
        WitAddress {
            node: address.node,
            process: address.process.into(),
        }
    }
}

impl From<ProcessId> for WitProcessId {
    fn from(process: ProcessId) -> Self {
        WitProcessId {
            process_name: process.process_name,
            package_name: process.package_name,
            publisher_node: process.publisher_node,
        }
    }
}

fn ls_files(files_dir: &Directory) -> anyhow::Result<Vec<FileInfo>> {
    let entries = files_dir.read()?;
    let files: Vec<FileInfo> = entries
        .iter()
        .filter_map(|file| match file.file_type {
            FileType::File => match metadata(&file.path, None) {
                Ok(metadata) => Some(FileInfo {
                    name: file.path.clone(),
                    size: metadata.len,
                }),
                Err(_) => None,
            },
            _ => None,
        })
        .collect();
    Ok(files)
}

fn handle_transfer_request(request: &TransferRequest, files_dir: &Directory) -> anyhow::Result<()> {
    match request {
        TransferRequest::ListFiles => {
            let files = ls_files(files_dir)?;
            Response::new()
                .body(TransferResponse::ListFiles(files))
                .send()?;
        }
    }
    Ok(())
}

fn handle_worker_request(
    our: &Address,
    source: &Address,
    request: &WorkerRequest,
) -> anyhow::Result<()> {
    match request {
        WorkerRequest::Download(DownloadRequest {
            ref name,
            ref target,
            is_requestor,
        }) => {
            match start_download(
                &our.clone().into(),
                &source.clone().into(),
                name,
                target,
                *is_requestor,
            ) {
                Ok(_) => {}
                Err(e) => return Err(anyhow::anyhow!("{e}")),
            }
        }
        WorkerRequest::Progress(ProgressRequest { name, progress }) => {
            info!("{} progress: {}%", name, progress);
            Response::new().body(WorkerResponse::Progress).send()?;
        }
    }
    Ok(())
}

fn handle_transfer_response(source: &Address, response: &TransferResponse) -> anyhow::Result<()> {
    match response {
        TransferResponse::ListFiles(ref files) => {
            println!(
                "{}",
                files.iter().fold(
                    format!("{source} available files:\nFile\t\tSize (bytes)\n"),
                    |mut msg, file| {
                        msg.push_str(&format!(
                            "{}\t\t{}",
                            file.name.split('/').last().unwrap(),
                            file.size,
                        ));
                        msg
                    }
                )
            );
        }
    }
    Ok(())
}

fn handle_worker_response(response: &WorkerResponse) -> anyhow::Result<()> {
    match response {
        WorkerResponse::Download(ref result) => {
            if let Err(e) = result {
                return Err(anyhow::anyhow!("{e}"));
            }
        }
        WorkerResponse::Progress => {}
    }
    Ok(())
}

fn handle_message(our: &Address, message: &Message, files_dir: &Directory) -> anyhow::Result<()> {
    match message.body().try_into()? {
        // requests
        Msg::TransferRequest(ref tr) => handle_transfer_request(tr, files_dir),
        Msg::WorkerRequest(ref wr) => handle_worker_request(our, message.source(), wr),

        // responses
        Msg::TransferResponse(ref tr) => handle_transfer_response(message.source(), tr),
        Msg::WorkerResponse(ref wr) => handle_worker_response(wr),
    }
}

#[cfg(feature = "test")]
#[derive(Debug, serde::Deserialize, serde::Serialize, process_macros::SerdeJsonInto)]
#[cfg(feature = "test")]
enum Setup {
    Caps,
    WriteFile { name: String, contents: Vec<u8> },
}

#[cfg(feature = "test")]
fn handle_tester_setup(our: &Address, drive_path: &str) -> anyhow::Result<()> {
    println!("awaiting setup...");

    let Ok(message) = await_message() else {
        return Err(anyhow::anyhow!("a"));
    };
    // TODO: confirm its from tester
    match message.body().try_into()? {
        Setup::Caps => {
            println!("got caps...");
            let vfs_read_cap = serde_json::json!({
                "kind": "read",
                "drive": drive_path,
            })
            .to_string();
            let vfs_address = Address {
                node: our.node.clone(),
                process: "vfs:distro:sys".parse()?,
            };

            let read_cap = get_capability(&vfs_address, &vfs_read_cap).unwrap();

            Response::new()
                .body(vec![])
                .capabilities(vec![read_cap])
                .send()
                .unwrap();
            println!("sent caps");
        }
        Setup::WriteFile {
            ref name,
            ref contents,
        } => {
            println!("got write file...");
            let file = open_file(&format!("{drive_path}/{name}"), true, None)?;
            file.write(contents)?;
        }
    }
    println!("setup done");
    Ok(())
}

call_init!(init);
fn init(our: Address) {
    init_logging(Level::DEBUG, Level::INFO, None, None, None).unwrap();
    info!("begin");

    let drive_path = create_drive(our.package_id(), "files", None).unwrap();
    let files_dir = open_dir(&drive_path, false, None).unwrap();

    #[cfg(feature = "test")]
    handle_tester_setup(&our, &drive_path).unwrap();

    loop {
        match await_message() {
            Err(send_error) => error!("got SendError: {send_error}"),
            Ok(ref message) => match handle_message(&our, message, &files_dir) {
                Ok(_) => {}
                Err(e) => error!("got error while handling message: {e:?}"),
            },
        }
    }
}
