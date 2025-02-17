use crate::hyperware::process::file_transfer_worker::{
    ChunkRequest, DownloadRequest, InternalRequest, ProgressRequest, Request as WorkerRequest,
    Response as WorkerResponse,
};
use crate::hyperware::process::standard::{Address as WitAddress, ProcessId as WitProcessId};
use hyperware_process_lib::logging::{error, info, init_logging, Level};
use hyperware_process_lib::{
    await_message, call_init, get_blob,
    vfs::{open_dir, open_file, Directory, File, SeekFrom},
    Address, Message, ProcessId, Request, Response,
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
    WorkerRequest(WorkerRequest),
    InternalRequest(InternalRequest),

    // responses
    WorkerResponse(WorkerResponse),
}

impl From<WitAddress> for Address {
    fn from(address: WitAddress) -> Self {
        Address {
            node: address.node,
            process: address.process.into(),
        }
    }
}

impl From<WitProcessId> for ProcessId {
    fn from(process: WitProcessId) -> Self {
        ProcessId {
            process_name: process.process_name,
            package_name: process.package_name,
            publisher_node: process.publisher_node,
        }
    }
}

const CHUNK_SIZE: u64 = 1048576; // 1MB

fn handle_worker_request(
    request: &WorkerRequest,
    file: &mut Option<File>,
    files_dir: &Directory,
) -> anyhow::Result<bool> {
    match request {
        WorkerRequest::Download(DownloadRequest {
            name,
            target,
            is_requestor,
        }) => {
            Response::new()
                .body(WorkerResponse::Download(Ok(())))
                .send()?;

            // open/create empty file in both cases.
            let mut active_file = open_file(&format!("{}/{}", files_dir.path, &name), true, None)?;

            if *is_requestor {
                *file = Some(active_file);
                Request::new()
                    .expects_response(5)
                    .body(WorkerRequest::Download(DownloadRequest {
                        name: name.to_string(),
                        target: target.clone(),
                        is_requestor: false,
                    }))
                    .target::<Address>(target.clone().into())
                    .send()?;
            } else {
                // we are sender: chunk the data, and send it.
                let size = active_file.metadata()?.len;
                let num_chunks = (size as f64 / CHUNK_SIZE as f64).ceil() as u64;

                // give receiving worker file size so it can track download progress
                Request::new()
                    .body(InternalRequest::Size(size))
                    .target(target.clone())
                    .send()?;

                active_file.seek(SeekFrom::Start(0))?;

                for i in 0..num_chunks {
                    let offset = i * CHUNK_SIZE;
                    let length = CHUNK_SIZE.min(size - offset);

                    let mut buffer = vec![0; length as usize];
                    active_file.read_at(&mut buffer)?;

                    Request::new()
                        .body(InternalRequest::Chunk(ChunkRequest {
                            name: name.clone(),
                            offset,
                            length,
                        }))
                        .target(target.clone())
                        .blob_bytes(buffer)
                        .send()?;
                }
                return Ok(true);
            }
        }
        WorkerRequest::Progress(_) => {
            return Err(anyhow::anyhow!(
                "worker: got unexpected WorkerRequest::Progress",
            ));
        }
    }
    Ok(false)
}

fn handle_internal_request(
    request: &InternalRequest,
    file: &mut Option<File>,
    size: &mut Option<u64>,
    parent: &Option<Address>,
) -> anyhow::Result<bool> {
    match request {
        InternalRequest::Chunk(ChunkRequest {
            name,
            offset,
            length,
        }) => {
            // someone sending a chunk to us
            let file = match file {
                Some(file) => file,
                None => {
                    return Err(anyhow::anyhow!(
                        "worker: receive error: no file initialized"
                    ));
                }
            };

            let bytes = match get_blob() {
                Some(blob) => blob.bytes,
                None => {
                    return Err(anyhow::anyhow!("worker: receive error: no blob"));
                }
            };

            file.write_all(&bytes)?;

            // if sender has sent us a size, give a progress update to main transfer
            let Some(ref parent) = parent else {
                return Ok(false);
            };
            if let Some(size) = size {
                let progress = ((offset + length) as f64 / *size as f64 * 100.0) as u64;

                Request::new()
                    .expects_response(5)
                    .body(WorkerRequest::Progress(ProgressRequest {
                        name: name.to_string(),
                        progress,
                    }))
                    .target(parent)
                    .send()?;

                if progress >= 100 {
                    return Ok(true);
                }
            }
        }
        InternalRequest::Size(incoming_size) => {
            *size = Some(*incoming_size);
        }
    }
    Ok(false)
}

fn handle_worker_response(response: &WorkerResponse) -> anyhow::Result<bool> {
    match response {
        WorkerResponse::Download(ref result) => {
            if let Err(e) = result {
                return Err(anyhow::anyhow!("{e}"));
            }
        }
        WorkerResponse::Progress => {}
    }
    Ok(false)
}

fn handle_message(
    message: &Message,
    file: &mut Option<File>,
    files_dir: &Directory,
    size: &mut Option<u64>,
    parent: &mut Option<Address>,
) -> anyhow::Result<bool> {
    return Ok(match message.body().try_into()? {
        // requests
        Msg::WorkerRequest(ref wr) => {
            *parent = Some(message.source().clone());
            handle_worker_request(wr, file, files_dir)?
        }
        Msg::InternalRequest(ref ir) => handle_internal_request(ir, file, size, parent)?,

        // responses
        Msg::WorkerResponse(ref wr) => handle_worker_response(wr)?,
    });
}

call_init!(init);
fn init(our: Address) {
    init_logging(Level::DEBUG, Level::INFO, None, None, None).unwrap();
    info!("worker: begin");
    let start = std::time::Instant::now();

    let drive_path = format!("{}/files", our.package_id());
    let files_dir = open_dir(&drive_path, false, None).unwrap();

    let mut file: Option<File> = None;
    let mut size: Option<u64> = None;
    let mut parent: Option<Address> = None;

    loop {
        match await_message() {
            Err(send_error) => error!("worker: got SendError: {send_error}"),
            Ok(ref message) => {
                match handle_message(message, &mut file, &files_dir, &mut size, &mut parent) {
                    Ok(exit) => {
                        if exit {
                            info!("worker: done: exiting, took {:?}", start.elapsed());
                            break;
                        }
                    }
                    Err(e) => error!("worker: got error while handling message: {e:?}"),
                }
            }
        }
    }
}
