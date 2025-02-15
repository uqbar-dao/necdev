use crate::hyperware::process::file_transfer_worker::{DownloadRequest, Request as WorkerRequest};
use crate::hyperware::process::standard::{Address as WitAddress, ProcessId as WitProcessId};
use hyperware_process_lib::{
    await_next_message_body, call_init, println, Address, ProcessId, Request,
};

wit_bindgen::generate!({
    path: "target/wit",
    world: "file-transfer-template-dot-os-v0",
    generate_unused_types: true,
    additional_derives: [serde::Deserialize, serde::Serialize, process_macros::SerdeJsonInto],
});

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

call_init!(init);
fn init(our: Address) {
    let Ok(body) = await_next_message_body() else {
        println!("failed to get args!");
        return;
    };

    let args = String::from_utf8(body).unwrap_or_default();
    let Some((name, who)) = args.split_once(" ") else {
        println!("usage: download:file-transfer:template.os file_name who");
        return;
    };
    let our: Address = format!("{}@file-transfer:file-transfer:template.os", our.node())
        .parse()
        .unwrap();

    let target: Address = format!("{}@file-transfer:file-transfer:template.os", who)
        .parse()
        .unwrap();

    match Request::to(our)
        .body(WorkerRequest::Download(DownloadRequest {
            name: name.into(),
            target: target.clone().into(),
            is_requestor: true,
        }))
        .send_and_await_response(5)
    {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => println!("download failed: {e:?}"),
        Err(e) => println!("download failed; SendError: {e:?}"),
    }
}
