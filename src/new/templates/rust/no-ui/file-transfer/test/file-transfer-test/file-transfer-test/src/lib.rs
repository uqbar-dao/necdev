use crate::hyperware::process::file_transfer::{
    FileInfo, Request as TransferRequest, Response as TransferResponse,
};
use crate::hyperware::process::file_transfer_worker::{
    Address as WitAddress, DownloadRequest, Request as WorkerRequest,
};
use crate::hyperware::process::standard::ProcessId as WitProcessId;
use crate::hyperware::process::tester::{
    FailResponse, Request as TesterRequest, Response as TesterResponse, RunRequest,
};

use hyperware_process_lib::{
    await_message, call_init, our_capabilities, print_to_terminal, println, save_capabilities,
    vfs::File, Address, ProcessId, Request, Response,
};

mod tester_lib;

wit_bindgen::generate!({
    path: "target/wit",
    world: "file-transfer-test-template-dot-os-v0",
    generate_unused_types: true,
    additional_derives: [PartialEq, serde::Deserialize, serde::Serialize, process_macros::SerdeJsonInto],
});

const FILE_NAME: &str = "my_file.txt";
const FILE_CONTENTS: &str = "hi";
const DRIVE_PATH: &str = "file-transfer:template.os";

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

#[derive(Debug, serde::Deserialize, serde::Serialize, process_macros::SerdeJsonInto)]
enum Setup {
    Caps,
    WriteFile { name: String, contents: Vec<u8> },
}

fn make_ft_address(node: &str) -> Address {
    Address {
        node: node.to_string(),
        process: ProcessId::new(Some("file-transfer"), "file-transfer", "template.os"),
    }
}

fn make_file_path() -> String {
    format!("{DRIVE_PATH}/files/{FILE_NAME}")
}

fn setup(our: &Address, their: &str) -> anyhow::Result<()> {
    let our_ft_address = make_ft_address(&our.node);
    let their_ft_address = make_ft_address(their);

    // write file on their
    Request::new()
        .target(their_ft_address.clone())
        .body(Setup::WriteFile {
            name: FILE_NAME.to_string(),
            contents: FILE_CONTENTS.as_bytes().to_vec(),
        })
        .send()?;

    // caps on our
    println!("file-transfer-test: started caps handshake...");

    let response = Request::new()
        .target(our_ft_address.clone())
        .body(Setup::Caps)
        .send_and_await_response(5)??;

    save_capabilities(response.capabilities());
    println!("file-transfer-test: got caps {:#?}", our_capabilities());

    Ok(())
}

fn test_list_files(our_ft_address: &Address, their_ft_address: &Address) -> anyhow::Result<()> {
    // our: none
    let response = Request::new()
        .target(our_ft_address)
        .body(TransferRequest::ListFiles)
        .send_and_await_response(15)?
        .unwrap();
    if response.is_request() {
        fail!("file-transfer-test");
    };
    let TransferResponse::ListFiles(files) = response.body().try_into()?;
    println!("{files:?}");
    if files.len() != 0 {
        fail!("file-transfer-test");
    }

    // their: one
    let response = Request::new()
        .target(their_ft_address)
        .body(TransferRequest::ListFiles)
        .send_and_await_response(15)?
        .unwrap();
    if response.is_request() {
        fail!("file-transfer-test");
    };
    let TransferResponse::ListFiles(files) = response.body().try_into()?;
    println!("{files:?}");
    if files.len() != 1 {
        fail!("file-transfer-test");
    }
    let file = files[0].clone();
    let expected_file_info = FileInfo {
        name: make_file_path(),
        size: FILE_CONTENTS.len() as u64,
    };
    if file != expected_file_info {
        fail!("file-transfer-test");
    }
    Ok(())
}

fn test_download(our_ft_address: &Address, their_ft_address: &Address) -> anyhow::Result<()> {
    let response = Request::new()
        .target(our_ft_address)
        .body(WorkerRequest::Download(DownloadRequest {
            name: FILE_NAME.to_string(),
            target: their_ft_address.clone().into(),
            is_requestor: true,
        }))
        .send_and_await_response(15)?
        .unwrap();
    if response.is_request() {
        fail!("file-transfer-test");
    };
    std::thread::sleep(std::time::Duration::from_secs(3));

    let file = File {
        path: make_file_path(),
        timeout: 5,
    };
    let file_contents = file.read()?;
    if file_contents != FILE_CONTENTS.as_bytes() {
        fail!("file-transfer-test");
    }
    Ok(())
}

fn handle_message(our: &Address) -> anyhow::Result<()> {
    let message = await_message().unwrap();

    if !message.is_request() {
        unimplemented!();
    }
    let source = message.source();
    if our.node != source.node {
        return Err(anyhow::anyhow!(
            "rejecting foreign Message from {:?}",
            source,
        ));
    }
    let TesterRequest::Run(RunRequest {
        input_node_names: node_names,
        ..
    }) = message.body().try_into()?;
    print_to_terminal(0, "file-transfer-test: a");
    assert!(node_names.len() >= 2);
    // we are master node
    assert!(our.node == node_names[0]);

    if setup(&our, &node_names[1]).is_err() {
        fail!("file-transfer-test");
    }

    let our_ft_address = make_ft_address(&our.node);
    let their_ft_address = make_ft_address(&node_names[1]);

    if test_list_files(&our_ft_address, &their_ft_address).is_err() {
        fail!("file-transfer-test");
    }

    // Test file_transfer_worker
    println!("file-transfer-test: b");
    if test_download(&our_ft_address, &their_ft_address).is_err() {
        fail!("file-transfer-test");
    }
    //let response = Request::new()
    //    .target(our_ft_address.clone())
    //    .body(WorkerRequest::Download(DownloadRequest {
    //        name: FILE_NAME.to_string(),
    //        target: their_ft_address.into(),
    //        is_requestor: true,
    //    }))
    //    .send_and_await_response(15)?
    //    .unwrap();
    //if response.is_request() {
    //    fail!("file-transfer-test");
    //};
    //std::thread::sleep(std::time::Duration::from_secs(3));

    //let file = File {
    //    path: format!("{DRIVE_PATH}/files/{FILE_NAME}"),
    //    timeout: 5,
    //};
    //let file_contents = file.read()?;
    //if file_contents != FILE_CONTENTS.as_bytes() {
    //    fail!("file-transfer-test");
    //}

    Response::new()
        .body(TesterResponse::Run(Ok(())))
        .send()
        .unwrap();

    Ok(())
}

call_init!(init);
fn init(our: Address) {
    print_to_terminal(0, "begin");

    loop {
        match handle_message(&our) {
            Ok(()) => {}
            Err(e) => {
                print_to_terminal(0, format!("file-transfer-test: error: {e:?}").as_str());

                fail!("file-transfer-test");
            }
        };
    }
}
