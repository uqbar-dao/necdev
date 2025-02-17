use crate::hyperware::process::file_transfer::{
    Request as TransferRequest, Response as TransferResponse,
};
use hyperware_process_lib::{await_next_message_body, call_init, println, Address, Message, Request};

wit_bindgen::generate!({
    path: "target/wit",
    world: "file-transfer-template-dot-os-v0",
    generate_unused_types: true,
    additional_derives: [serde::Deserialize, serde::Serialize, process_macros::SerdeJsonInto],
});

call_init!(init);
fn init(_our: Address) {
    let Ok(body) = await_next_message_body() else {
        println!("failed to get args!");
        return;
    };

    let who = String::from_utf8(body).unwrap_or_default();
    if who.is_empty() {
        println!("usage: list-files:file-transfer:template.os who");
        return;
    }

    let target: Address = format!("{}@file-transfer:file-transfer:template.os", who)
        .parse()
        .unwrap();

    let Ok(Ok(Message::Response { body, .. })) = Request::to(target)
        .body(TransferRequest::ListFiles)
        .send_and_await_response(5)
    else {
        println!("did not receive expected Response from {who}");
        return;
    };

    let Ok(TransferResponse::ListFiles(files)) = body.try_into() else {
        println!("did not receive expected ListFiles from {who}");
        return;
    };

    println!(
        "{}",
        files.iter().fold(
            format!("{who} available files:\nFile\t\tSize (bytes)\n"),
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
