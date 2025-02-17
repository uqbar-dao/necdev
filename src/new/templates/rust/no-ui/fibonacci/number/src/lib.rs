use crate::hyperware::process::fibonacci::{Request as FibonacciRequest, Response as FibonacciResponse};
use hyperware_process_lib::{
    await_next_message_body, call_init, println, Address, Message, Request,
};

wit_bindgen::generate!({
    path: "target/wit",
    world: "fibonacci-template-dot-os-v0",
    generate_unused_types: true,
    additional_derives: [serde::Deserialize, serde::Serialize],
});

call_init!(init);
fn init(our: Address) {
    let Ok(body) = await_next_message_body() else {
        println!("failed to get args!");
        return;
    };

    let number: u32 = String::from_utf8(body)
        .unwrap_or_default()
        .parse()
        .unwrap_or_default();

    let Ok(Ok(Message::Response { body, .. })) =
        Request::to((our.node(), ("fibonacci", "fibonacci", "template.os")))
            .body(serde_json::to_vec(&FibonacciRequest::Number(number)).unwrap())
            .send_and_await_response(5)
    else {
        println!("did not receive expected Response from fibonacci:fibonacci:template.os");
        return;
    };

    let Ok(FibonacciResponse::Number(_number)) = serde_json::from_slice(&body) else {
        println!("did not receive expected Ack from fibonacci:fibonacci:template.os");
        return;
    };

    // don't need to print the number here since the main process prints it
}
