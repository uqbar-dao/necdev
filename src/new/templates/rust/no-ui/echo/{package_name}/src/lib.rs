use kinode_process_lib::{await_message, call_init, println, Address, Message, Response};

wit_bindgen::generate!({
    path: "target/wit",
    world: "process-v0",
});

fn handle_message(message: &Message) -> anyhow::Result<()> {
    if !message.is_request() {
        return Err(anyhow::anyhow!("unexpected Response: {:?}", message));
    }

    let body: serde_json::Value = serde_json::from_slice(message.body())?;
    println!("got {body:?}");
    Response::new()
        .body(serde_json::to_vec(&serde_json::json!("Ack")).unwrap())
        .send()
        .unwrap();
    Ok(())
}

call_init!(init);
fn init(_our: Address) {
    println!("begin");

    loop {
        match await_message() {
            Err(send_error) => println!("got SendError: {send_error}"),
            Ok(ref message) => match handle_message(message) {
                Ok(_) => {}
                Err(e) => println!("got error while handling message: {e:?}"),
            },
        }
    }
}
