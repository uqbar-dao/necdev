use std::collections::HashMap;

use crate::hyperware::process::chat::{
    ChatMessage, Request as ChatRequest, Response as ChatResponse, SendRequest,
};
use hyperware_process_lib::logging::{error, info, init_logging, Level};
use hyperware_process_lib::{await_message, call_init, println, Address, Message, Request, Response};

wit_bindgen::generate!({
    path: "target/wit",
    world: "chat-template-dot-os-v0",
    generate_unused_types: true,
    additional_derives: [serde::Deserialize, serde::Serialize, process_macros::SerdeJsonInto],
});

type MessageArchive = HashMap<String, Vec<ChatMessage>>;

fn handle_message(
    our: &Address,
    message: &Message,
    message_archive: &mut MessageArchive,
) -> anyhow::Result<()> {
    if !message.is_request() {
        return Err(anyhow::anyhow!("unexpected Response: {:?}", message));
    }

    let body = message.body();
    let source = message.source();
    match body.try_into()? {
        ChatRequest::Send(SendRequest {
            ref target,
            ref message,
        }) => {
            // Counterparty is the other node in the chat with us
            let (counterparty, author) = if target == &our.node {
                (&source.node, source.node.clone())
            } else {
                (target, our.node.clone())
            };

            // If the target is not us, send a request to the target
            if target == &our.node {
                println!("{}: {}", source.node, message);
            } else {
                Request::new()
                    .target((target, "chat", "chat", "template.os"))
                    .body(body)
                    .send_and_await_response(5)??;
            }

            // Insert message into archive, creating one for counterparty if it DNE
            let new_message = ChatMessage {
                author: author.clone(),
                content: message.clone(),
            };
            message_archive
                .entry(counterparty.to_string())
                .and_modify(|e| e.push(new_message.clone()))
                .or_insert(vec![new_message]);

            Response::new().body(ChatResponse::Send).send().unwrap();
        }
        ChatRequest::History(ref node) => {
            Response::new()
                .body(ChatResponse::History(
                    message_archive
                        .get(node)
                        .map(|msgs| msgs.clone())
                        .unwrap_or_default(),
                ))
                .send()?;
        }
    }
    Ok(())
}

call_init!(init);
fn init(our: Address) {
    init_logging(Level::DEBUG, Level::INFO, None, None, None).unwrap();
    info!("begin");

    let mut message_archive = HashMap::new();

    loop {
        match await_message() {
            Err(send_error) => error!("got SendError: {send_error}"),
            Ok(ref message) => match handle_message(&our, message, &mut message_archive) {
                Ok(_) => {}
                Err(e) => error!("got error while handling message: {e:?}"),
            },
        }
    }
}
