use std::collections::HashMap;

use crate::hyperware::process::chat::{
    ChatMessage, Request as ChatRequest, Response as ChatResponse, SendRequest,
};
use hyperware_process_lib::logging::{error, info, init_logging, Level};
use hyperware_process_lib::{
    await_message, call_init, get_blob,
    http::server::{
        send_response, HttpBindingConfig, HttpServer, HttpServerRequest, StatusCode,
        WsBindingConfig, WsMessageType,
    },
    println, Address, LazyLoadBlob, Message, Request, Response,
};

wit_bindgen::generate!({
    path: "target/wit",
    world: "chat-template-dot-os-v0",
    generate_unused_types: true,
    additional_derives: [serde::Deserialize, serde::Serialize, process_macros::SerdeJsonInto],
});

const HTTP_API_PATH: &str = "/messages";
const WS_PATH: &str = "/";

#[derive(Debug, serde::Serialize, serde::Deserialize, process_macros::SerdeJsonInto)]
struct NewMessage {
    chat: String,
    author: String,
    content: String,
}

type MessageArchive = HashMap<String, Vec<ChatMessage>>;

fn make_http_address(our: &Address) -> Address {
    Address::from((our.node(), "http_server", "distro", "sys"))
}

fn handle_http_server_request(
    our: &Address,
    body: &[u8],
    message_archive: &mut MessageArchive,
    server: &mut HttpServer,
) -> anyhow::Result<()> {
    let Ok(request) = serde_json::from_slice::<HttpServerRequest>(body) else {
        // Fail quietly if we can't parse the request
        info!("couldn't parse message from http_server: {body:?}");
        return Ok(());
    };

    match request {
        HttpServerRequest::WebSocketOpen {
            ref path,
            channel_id,
        } => server.handle_websocket_open(path, channel_id),
        HttpServerRequest::WebSocketClose(channel_id) => server.handle_websocket_close(channel_id),
        HttpServerRequest::WebSocketPush { .. } => {
            let Some(blob) = get_blob() else {
                return Ok(());
            };

            handle_chat_request(
                our,
                &make_http_address(our),
                &blob.bytes,
                true,
                message_archive,
                server,
            )?;
        }
        HttpServerRequest::Http(request) => {
            match request.method().unwrap().as_str() {
                // Get all messages
                "GET" => {
                    let headers = HashMap::from([(
                        "Content-Type".to_string(),
                        "application/json".to_string(),
                    )]);

                    send_response(
                        StatusCode::OK,
                        Some(headers),
                        serde_json::to_vec(&serde_json::json!({
                            "History": {
                                "messages": message_archive.clone()
                            }
                        }))
                        .unwrap(),
                    );
                }
                // Send a message
                "POST" => {
                    let Some(blob) = get_blob() else {
                        send_response(StatusCode::BAD_REQUEST, None, vec![]);
                        return Ok(());
                    };
                    handle_chat_request(
                        our,
                        &make_http_address(our),
                        &blob.bytes,
                        true,
                        message_archive,
                        server,
                    )
                    .unwrap();

                    send_response(StatusCode::CREATED, None, vec![]);
                }
                _ => send_response(StatusCode::METHOD_NOT_ALLOWED, None, vec![]),
            }
        }
    };

    Ok(())
}

fn handle_chat_request(
    our: &Address,
    source: &Address,
    body: &[u8],
    is_http: bool,
    message_archive: &mut MessageArchive,
    server: &HttpServer,
) -> anyhow::Result<()> {
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

            if is_http {
                // If is HTTP from FE: done
                return Ok(());
            }

            // Not HTTP from FE: send response to node & update any FE listeners
            Response::new().body(ChatResponse::Send).send().unwrap();

            // Send a WebSocket message to the http server in order to update the UI
            let blob = LazyLoadBlob {
                mime: Some("application/json".to_string()),
                bytes: serde_json::to_vec(&serde_json::json!({
                    "NewMessage": NewMessage {
                        chat: counterparty.to_string(),
                        author,
                        content: message.to_string(),
                    }
                }))
                .unwrap(),
            };
            server.ws_push_all_channels(WS_PATH, WsMessageType::Text, blob);
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

fn handle_message(
    our: &Address,
    message: &Message,
    message_archive: &mut MessageArchive,
    server: &mut HttpServer,
) -> anyhow::Result<()> {
    if !message.is_request() {
        return Ok(());
    }

    let body = message.body();
    let source = message.source();

    if source == &make_http_address(our) {
        handle_http_server_request(our, body, message_archive, server)?;
    } else {
        handle_chat_request(our, source, body, false, message_archive, server)?;
    }

    Ok(())
}

call_init!(init);
fn init(our: Address) {
    init_logging(&our, Level::DEBUG, Level::INFO, None, None).unwrap();
    info!("begin");

    let mut message_archive = HashMap::new();

    let mut server = HttpServer::new(5);

    // Bind UI files to routes with index.html at "/"; API to /messages; WS to "/"
    server
        .serve_ui(&our, "ui", vec!["/"], HttpBindingConfig::default())
        .expect("failed to serve UI");
    server
        .bind_http_path(HTTP_API_PATH, HttpBindingConfig::default())
        .expect("failed to bind messages API");
    server
        .bind_ws_path(WS_PATH, WsBindingConfig::default())
        .expect("failed to bind WS API");

    loop {
        match await_message() {
            Err(send_error) => error!("got SendError: {send_error}"),
            Ok(ref message) => {
                match handle_message(&our, message, &mut message_archive, &mut server) {
                    Ok(_) => {}
                    Err(e) => error!("got error while handling message: {e:?}"),
                }
            }
        }
    }
}
