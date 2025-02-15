use hyperware_process_lib::{await_message, call_init, println, Address};

wit_bindgen::generate!({
    path: "target/wit",
    world: "process-v1",
});

call_init!(init);
fn init(_our: Address) {
    loop {
        match await_message() {
            Err(send_error) => println!("got SendError: {send_error}"),
            Ok(message) => println!("got Message: {message:?}"),
        }
    }
}
