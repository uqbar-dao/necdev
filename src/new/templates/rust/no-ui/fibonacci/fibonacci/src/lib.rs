use crate::hyperware::process::fibonacci::{
    Request as FibonacciRequest, Response as FibonacciResponse,
};
use hyperware_process_lib::logging::{error, info, init_logging, Level};
use hyperware_process_lib::{await_message, call_init, Address, Message, Response};

wit_bindgen::generate!({
    path: "target/wit",
    world: "fibonacci-template-dot-os-v0",
    generate_unused_types: true,
    additional_derives: [serde::Deserialize, serde::Serialize, process_macros::SerdeJsonInto],
});

/// calculate the nth Fibonacci number
/// since we are using u64, the maximum number
/// we can calculate is the 93rd Fibonacci number
fn fibonacci(n: u32) -> u64 {
    if n == 0 {
        return 0;
    }
    let mut a = 0;
    let mut b = 1;
    let mut sum;
    for _ in 1..n {
        sum = a + b;
        a = b;
        b = sum;
    }
    b
}

fn handle_message(message: &Message) -> anyhow::Result<()> {
    if !message.is_request() {
        return Err(anyhow::anyhow!("expected a request"));
    }

    match message.body().try_into()? {
        FibonacciRequest::Number(number) => {
            let start = std::time::Instant::now();
            let result = fibonacci(number);
            let duration = start.elapsed();
            info!(
                "fibonacci({}) = {}; {}ns",
                number,
                result,
                duration.as_nanos(),
            );
            Response::new()
                .body(FibonacciResponse::Number(result))
                .send()
                .unwrap();
        }
        FibonacciRequest::Numbers((number, number_trials)) => {
            let mut durations = Vec::new();
            for _ in 0..number_trials {
                let start = std::time::Instant::now();
                let _result = fibonacci(number);
                let duration = start.elapsed();
                durations.push(duration);
            }
            let result = fibonacci(number);
            let mean =
                durations.iter().fold(0, |sum, item| sum + item.as_nanos()) / number_trials as u128;
            let absolute_deviation = durations.iter().fold(0, |ad, item| {
                let trial = item.as_nanos();
                ad + if mean >= trial {
                    mean - trial
                } else {
                    trial - mean
                }
            }) / number_trials as u128;
            info!(
                "fibonacci({}) = {}; {}±{}ns averaged over {} trials",
                number, result, mean, absolute_deviation, number_trials,
            );
            Response::new()
                .body(FibonacciResponse::Numbers((result, number_trials)))
                .send()
                .unwrap();
        }
    }
    Ok(())
}

call_init!(init);
fn init(_our: Address) {
    init_logging(Level::DEBUG, Level::INFO, None, None, None).unwrap();
    info!("begin");

    loop {
        match await_message() {
            Err(send_error) => error!("got SendError: {send_error}"),
            Ok(ref message) => match handle_message(message) {
                Ok(_) => {}
                Err(e) => error!("got error while handling message: {e:?}"),
            },
        }
    }
}
