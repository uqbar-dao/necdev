use crate::hyperware::process::fibonacci::{Request as FibRequest, Response as FibResponse};
use crate::hyperware::process::tester::{Request as TesterRequest, Response as TesterResponse, RunRequest, FailResponse};

use hyperware_process_lib::{await_message, call_init, print_to_terminal, Address, ProcessId, Request, Response};

mod tester_lib;

wit_bindgen::generate!({
    path: "target/wit",
    world: "fibonacci-test-template-dot-os-v0",
    generate_unused_types: true,
    additional_derives: [PartialEq, serde::Deserialize, serde::Serialize, process_macros::SerdeJsonInto],
});

fn test_number(n: u32, address: &Address) -> anyhow::Result<u64> {
    let response = Request::new()
        .target(address)
        .body(FibRequest::Number(n))
        .send_and_await_response(15)?.unwrap();
    if response.is_request() { fail!("fibonacci_test"); };
    let FibResponse::Number(fib_number) = response.body().try_into()? else {
        fail!("fibonacci_test");
    };
    Ok(fib_number)
}

fn test_numbers(n: u32, n_trials: u32, address: &Address) -> anyhow::Result<u64> {
    let response = Request::new()
        .target(address)
        .body(FibRequest::Numbers((n, n_trials)))
        .send_and_await_response(15)?.unwrap();
    if response.is_request() { fail!("fibonacci_test"); };
    let FibResponse::Numbers((fib_number, _)) = response.body().try_into()? else {
        fail!("fibonacci_test");
    };
    Ok(fib_number)
}

fn handle_message (our: &Address) -> anyhow::Result<()> {
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
    print_to_terminal(0, "fibonacci_test: a");
    assert!(node_names.len() == 1);

    let our_fib_address = Address {
        node: our.node.clone(),
        process: ProcessId::new(Some("fibonacci"), "fibonacci", "template.os"),
    };

    let numbers = vec![0, 1, 2, 5, 10, 20, 30, 47];
    let expecteds = vec![0, 1, 1, 5, 55, 6_765, 832_040, 2_971_215_073];
    for (number, expected) in numbers.iter().zip(expecteds.iter()) {
        let result = test_number(number.clone(), &our_fib_address)?;
        if &result != expected {
            fail!("fibonacci_test");
        }
    }

    let numbers = vec![0, 1, 2, 5, 10, 20, 30, 47];
    let expecteds = vec![0, 1, 1, 5, 55, 6_765, 832_040, 2_971_215_073];
    for (number, expected) in numbers.iter().zip(expecteds.iter()) {
        let result = test_numbers(number.clone(), 5, &our_fib_address)?;
        if &result != expected {
            fail!("fibonacci_test");
        }
    }

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
            Ok(()) => {},
            Err(e) => {
                print_to_terminal(0, format!("fibonacci_test: error: {e:?}").as_str());

                fail!("fibonacci_test");
            },
        };
    }
}
