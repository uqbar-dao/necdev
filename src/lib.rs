pub mod boot_fake_node;
pub mod boot_real_node;
pub mod build;
pub mod build_start_package;
pub mod chain;
pub mod connect;
pub mod dev_ui;
pub mod inject_message;
pub mod new;
pub mod publish;
pub mod remove_package;
pub mod reset_cache;
pub mod run_tests;
pub mod setup;
pub mod start_package;
pub mod update;
pub mod view_api;

pub const KIT_CACHE: &str = "/tmp/hyperware-kit-cache";
pub const KIT_LOG_PATH_DEFAULT: &str = "/tmp/hyperware-kit-cache/logs/log.log";

wit_bindgen::generate!({
    path: "src/run_tests/wit",
    world: "tester-sys-v0",
    generate_unused_types: true,
    additional_derives: [serde::Deserialize, serde::Serialize],
});
