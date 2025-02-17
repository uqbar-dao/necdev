use std::path::PathBuf;

use color_eyre::{eyre::eyre, Result, Section};
use fs_err as fs;
use serde_json::json;
use tracing::{info, instrument, warn};

use crate::{boot_fake_node::extract_zip, inject_message, KIT_CACHE, KIT_LOG_PATH_DEFAULT};

#[instrument(level = "trace", skip_all)]
fn make_app_store_message(
    process_name: &str,
    node: Option<&str>,
    message: &serde_json::Value,
) -> Result<serde_json::Value> {
    inject_message::make_message(
        &format!("{process_name}:app-store:sys"),
        Some(5),
        &message.to_string(),
        node,
        None,
        None,
    )
}

#[instrument(level = "trace", skip_all)]
fn make_list_apis(node: Option<&str>) -> Result<serde_json::Value> {
    let message = json!("Apis");
    make_app_store_message("main", node, &message)
}

#[instrument(level = "trace", skip_all)]
fn make_get_app(
    node: Option<&str>,
    package_name: &str,
    publisher_node: &str,
) -> Result<serde_json::Value> {
    let message = json!({
        "GetApp": {
            "package_name": package_name,
            "publisher_node": publisher_node,
        },
    });
    make_app_store_message("chain", node, &message)
}

#[instrument(level = "trace", skip_all)]
fn make_get_api(
    node: Option<&str>,
    package_name: &str,
    publisher_node: &str,
) -> Result<serde_json::Value> {
    let message = json!({
        "GetApi": {
            "package_name": package_name,
            "publisher_node": publisher_node,
        },
    });
    make_app_store_message("main", node, &message)
}

#[instrument(level = "trace", skip_all)]
fn make_download(
    node: Option<&str>,
    package_name: &str,
    publisher_node: &str,
    download_from: Option<&str>,
    desired_version_hash: &str,
) -> Result<serde_json::Value> {
    let download_from = download_from.unwrap_or_else(|| publisher_node);
    let message = json!({
        "LocalDownload": {
            "package_id": {
                "package_name": package_name,
                "publisher_node": publisher_node,
            },
            "download_from": download_from,
            "desired_version_hash": desired_version_hash,
        },
    });
    make_app_store_message("downloads", node, &message)
}

#[instrument(level = "trace", skip_all)]
fn split_package_id(package_id: &str) -> Result<(String, String)> {
    let mut pids = package_id.splitn(2, ':');
    let (Some(package_name), Some(publisher_node), None) = (pids.next(), pids.next(), pids.next())
    else {
        return Err(eyre!(
            "package_id must be None or Some(<package>:<publisher>)"
        ));
    };
    Ok((package_name.to_string(), publisher_node.to_string()))
}

#[instrument(level = "trace", skip_all)]
async fn get_version_hash(
    node: Option<&str>,
    url: &str,
    package_name: &str,
    publisher_node: &str,
) -> Result<String> {
    let request = make_get_app(node, package_name, publisher_node)?;
    let response = inject_message::send_request(url, request).await?;
    let (body, _) = parse_response(response, url).await?;
    let body: serde_json::Value = serde_json::from_str(&body)?;
    let Some(result) = body.get("GetApp") else {
        return Err(eyre!(
            "Couldn't get version hash: bad response from node at {url}: {body}"
        ));
    };
    return match result {
        serde_json::Value::String(s) => Ok(s.clone()),
        serde_json::Value::Null => {
            warn!("Couldn't get version hash: got Null from node at {url}: {body}");
            Ok(String::new())
        }
        _ => Err(eyre!(
            "Couldn't get version hash: got unexpected result from node at {url}: {body}"
        )),
    };
}

#[instrument(level = "trace", skip_all)]
async fn parse_response(
    response: reqwest::Response,
    url: &str,
) -> Result<(String, Option<Vec<u8>>)> {
    let inject_message::Response { body, lazy_load_blob, .. } =
        inject_message::parse_response(response)
            .await
            .map_err(|e| {
                let e_string = e.to_string();
                if e_string.contains("Failed with status code:") {
                    eyre!("{e_string}\ncheck logs (default at {KIT_LOG_PATH_DEFAULT}) for full http response")
                        .with_suggestion(|| format!("is Hyperdrive running at url {url}?"))
                } else {
                    eyre!(e_string)
                }
            })?;
    Ok((body, lazy_load_blob))
}

#[instrument(level = "trace", skip_all)]
fn rewrite_list_apis(mut output: serde_json::Value) -> Result<serde_json::Value> {
    if let serde_json::Value::Object(ref mut obj) = output {
        if let Some(serde_json::Value::Object(apis_response)) = obj.get_mut("ApisResponse") {
            if let Some(serde_json::Value::Array(apis)) = apis_response.get_mut("apis") {
                let transformed_apis: Vec<_> = apis
                    .iter()
                    .map(|api| {
                        if let serde_json::Value::Object(api_map) = api {
                            let package_name =
                                api_map.get("package_name").unwrap().as_str().unwrap();
                            let publisher_node =
                                api_map.get("publisher_node").unwrap().as_str().unwrap();
                            serde_json::Value::String(format!("{package_name}:{publisher_node}"))
                        } else {
                            serde_json::Value::String(String::new())
                        }
                    })
                    .collect();

                // Replace the old array with the new one
                *apis = transformed_apis;
            }
        }
    }
    Ok(output)
}

#[instrument(level = "trace", skip_all)]
async fn await_download(node: Option<&str>, url: &str, package_id: &str) -> Result<()> {
    loop {
        let apis = list_apis(node, url, false).await?;
        if check_element_exists(&apis, package_id) {
            return Ok(());
        }
        tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
    }
}

#[instrument(level = "trace", skip_all)]
fn check_element_exists(data: &serde_json::Value, element: &str) -> bool {
    if let Some(apis_response) = data.get("ApisResponse") {
        if let Some(apis) = apis_response.get("apis") {
            if let Some(array) = apis.as_array() {
                return array.iter().any(|item| item.as_str() == Some(element));
            }
        }
    }
    false
}

#[instrument(level = "trace", skip_all)]
async fn download(
    node: Option<&str>,
    url: &str,
    package_id: &str,
    download_from: Option<&str>,
    desired_version_hash: Option<&str>,
) -> Result<()> {
    let (package_name, publisher_node) = split_package_id(package_id)?;
    let desired_version_hash = match desired_version_hash {
        Some(hash) => hash.to_string(),
        None => get_version_hash(node, url, &package_name, &publisher_node).await?,
    };
    if desired_version_hash.is_empty() {
        return Err(eyre!("Failed to get required version hash"));
    }
    let request = make_download(
        node,
        &package_name,
        &publisher_node,
        download_from,
        &desired_version_hash,
    )?;
    let response = inject_message::send_request(url, request).await?;
    let (body, _) = parse_response(response, url).await?;
    if body.contains("Success") {
        Ok(())
    } else if body.contains("Started") {
        await_download(node, url, package_id).await
    } else {
        Err(eyre!(
            "Could not find package {package_id} locally or via download from {}: {body}",
            download_from.unwrap_or_else(|| {
                let mut iter = package_id.split(':');
                iter.next();
                iter.next().unwrap()
            }),
        ))
    }
}

#[instrument(level = "trace", skip_all)]
async fn list_apis(node: Option<&str>, url: &str, verbose: bool) -> Result<serde_json::Value> {
    let request = make_list_apis(node)?;
    let response = inject_message::send_request(url, request).await?;
    let (body, _) = parse_response(response, url).await?;
    let body = serde_json::from_str::<serde_json::Value>(&body)?;
    let body = rewrite_list_apis(body)?;
    if verbose {
        info!("{}", serde_json::to_string_pretty(&body)?);
    }
    Ok(body)
}

#[instrument(level = "trace", skip_all)]
async fn get_api(
    node: Option<&str>,
    url: &str,
    package_id: &str,
    download_from: Option<&str>,
    verbose: bool,
    is_first_call: bool,
) -> Result<PathBuf> {
    let (package_name, publisher_node) = split_package_id(package_id)?;
    let request = make_get_api(node, &package_name, &publisher_node)?;
    let response = inject_message::send_request(url, request).await?;
    let (body, blob) = parse_response(response, url).await?;
    let zip_dir = if let Some(blob) = blob {
        // get_api success
        let api_name = format!("{}-api", package_id);
        let zip_dir = PathBuf::from(KIT_CACHE).join(api_name);
        let zip_path = zip_dir.join(format!("{}-api.zip", package_id));
        if zip_dir.exists() {
            fs::remove_dir_all(&zip_dir)?;
        }
        fs::create_dir_all(&zip_dir)?;
        fs::write(&zip_path, blob)?;
        extract_zip(&zip_path)?;
        for entry in fs::read_dir(&zip_dir)? {
            let entry = entry?;
            let path = entry.path();
            if Some("wit") == path.extension().and_then(|s| s.to_str()) {
                let file_path = path.to_str().unwrap_or_default();
                let wit_contents = fs::read_to_string(&path)?;
                if verbose {
                    info!("{}\n\n{}", file_path, wit_contents);
                }
            }
        }
        zip_dir
    } else {
        if is_first_call && body.contains("Failure") {
            // try to download the package & try again
            download(node, url, package_id, download_from, None).await?;
            Box::pin(get_api(
                node,
                url,
                package_id,
                download_from,
                verbose,
                false,
            ))
            .await?
        } else {
            // unexpected case
            let body = serde_json::from_str::<serde_json::Value>(&body)?;
            return Err(eyre!("{}", serde_json::to_string_pretty(&body)?));
        }
    };

    Ok(zip_dir)
}

#[instrument(level = "trace", skip_all)]
pub async fn execute(
    node: Option<&str>,
    package_id: Option<&str>,
    url: &str,
    download_from: Option<&str>,
    verbose: bool,
) -> Result<Option<PathBuf>> {
    if let Some(package_id) = package_id {
        Ok(Some(
            get_api(node, url, &package_id, download_from, verbose, true).await?,
        ))
    } else {
        list_apis(node, url, verbose).await?;
        Ok(None)
    }
}
