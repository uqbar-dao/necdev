use std::collections::{HashMap, HashSet};
use std::io::{BufRead, Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::SystemTime;

use color_eyre::{
    Section,
    {
        eyre::{eyre, WrapErr},
        Result,
    },
};
use fs_err as fs;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::{debug, info, instrument, warn};
use walkdir::WalkDir;
use zip::write::FileOptions;

use hyperware_process_lib::{kernel_types::Erc721Metadata, PackageId};

use crate::publish::make_local_file_link_path;
use crate::run_tests::types::BroadcastRecvBool;
use crate::setup::{
    check_js_deps, check_py_deps, check_rust_deps, get_deps, get_newest_valid_node_version,
    get_python_version, REQUIRED_PY_PACKAGE,
};
use crate::view_api;
use crate::KIT_CACHE;

mod rewrite;
use rewrite::copy_and_rewrite_package;

const PY_VENV_NAME: &str = "process_env";
const JAVASCRIPT_SRC_PATH: &str = "src/lib.js";
const PYTHON_SRC_PATH: &str = "src/lib.py";
const RUST_SRC_PATH: &str = "src/lib.rs";
const PACKAGE_JSON_NAME: &str = "package.json";
const COMPONENTIZE_MJS_NAME: &str = "componentize.mjs";
const HYPERWARE_WIT_1_0_0_URL: &str =
    //"https://raw.githubusercontent.com/kinode-dao/hyperware-wit/v1.0.0/hyperware.wit";
    "https://gist.githubusercontent.com/nick1udwig/3cfef4c96d945513c5fbc69d6bfbb4d9/raw/46d9a404813009a2adab54e9cc3e950cbe14ba3f/hyperware.wit";
const WASI_VERSION: &str = "27.0.0"; // TODO: un-hardcode
const DEFAULT_WORLD_0_7_0: &str = "process";
const DEFAULT_WORLD_0_8_0: &str = "process-v0";
const KINODE_PROCESS_LIB_CRATE_NAME: &str = "hyperware_process_lib";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CargoFile {
    package: CargoPackage,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CargoPackage {
    name: String,
}

pub fn make_fake_kill_chan() -> BroadcastRecvBool {
    let (_send_to_kill, recv_kill) = tokio::sync::broadcast::channel(1);
    recv_kill
}

pub fn make_pkg_publisher(metadata: &Erc721Metadata) -> String {
    let package_name = metadata.properties.package_name.as_str();
    let publisher = metadata.properties.publisher.as_str();
    let pkg_publisher = format!("{}:{}", package_name, publisher);
    pkg_publisher
}

pub fn make_zip_filename(package_dir: &Path, pkg_publisher: &str) -> PathBuf {
    let zip_filename = package_dir
        .join("target")
        .join(pkg_publisher)
        .with_extension("zip");
    zip_filename
}

#[instrument(level = "trace", skip_all)]
pub fn hash_zip_pkg(zip_path: &Path) -> Result<String> {
    let mut file = fs::File::open(&zip_path)?;
    let mut hasher = Sha256::new();
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;
    hasher.update(&buffer);
    let hash_result = hasher.finalize();
    Ok(format!("{hash_result:x}"))
}

#[instrument(level = "trace", skip_all)]
pub fn zip_pkg(package_dir: &Path, pkg_publisher: &str) -> Result<(PathBuf, String)> {
    let pkg_dir = package_dir.join("pkg");
    let target_dir = package_dir.join("target");
    fs::create_dir_all(&target_dir)?;
    let zip_filename = make_zip_filename(package_dir, pkg_publisher);
    zip_directory(&pkg_dir, &zip_filename.to_str().unwrap())?;

    let hash = hash_zip_pkg(&zip_filename)?;
    Ok((zip_filename, hash))
}

#[instrument(level = "trace", skip_all)]
fn zip_directory(directory: &Path, zip_filename: &str) -> Result<()> {
    let file = fs::File::create(zip_filename)?;

    let mut zip = zip::ZipWriter::new(file);

    let options = FileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated)
        .unix_permissions(0o755)
        .last_modified_time(zip::DateTime::from_date_and_time(2023, 6, 19, 0, 0, 0).unwrap());

    let mut walk_dir = WalkDir::new(directory)
        .into_iter()
        .filter_map(|entry| entry.ok())
        .collect::<Vec<_>>();
    walk_dir.sort_by_key(|entry| entry.path().to_owned());
    for entry in walk_dir {
        let path = entry.path();
        let name = path.strip_prefix(Path::new(directory))?;

        if path.is_file() {
            zip.start_file(name.to_string_lossy(), options)?;
            let mut f = fs::File::open(path)?;
            let mut buffer = Vec::new();
            f.read_to_end(&mut buffer)?;
            zip.write_all(&*buffer)?;
        } else if name.as_os_str().len() != 0 {
            // Only if it is not the root directory
            zip.add_directory(name.to_string_lossy(), options)?;
        }
    }

    zip.finish()?;
    Ok(())
}

#[instrument(level = "trace", skip_all)]
pub fn has_feature(cargo_toml_path: &str, feature: &str) -> Result<bool> {
    let cargo_toml_content = fs::read_to_string(cargo_toml_path)?;
    let cargo_toml: toml::Value = cargo_toml_content.parse()?;

    if let Some(features) = cargo_toml.get("features").and_then(|f| f.as_table()) {
        Ok(features.contains_key(feature))
    } else {
        Ok(false)
    }
}

#[instrument(level = "trace", skip_all)]
pub fn remove_missing_features(cargo_toml_path: &Path, features: Vec<&str>) -> Result<Vec<String>> {
    let cargo_toml_content = fs::read_to_string(cargo_toml_path)?;
    let cargo_toml: toml::Value = cargo_toml_content.parse()?;
    let Some(cargo_features) = cargo_toml.get("features").and_then(|f| f.as_table()) else {
        return Ok(vec![]);
    };

    Ok(features
        .iter()
        .filter_map(|f| {
            let f = f.to_string();
            if cargo_features.contains_key(&f) {
                Some(f)
            } else {
                None
            }
        })
        .collect())
}

/// Check if the first element is empty and there are no more elements
#[instrument(level = "trace", skip_all)]
fn is_only_empty_string(splitted: &Vec<&str>) -> bool {
    let mut parts = splitted.iter();
    parts.next() == Some(&"") && parts.next().is_none()
}

#[instrument(level = "trace", skip_all)]
pub fn run_command(cmd: &mut Command, verbose: bool) -> Result<Option<(String, String)>> {
    if verbose {
        let mut child = cmd.spawn()?;
        let result = child.wait()?;
        if result.success() {
            return Ok(None);
        } else {
            return Err(eyre!(
                "Command `{} {:?}` failed with exit code {:?}",
                cmd.get_program().to_str().unwrap(),
                cmd.get_args()
                    .map(|a| a.to_str().unwrap())
                    .collect::<Vec<_>>(),
                result.code(),
            ));
        }
    }
    let output = match cmd.output() {
        Ok(o) => o,
        Err(e) => {
            return Err(eyre!(
                "Command `{} {:?}` failed with error {:?}",
                cmd.get_program().to_str().unwrap(),
                cmd.get_args()
                    .map(|a| a.to_str().unwrap())
                    .collect::<Vec<_>>(),
                e,
            ));
        }
    };
    if output.status.success() {
        Ok(Some((
            String::from_utf8_lossy(&output.stdout).to_string(),
            String::from_utf8_lossy(&output.stderr).to_string(),
        )))
    } else {
        Err(eyre!(
            "Command `{} {:?}` failed with exit code {:?}\nstdout: {}\nstderr: {}",
            cmd.get_program().to_str().unwrap(),
            cmd.get_args()
                .map(|a| a.to_str().unwrap())
                .collect::<Vec<_>>(),
            output.status.code(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        ))
    }
}

#[instrument(level = "trace", skip_all)]
pub async fn download_file(url: &str, path: &Path) -> Result<()> {
    fs::create_dir_all(&KIT_CACHE)?;
    let mut hasher = Sha256::new();
    hasher.update(url.as_bytes());
    let hashed_url = hasher.finalize();
    let hashed_url_path = Path::new(KIT_CACHE).join(format!("{hashed_url:x}"));

    let content = if hashed_url_path.exists() {
        fs::read(hashed_url_path)?
    } else {
        let response = reqwest::get(url).await?;

        // Check if response status is 200 (OK)
        if response.status() != reqwest::StatusCode::OK {
            return Err(eyre!(
                "Failed to download file: HTTP Status {}",
                response.status()
            ));
        }

        let content = response.bytes().await?.to_vec();
        fs::write(hashed_url_path, &content)?;
        content
    };

    if path.exists() {
        if path.is_dir() {
            fs::remove_dir_all(path)?;
        } else {
            let existing_content = fs::read(path)?;
            if content == existing_content {
                return Ok(());
            }
        }
    }
    fs::create_dir_all(
        path.parent()
            .ok_or_else(|| eyre!("path doesn't have parent"))?,
    )?;
    fs::write(path, &content)?;
    Ok(())
}

#[instrument(level = "trace", skip_all)]
pub fn read_metadata(package_dir: &Path) -> Result<Erc721Metadata> {
    let metadata: Erc721Metadata =
        serde_json::from_reader(fs::File::open(package_dir.join("metadata.json"))
            .wrap_err_with(|| "Missing required metadata.json file. See discussion at https://book.hyperware.ai/my_first_app/chapter_1.html?highlight=metadata.json#metadatajson")?
        )?;
    Ok(metadata)
}

#[instrument(level = "trace", skip_all)]
pub fn read_and_update_metadata(package_dir: &Path) -> Result<Erc721Metadata> {
    let mut metadata = read_metadata(package_dir)?;

    let metadata_dot_json =
        make_local_file_link_path(&package_dir.join("metadata.json"), "metadata.json")?;

    let current_version_field = semver::Version::parse(&metadata.properties.current_version)?;
    let most_recent_version: semver::Version = metadata
        .properties
        .code_hashes
        .keys()
        .filter_map(|s| semver::Version::parse(&s).ok())
        .max()
        .ok_or_else(|| eyre!("{metadata_dot_json} doesn't list versions"))?;

    if most_recent_version == current_version_field {
        // we're up-to-date: don't edit
    } else if most_recent_version > current_version_field {
        // we're out-of-date: update
        replace_version_in_file(
            &package_dir.join("metadata.json"),
            r#"("current_version":\s*")(\d+\.\d+\.\d+)"#,
            &format!(r#"${{1}}{most_recent_version}"#),
        )?;
        metadata = read_metadata(package_dir)?;
    } else {
        // unexpected case: error
        return Err(eyre!(
            "{} has a current_version ({}) that does not exist: newest listed version {}",
            metadata_dot_json,
            current_version_field,
            most_recent_version,
        ));
    }

    Ok(metadata)
}

fn replace_version_in_file(file_path: &Path, pattern: &str, new_version: &str) -> Result<()> {
    let file = fs::File::open(&file_path)?;
    let reader = std::io::BufReader::new(file);

    let mut content = String::new();
    let version_regex = regex::Regex::new(pattern).unwrap();

    for line in reader.lines() {
        let line = line?;
        let new_line = if version_regex.is_match(&line) {
            version_regex.replace(&line, new_version).to_string()
        } else {
            line
        };
        content.push_str(&new_line);
        content.push('\n');
    }

    fs::write(file_path, content.as_bytes())?;
    Ok(())
}

/// Regex to dynamically capture the world name after 'world'
fn extract_world(data: &str) -> Option<String> {
    let re = regex::Regex::new(r"world\s+([^\s\{]+)").unwrap();
    re.captures(data)
        .and_then(|caps| caps.get(1).map(|match_| match_.as_str().to_string()))
}

fn extract_worlds_from_files(directory: &Path) -> Vec<String> {
    let mut worlds = vec![];

    // Safe to return early if directory reading fails
    let entries = match fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(_) => return worlds,
    };

    for entry in entries.filter_map(Result::ok) {
        let path = entry.path();
        if !path.is_file()
            || Some("hyperware.wit") == path.file_name().and_then(|s| s.to_str())
            || Some("wit") != path.extension().and_then(|s| s.to_str())
        {
            continue;
        }
        let contents = fs::read_to_string(&path).unwrap_or_default();
        if let Some(world) = extract_world(&contents) {
            worlds.push(world);
        }
    }

    worlds
}

fn get_world_or_default(directory: &Path, default_world: &str) -> String {
    let worlds = extract_worlds_from_files(directory);
    if worlds.len() == 1 {
        return worlds[0].clone();
    }
    warn!(
        "Found {} worlds in {directory:?}; defaulting to {default_world}",
        worlds.len()
    );
    default_world.to_string()
}

#[instrument(level = "trace", skip_all)]
fn copy_dir(src: impl AsRef<Path>, dst: impl AsRef<Path>) -> Result<()> {
    let src = src.as_ref();
    let dst = dst.as_ref();
    if !dst.exists() {
        fs::create_dir_all(dst)?;
    }

    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());

        if src_path.is_dir() {
            copy_dir(&src_path, &dst_path)?;
        } else {
            fs::copy(&src_path, &dst_path)?;
        }
    }
    Ok(())
}

fn file_with_extension_exists(dir: &Path, extension: &str) -> bool {
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.filter_map(Result::ok) {
            let path = entry.path();
            if path.is_file() && path.extension().and_then(|ext| ext.to_str()) == Some(extension) {
                return true;
            }
        }
    }
    false
}

#[instrument(level = "trace", skip_all)]
fn parse_version_from_url(url: &str) -> Result<semver::VersionReq> {
    let re = regex::Regex::new(r"\?tag=v([0-9]+\.[0-9]+\.[0-9]+)$").unwrap();
    if let Some(caps) = re.captures(url) {
        if let Some(version) = caps.get(1) {
            return Ok(semver::VersionReq::parse(&format!(
                "^{}",
                version.as_str()
            ))?);
        }
    }
    Err(eyre!("No valid version found in the URL"))
}

#[instrument(level = "trace", skip_all)]
fn find_crate_versions(
    crate_name: &str,
    packages: &HashMap<cargo_metadata::PackageId, &cargo_metadata::Package>,
) -> Result<HashMap<semver::VersionReq, Vec<String>>> {
    let mut versions = HashMap::new();

    // Iterate over all packages
    for package in packages.values() {
        // Check each dependency of the package
        for dependency in &package.dependencies {
            if dependency.name == crate_name {
                let version = if dependency.req != semver::VersionReq::default() {
                    dependency.req.clone()
                } else {
                    if let Some(ref source) = dependency.source {
                        match parse_version_from_url(source) {
                            Ok(v) => v,
                            Err(e) => {
                                warn!("Error parsing import version: {e}");
                                continue;
                            }
                        }
                    } else {
                        semver::VersionReq::default()
                    }
                };
                versions
                    .entry(version)
                    .or_insert_with(Vec::new)
                    .push(package.name.clone());
            }
        }
    }

    Ok(versions)
}

#[instrument(level = "trace", skip_all)]
fn check_process_lib_version(cargo_toml_path: &Path) -> Result<()> {
    let metadata = match cargo_metadata::MetadataCommand::new()
        .manifest_path(cargo_toml_path)
        .exec()
    {
        Ok(m) => m,
        Err(_) => {
            warn!(
                "Couldn't find Cargo.toml where expected: {:?}; continuing.",
                cargo_toml_path,
            );
            return Ok(());
        }
    };
    let packages: HashMap<cargo_metadata::PackageId, &cargo_metadata::Package> = metadata
        .packages
        .iter()
        .map(|package| (package.id.clone(), package))
        .collect();
    let versions = find_crate_versions(KINODE_PROCESS_LIB_CRATE_NAME, &packages)?;
    if versions.len() > 1 {
        return Err(eyre!(
            "Found different versions of {} in different crates:{}",
            KINODE_PROCESS_LIB_CRATE_NAME,
            versions.iter().fold(String::new(), |s, (version, crates)| {
                format!("{s}\n{version}\t{crates:?}")
            })
        )
        .with_suggestion(|| {
            format!(
                "Set all {} versions to be the same to avoid hard-to-debug errors.",
                KINODE_PROCESS_LIB_CRATE_NAME,
            )
        }));
    }
    Ok(())
}

/// Scans all .rs files in a directory recursively and returns the most recent
/// modification time of any included file
pub fn get_latest_include_mod_time<P: AsRef<Path>>(dir: P) -> Result<Option<SystemTime>> {
    let includes = scan_includes(dir)?;

    let mut latest_time = None;

    for path in includes {
        match get_file_modified_time(&path) {
            Ok(mod_time) => {
                latest_time = Some(match latest_time {
                    Some(current_latest) => std::cmp::max(current_latest, mod_time),
                    None => mod_time,
                });
            }
            Err(e) => warn!("Could not get modification time for {path:?}: {e}"),
        }
    }

    Ok(latest_time)
}

/// Scans all .rs files in a directory recursively and returns arguments
/// to include!, include_str!, and include_bytes! macros
#[instrument(level = "trace", skip_all)]
pub fn scan_includes<P: AsRef<Path>>(dir: P) -> Result<Vec<PathBuf>> {
    let mut includes = Vec::new();
    let include_regex =
        regex::Regex::new(r#"(?:include|include_str|include_bytes)!\s*\(\s*"([^"]+)"\s*\)"#)?;

    // Recursively walk directory
    visit_dirs(dir.as_ref(), &include_regex, &mut includes)?;

    Ok(includes)
}

#[instrument(level = "trace", skip_all)]
fn visit_dirs(dir: &Path, regex: &regex::Regex, includes: &mut Vec<PathBuf>) -> Result<()> {
    if dir.is_dir() {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.is_dir() {
                visit_dirs(&path, regex, includes)?;
            } else if let Some(ext) = path.extension() {
                if ext == "rs" {
                    scan_file(&path, regex, includes)?;
                }
            }
        }
    }
    Ok(())
}

#[instrument(level = "trace", skip_all)]
fn scan_file(file: &Path, regex: &regex::Regex, includes: &mut Vec<PathBuf>) -> Result<()> {
    let contents = fs::read_to_string(file)?;

    for cap in regex.captures_iter(&contents) {
        if let Some(path) = cap.get(1) {
            includes.push(file.parent().unwrap().join(path.as_str()));
        }
    }

    Ok(())
}

#[instrument(level = "trace", skip_all)]
fn get_most_recent_modified_time(
    dir: &Path,
    exclude_files: &HashSet<&str>,
    exclude_extensions: &HashSet<&str>,
    exclude_dirs: &HashSet<&str>,
    must_exist_dirs: &mut HashSet<&str>,
    is_recursion: bool,
) -> Result<(Option<SystemTime>, Option<SystemTime>)> {
    let mut most_recent: Option<SystemTime> = None;
    let mut most_recent_excluded: Option<SystemTime> = None;

    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();

        let file_name = path
            .file_name()
            .unwrap_or_default()
            .to_str()
            .unwrap_or_default();

        if exclude_files.contains(file_name) {
            let file_time = get_file_modified_time(&path)?;
            most_recent_excluded =
                Some(most_recent_excluded.map_or(file_time, |t| t.max(file_time)));
            continue;
        }

        if path.is_dir() {
            let dir_name = path
                .file_name()
                .unwrap_or_default()
                .to_str()
                .unwrap_or_default();
            must_exist_dirs.remove(dir_name);
            if exclude_dirs.contains(dir_name) {
                continue;
            }

            let (sub_time, sub_time_excluded) = get_most_recent_modified_time(
                &path,
                exclude_files,
                exclude_extensions,
                exclude_dirs,
                must_exist_dirs,
                true,
            )?;

            if let Some(st) = sub_time {
                most_recent = Some(most_recent.map_or(st, |t| t.max(st)));
            }
            if let Some(ste) = sub_time_excluded {
                most_recent_excluded = Some(most_recent_excluded.map_or(ste, |t| t.max(ste)));
            }
        } else {
            if let Some(extension) = path.extension() {
                if exclude_extensions.contains(&extension.to_str().unwrap_or_default()) {
                    let file_time = get_file_modified_time(&path)?;
                    most_recent_excluded =
                        Some(most_recent_excluded.map_or(file_time, |t| t.max(file_time)));
                    continue;
                }
            }

            let file_time = get_file_modified_time(&path)?;
            most_recent = Some(most_recent.map_or(file_time, |t| t.max(file_time)));
        }
    }

    if !is_recursion && !must_exist_dirs.is_empty() {
        return Err(eyre!("Didn't find required dirs: {must_exist_dirs:?}"));
    }

    debug!("get_most_recent_modified_time: most_recent: {most_recent:?}, most_recent_excluded: {most_recent_excluded:?}");

    Ok((most_recent, most_recent_excluded))
}

#[instrument(level = "trace", skip_all)]
fn get_file_modified_time(file_path: &Path) -> Result<SystemTime> {
    let metadata = fs::metadata(file_path)?;
    Ok(metadata.modified()?)
}

#[instrument(level = "trace", skip_all)]
fn get_cargo_package_path(package: &cargo_metadata::Package) -> Result<PathBuf> {
    match package
        .manifest_path
        .parent()
        .map(|p| p.as_std_path().to_path_buf())
    {
        Some(p) => Ok(p),
        None => Err(eyre!(
            "Cargo manifest path {} has no parent",
            package.manifest_path
        )),
    }
}

#[instrument(level = "trace", skip_all)]
fn is_up_to_date(
    build_with_features_path: &Path,
    build_with_cludes_path: &Path,
    features: &str,
    cludes: &str,
    package_dir: &Path,
) -> Result<bool> {
    let old_features = fs::read_to_string(&build_with_features_path).ok();
    let old_cludes = fs::read_to_string(&build_with_cludes_path).ok();

    debug!(
        "is_up_to_date({package_dir:?}):
    old_features == Some(features.to_string()): {}
    old_cludes == Some(cludes.to_string()): {}
    package_dir.join(\"Cargo.lock\").exists(): {}
    package_dir.join(\"pkg\").exists(): {}
    package_dir.join(\"pkg\").join(\"api.zip\").exists(): {}
    file_with_extension_exists(&package_dir.join(\"pkg\"), \"wasm\"): {}",
        old_features == Some(features.to_string()),
        old_cludes == Some(cludes.to_string()),
        package_dir.join("Cargo.lock").exists(),
        package_dir.join("pkg").exists(),
        package_dir.join("pkg").join("api.zip").exists(),
        file_with_extension_exists(&package_dir.join("pkg"), "wasm"),
    );

    if old_features == Some(features.to_string())
        && old_cludes == Some(cludes.to_string())
        && package_dir.join("Cargo.lock").exists()
        && package_dir.join("pkg").exists()
        && package_dir.join("pkg").join("api.zip").exists()
        && file_with_extension_exists(&package_dir.join("pkg"), "wasm")
    {
        let (mut source_time, build_time) = match get_most_recent_modified_time(
            package_dir,
            &HashSet::from(["Cargo.lock", "api.zip"]),
            &HashSet::from(["wasm"]),
            &HashSet::from(["target"]),
            &mut HashSet::from(["target"]),
            false,
        ) {
            Ok(v) => v,
            Err(e) => {
                if e.to_string().starts_with("Didn't find required dirs:") {
                    debug!("is_up_to_date first {e}");
                    return Ok(false);
                } else {
                    return Err(e);
                }
            }
        };
        let Some(build_time) = build_time else {
            debug!("is_up_to_date: no built files: not up-to-date");
            return Ok(false);
        };

        // update source to most recent of package_dir
        //  or package_dir's local deps
        let metadata = cargo_metadata::MetadataCommand::new()
            .manifest_path(package_dir.join("Cargo.toml"))
            .exec()?;
        for package in metadata.packages.iter().filter(|p| p.source.is_none()) {
            let dep_package_dir = get_cargo_package_path(&package)?;
            let (dep_source_time, _) = match get_most_recent_modified_time(
                &dep_package_dir,
                &HashSet::from(["Cargo.lock", "api.zip"]),
                &HashSet::from(["wasm"]),
                &HashSet::from(["target"]),
                &mut HashSet::from(["target"]),
                false,
            ) {
                Ok(v) => v,
                Err(e) => {
                    if e.to_string().starts_with("Didn't find required dirs:") {
                        debug!("is_up_to_date second {e}");
                        return Ok(false);
                    } else {
                        return Err(e);
                    }
                }
            };
            // TODO: refactor source time updating along with get_latest_include_mode_time to map_or
            match source_time {
                None => source_time = dep_source_time,
                Some(ref st) => {
                    if let Some(ref dst) = dep_source_time {
                        if dst.duration_since(st.clone()).is_ok() {
                            // dep has more recent changes than source
                            //  -> update source_time to dep_source_time
                            source_time = dep_source_time;
                        }
                    }
                }
            }
        }

        // update source to most recent of above or include!s
        let include_source_time = get_latest_include_mod_time(package_dir)?;
        // TODO: refactor source time updating along with get_latest_include_mode_time to map_or
        match source_time {
            None => source_time = include_source_time,
            Some(ref st) => {
                if let Some(ref ist) = include_source_time {
                    if ist.duration_since(st.clone()).is_ok() {
                        // includes have more recent changes than source
                        //  -> update source_time to include_source_time
                        source_time = include_source_time;
                    }
                }
            }
        }

        if let Some(source_time) = source_time {
            if build_time.duration_since(source_time).is_ok() {
                // build_time - source_time >= 0
                //  -> current build is up-to-date: don't rebuild
                info!("Build up-to-date.");
                return Ok(true);
            }
        }
    }
    Ok(false)
}

#[instrument(level = "trace", skip_all)]
async fn compile_javascript_wasm_process(
    process_dir: &Path,
    valid_node: Option<String>,
    world: &str,
    verbose: bool,
) -> Result<()> {
    info!(
        "Compiling Javascript Hyperware process in {:?}...",
        process_dir
    );

    let wasm_file_name = process_dir.file_name().and_then(|s| s.to_str()).unwrap();
    let world_name = get_world_or_default(&process_dir.join("target").join("wit"), world);

    let install = "npm install".to_string();
    let componentize = format!("node componentize.mjs {wasm_file_name} {world_name}");
    let (install, componentize) = valid_node
        .map(|valid_node| {
            (
                format!(
                    "source ~/.nvm/nvm.sh && nvm use {} && {}",
                    valid_node, install
                ),
                format!(
                    "source ~/.nvm/nvm.sh && nvm use {} && {}",
                    valid_node, componentize
                ),
            )
        })
        .unwrap_or_else(|| (install, componentize));

    run_command(
        Command::new("bash")
            .args(&["-c", &install])
            .current_dir(process_dir),
        verbose,
    )?;

    run_command(
        Command::new("bash")
            .args(&["-c", &componentize])
            .current_dir(process_dir),
        verbose,
    )?;

    info!(
        "Done compiling Javascript Hyperware process in {:?}.",
        process_dir
    );
    Ok(())
}

#[instrument(level = "trace", skip_all)]
async fn compile_python_wasm_process(
    process_dir: &Path,
    python: &str,
    world: &str,
    verbose: bool,
) -> Result<()> {
    info!("Compiling Python Hyperware process in {:?}...", process_dir);

    let wasm_file_name = process_dir.file_name().and_then(|s| s.to_str()).unwrap();
    let world_name = get_world_or_default(&process_dir.join("target").join("wit"), world);

    let source = format!("source ../{PY_VENV_NAME}/bin/activate");
    let install = format!("pip install {REQUIRED_PY_PACKAGE}");
    let componentize = format!(
        "componentize-py -d ../target/wit/ -w {} componentize lib -o ../../pkg/{}.wasm",
        world_name, wasm_file_name,
    );

    run_command(
        Command::new(python)
            .args(&["-m", "venv", PY_VENV_NAME])
            .current_dir(process_dir),
        verbose,
    )?;
    run_command(
        Command::new("bash")
            .args(&["-c", &format!("{source} && {install} && {componentize}")])
            .current_dir(process_dir.join("src")),
        verbose,
    )?;

    info!("Done compiling Python Hyperware process in {:?}.", process_dir);
    Ok(())
}

#[instrument(level = "trace", skip_all)]
async fn compile_rust_wasm_process(
    process_dir: &Path,
    features: &str,
    verbose: bool,
) -> Result<()> {
    info!("Compiling Rust Hyperware process in {:?}...", process_dir);

    // Paths
    let wit_dir = process_dir.join("target").join("wit");
    let bindings_dir = process_dir
        .join("target")
        .join("bindings")
        .join(process_dir.file_name().unwrap());
    fs::create_dir_all(&bindings_dir)?;

    // Check and download wasi_snapshot_preview1.wasm if it does not exist
    let wasi_snapshot_file = process_dir
        .join("target")
        .join("wasi_snapshot_preview1.wasm");
    let wasi_snapshot_url = format!(
        "https://github.com/bytecodealliance/wasmtime/releases/download/v{}/wasi_snapshot_preview1.reactor.wasm",
        WASI_VERSION,
    );
    download_file(&wasi_snapshot_url, &wasi_snapshot_file).await?;

    // Copy wit directory to bindings
    fs::create_dir_all(&bindings_dir.join("wit"))?;
    for entry in fs::read_dir(&wit_dir)? {
        let entry = entry?;
        fs::copy(
            entry.path(),
            bindings_dir.join("wit").join(entry.file_name()),
        )?;
    }

    // Build the module using Cargo
    let mut args = vec![
        "+nightly",
        "build",
        "--release",
        "--no-default-features",
        "--target",
        "wasm32-wasip1",
        "--target-dir",
        "target",
        "--color=always",
    ];
    let test_only = features == "test";
    let features: Vec<&str> = features.split(',').collect();
    let original_length = if is_only_empty_string(&features) {
        0
    } else {
        features.len()
    };
    let features = remove_missing_features(&process_dir.join("Cargo.toml"), features)?;
    if !test_only && original_length != features.len() {
        info!(
            "process {:?} missing features; using {:?}",
            process_dir, features
        );
    };
    let features = features.join(",");
    if !features.is_empty() {
        args.push("--features");
        args.push(&features);
    }
    let result = run_command(
        Command::new("cargo").args(&args).current_dir(process_dir),
        verbose,
    )?;

    if let Some((stdout, stderr)) = result {
        if stdout.contains("warning") {
            warn!("{}", stdout);
        }
        if stderr.contains("warning") {
            warn!("{}", stderr);
        }
    }

    // Adapt the module using wasm-tools

    // For use inside of process_dir
    // Run `wasm-tools component new`, putting output in pkg/
    //  and rewriting all `_`s to `-`s
    // cargo hates `-`s and so outputs with `_`s; Kimap hates
    //  `_`s and so we convert to and enforce all `-`s
    let wasm_file_name_cab = process_dir
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap()
        .replace("-", "_");
    let wasm_file_name_hep = wasm_file_name_cab.replace("_", "-");

    let wasm_file_prefix = Path::new("target/wasm32-wasip1/release");
    let wasm_file_cab = wasm_file_prefix.join(&format!("{wasm_file_name_cab}.wasm"));

    let wasm_file_pkg = format!("../pkg/{wasm_file_name_hep}.wasm");
    let wasm_file_pkg = Path::new(&wasm_file_pkg);

    let wasi_snapshot_file = Path::new("target/wasi_snapshot_preview1.wasm");

    run_command(
        Command::new("wasm-tools")
            .args(&[
                "component",
                "new",
                wasm_file_cab.to_str().unwrap(),
                "-o",
                wasm_file_pkg.to_str().unwrap(),
                "--adapt",
                wasi_snapshot_file.to_str().unwrap(),
            ])
            .current_dir(process_dir),
        verbose,
    )?;

    info!("Done compiling Rust Hyperware process in {:?}.", process_dir);
    Ok(())
}

#[instrument(level = "trace", skip_all)]
async fn compile_and_copy_ui(
    ui_path: &Path,
    valid_node: Option<String>,
    verbose: bool,
) -> Result<()> {
    info!("Building UI in {:?}...", ui_path);

    if ui_path.exists() && ui_path.is_dir() && ui_path.join("package.json").exists() {
        info!("Running npm install...");

        let install = "npm install".to_string();
        let run = "npm run build:copy".to_string();
        let (install, run) = valid_node
            .map(|valid_node| {
                (
                    format!(
                        "source ~/.nvm/nvm.sh && nvm use {} && {}",
                        valid_node, install
                    ),
                    format!("source ~/.nvm/nvm.sh && nvm use {} && {}", valid_node, run),
                )
            })
            .unwrap_or_else(|| (install, run));

        run_command(
            Command::new("bash")
                .args(&["-c", &install])
                .current_dir(&ui_path),
            verbose,
        )?;

        info!("Running npm run build:copy...");

        run_command(
            Command::new("bash")
                .args(&["-c", &run])
                .current_dir(&ui_path),
            verbose,
        )?;
    } else {
        return Err(eyre!("UI directory {ui_path:?} not found"));
    }

    info!("Done building UI in {:?}.", ui_path);
    Ok(())
}

#[instrument(level = "trace", skip_all)]
async fn build_wit_dir(
    process_dir: &Path,
    apis: &HashMap<String, Vec<u8>>,
    wit_version: Option<u32>,
) -> Result<()> {
    let wit_dir = process_dir.join("target").join("wit");
    if wit_dir.exists() {
        fs::remove_dir_all(&wit_dir)?;
    }
    let wit_url = match wit_version {
        Some(1) | _ => HYPERWARE_WIT_1_0_0_URL,
    };
    download_file(wit_url, &wit_dir.join("hyperware.wit")).await?;
    for (file_name, contents) in apis {
        let destination = wit_dir.join(file_name);
        fs::write(&destination, contents)?;
    }
    Ok(())
}

#[instrument(level = "trace", skip_all)]
async fn compile_package_item(
    path: PathBuf,
    features: String,
    apis: HashMap<String, Vec<u8>>,
    world: String,
    wit_version: Option<u32>,
    verbose: bool,
) -> Result<()> {
    if path.is_dir() {
        let is_rust_process = path.join(RUST_SRC_PATH).exists();
        let is_py_process = path.join(PYTHON_SRC_PATH).exists();
        let is_js_process = path.join(JAVASCRIPT_SRC_PATH).exists();
        if is_rust_process || is_py_process || is_js_process {
            build_wit_dir(&path, &apis, wit_version).await?;
        }

        if is_rust_process {
            compile_rust_wasm_process(&path, &features, verbose).await?;
        } else if is_py_process {
            let python = get_python_version(None, None)?
                .ok_or_else(|| eyre!("kit requires Python 3.10 or newer"))?;
            compile_python_wasm_process(&path, &python, &world, verbose).await?;
        } else if is_js_process {
            let valid_node = get_newest_valid_node_version(None, None)?;
            compile_javascript_wasm_process(&path, valid_node, &world, verbose).await?;
        }
    }
    Ok(())
}

#[instrument(level = "trace", skip_all)]
fn fetch_local_built_dependency(
    apis: &mut HashMap<String, Vec<u8>>,
    wasm_paths: &mut HashSet<PathBuf>,
    local_dependency: &Path,
) -> Result<()> {
    for entry in fs::read_dir(local_dependency.join("api"))? {
        let entry = entry?;
        let path = entry.path();
        let maybe_ext = path.extension().and_then(|s| s.to_str());
        if Some("wit") == maybe_ext {
            let file_name = path
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or_default();
            let wit_contents = fs::read(&path)?;
            apis.insert(file_name.into(), wit_contents);
        }
    }
    for entry in fs::read_dir(local_dependency.join("target").join("api"))? {
        let entry = entry?;
        let path = entry.path();
        let maybe_ext = path.extension().and_then(|s| s.to_str());
        if Some("wasm") == maybe_ext {
            wasm_paths.insert(path);
        }
    }
    Ok(())
}

#[instrument(level = "trace", skip_all)]
async fn fetch_dependencies(
    package_dir: &Path,
    dependencies: &Vec<String>,
    apis: &mut HashMap<String, Vec<u8>>,
    wasm_paths: &mut HashSet<PathBuf>,
    url: Option<String>,
    download_from: Option<&str>,
    mut local_dependencies: Vec<PathBuf>,
    features: &str,
    default_world: Option<&str>,
    include: &HashSet<PathBuf>,
    exclude: &HashSet<PathBuf>,
    rewrite: bool,
    force: bool,
    verbose: bool,
) -> Result<()> {
    if let Err(e) = Box::pin(execute(
        package_dir,
        true,
        false,
        include,
        exclude,
        true,
        features,
        url.clone(),
        download_from,
        default_world,
        vec![], // TODO: what about deps-of-deps?
        vec![],
        rewrite,
        false,
        force,
        verbose,
        true,
    ))
    .await
    {
        debug!("Failed to build self as dependency: {e:?}");
    } else if let Err(e) = fetch_local_built_dependency(apis, wasm_paths, package_dir) {
        debug!("Failed to fetch self as dependency: {e:?}");
    };
    let canon_package_dir = package_dir.canonicalize()?;
    for local_dependency in &local_dependencies
        .iter()
        .filter(|d| *d != &canon_package_dir)
        .collect::<Vec<&PathBuf>>()
    {
        // build dependency
        let local_dep_deps = local_dependencies
            .clone()
            .into_iter()
            .filter(|d| *d != canon_package_dir)
            .collect();
        Box::pin(execute(
            local_dependency,
            true,
            false,
            include,
            exclude,
            true,
            features,
            url.clone(),
            download_from,
            default_world,
            local_dep_deps,
            vec![],
            rewrite,
            false,
            force,
            verbose,
            false,
        ))
        .await?;
        fetch_local_built_dependency(apis, wasm_paths, &local_dependency)?;
    }
    let Some(ref url) = url else {
        return Ok(());
    };
    local_dependencies.push(package_dir.into());
    let local_dependencies: HashSet<&str> = local_dependencies
        .iter()
        .map(|p| p.file_name().and_then(|f| f.to_str()).unwrap())
        .collect();
    debug!("fetch_dependencies: local_dependencies: {local_dependencies:?}");
    for dependency in dependencies {
        let Ok(dep) = dependency.parse::<PackageId>() else {
            return Err(eyre!(
                "Dependencies must be PackageIds (e.g. `package:publisher.os`); given {dependency}.",
            ));
        };
        if local_dependencies.contains(dep.package()) {
            continue;
        }
        let Some(zip_dir) =
            view_api::execute(None, Some(dependency), url, download_from, false).await?
        else {
            return Err(eyre!(
                "Got unexpected result from fetching API for {dependency}"
            ));
        };
        for entry in fs::read_dir(zip_dir)? {
            let entry = entry?;
            let path = entry.path();
            let maybe_ext = path.extension().and_then(|s| s.to_str());
            if Some("wit") == maybe_ext {
                let file_name = path
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or_default();
                let wit_contents = fs::read(&path)?;
                apis.insert(file_name.into(), wit_contents);
            } else if Some("wasm") == maybe_ext {
                wasm_paths.insert(path);
            }
        }
    }
    Ok(())
}

fn extract_imports_exports_from_wit(input: &str) -> (Vec<String>, Vec<String>) {
    let import_re = regex::Regex::new(r"import\s+([^\s;]+)").unwrap();
    let export_re = regex::Regex::new(r"export\s+([^\s;]+)").unwrap();
    let imports: Vec<String> = import_re
        .captures_iter(input)
        .map(|cap| cap[1].to_string())
        .filter(|s| !(s.contains("wasi") || s.contains("hyperware:process/standard")))
        .collect();

    let exports: Vec<String> = export_re
        .captures_iter(input)
        .map(|cap| cap[1].to_string())
        .filter(|s| !s.contains("init"))
        .collect();

    (imports, exports)
}

#[instrument(level = "trace", skip_all)]
fn get_imports_exports_from_wasm(
    path: &PathBuf,
    imports: &mut HashMap<String, Vec<PathBuf>>,
    exports: &mut HashMap<String, PathBuf>,
    should_move_export: bool,
) -> Result<()> {
    let wit = run_command(
        Command::new("wasm-tools").args(["component", "wit", path.to_str().unwrap()]),
        false,
    )?;
    let Some((ref wit, _)) = wit else {
        return Ok(());
    };
    let (wit_imports, wit_exports) = extract_imports_exports_from_wit(wit);
    for wit_import in wit_imports {
        imports
            .entry(wit_import)
            .or_insert_with(Vec::new)
            .push(path.clone());
    }
    for wit_export in wit_exports {
        if exports.contains_key(&wit_export) {
            warn!("found multiple exporters of {wit_export}: {path:?} & {exports:?}");
        }
        let path = if should_move_export {
            let file_name = path
                .file_name()
                .and_then(|f| f.to_str())
                .unwrap()
                .replace("_", "-");
            let new_path = path
                .parent()
                .and_then(|p| p.parent())
                .unwrap()
                .join("target")
                .join("api")
                .join(file_name);
            fs::rename(&path, &new_path)?;
            new_path
        } else {
            path.clone()
        };

        exports.insert(wit_export, path);
    }
    Ok(())
}

#[instrument(level = "trace", skip_all)]
fn find_non_standard(
    package_dir: &Path,
    wasm_paths: &mut HashSet<PathBuf>,
) -> Result<(
    HashMap<String, Vec<PathBuf>>,
    HashMap<String, PathBuf>,
    HashSet<PathBuf>,
)> {
    let mut imports = HashMap::new();
    let mut exports = HashMap::new();

    for entry in fs::read_dir(package_dir.join("pkg"))? {
        let entry = entry?;
        let path = entry.path();
        if wasm_paths.contains(&path) {
            continue;
        }
        if !(path.is_file() && Some("wasm") == path.extension().and_then(|e| e.to_str())) {
            continue;
        }
        get_imports_exports_from_wasm(&path, &mut imports, &mut exports, true)?;
    }
    for export_path in exports.values() {
        if wasm_paths.contains(export_path) {
            // we already have it; don't include it twice
            wasm_paths.remove(export_path);
        }
    }
    for wasm_path in wasm_paths.iter() {
        get_imports_exports_from_wasm(wasm_path, &mut imports, &mut exports, false)?;
    }

    let others = wasm_paths
        .difference(&exports.values().map(|p| p.clone()).collect())
        .map(|p| p.clone())
        .collect();
    Ok((imports, exports, others))
}

#[instrument(level = "trace", skip_all)]
fn get_ui_dirs(
    package_dir: &Path,
    include: &HashSet<PathBuf>,
    exclude: &HashSet<PathBuf>,
) -> Result<Vec<PathBuf>> {
    let ui_dirs = fs::read_dir(package_dir)?
        .filter_map(|entry| {
            let path = entry.ok()?.path();
            if path.is_dir()
                && path.join(PACKAGE_JSON_NAME).exists()
                && !path.join(COMPONENTIZE_MJS_NAME).exists()
                && is_cluded(&path, include, exclude)
            {
                // is dir AND is js AND is not component AND is cluded
                //  -> is UI: add to Vec
                Some(path)
            } else {
                None
            }
        })
        .collect();
    Ok(ui_dirs)
}

#[instrument(level = "trace", skip_all)]
async fn check_and_populate_dependencies(
    package_dir: &Path,
    metadata: &Erc721Metadata,
    skip_deps_check: bool,
    verbose: bool,
) -> Result<(HashMap<String, Vec<u8>>, HashSet<String>)> {
    let mut checked_rust = false;
    let mut checked_py = false;
    let mut checked_js = false;
    let mut apis = HashMap::new();
    let mut dependencies = HashSet::new();
    let mut recv_kill = make_fake_kill_chan();
    // Do we need to do an `is_cluded()` check here?
    //  I think no because we may want to, e.g., build a process that
    //  depends on another that is already built but hasn't changed.
    for entry in fs::read_dir(package_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            if path.join(RUST_SRC_PATH).exists() && !checked_rust && !skip_deps_check {
                let deps = check_rust_deps()?;
                get_deps(deps, &mut recv_kill, verbose).await?;
                checked_rust = true;
            } else if path.join(PYTHON_SRC_PATH).exists() && !checked_py {
                check_py_deps()?;
                checked_py = true;
            } else if path.join(JAVASCRIPT_SRC_PATH).exists() && !checked_js && !skip_deps_check {
                let deps = check_js_deps()?;
                get_deps(deps, &mut recv_kill, verbose).await?;
                checked_js = true;
            } else if Some("api") == path.file_name().and_then(|s| s.to_str()) {
                // read api files: to be used in build
                for entry in fs::read_dir(path)? {
                    let entry = entry?;
                    let path = entry.path();
                    if Some("wit") != path.extension().and_then(|e| e.to_str()) {
                        continue;
                    };
                    let Some(file_name) = path.file_name().and_then(|s| s.to_str()) else {
                        continue;
                    };
                    if let Ok(api_contents) = fs::read(&path) {
                        apis.insert(file_name.to_string(), api_contents);
                    }
                }

                // fetch dependency apis: to be used in build
                if let Some(ref deps) = metadata.properties.dependencies {
                    dependencies.extend(deps.clone());
                }
            }
        }
    }
    Ok((apis, dependencies))
}

#[instrument(level = "trace", skip_all)]
fn zip_api(
    package_dir: &Path,
    target_api_dir: &Path,
    add_paths_to_api: &Vec<PathBuf>,
    metadata: &Erc721Metadata,
) -> Result<()> {
    let mut api_includes = add_paths_to_api.clone();
    if let Some(ref metadata_includes) = metadata.properties.api_includes {
        api_includes.extend_from_slice(metadata_includes);
    }
    for path in api_includes {
        let path = if path.exists() {
            path
        } else {
            package_dir.join(path).canonicalize().unwrap_or_default()
        };
        if !path.exists() {
            warn!("Given path to add to API does not exist: {path:?}");
            continue;
        }
        if let Err(e) = fs::copy(
            &path,
            target_api_dir.join(path.file_name().and_then(|f| f.to_str()).unwrap()),
        ) {
            warn!("Could not add path {path:?} to API: {e:?}");
        }
    }

    let zip_path = package_dir.join("pkg").join("api.zip");
    let zip_path = zip_path.to_str().unwrap();
    zip_directory(&target_api_dir, zip_path)?;
    Ok(())
}

/// is included AND is not excluded
fn is_cluded(path: &Path, include: &HashSet<PathBuf>, exclude: &HashSet<PathBuf>) -> bool {
    (include.is_empty() || include.contains(path)) && !exclude.contains(path)
}

/// package dir looks like:
/// ```
/// metadata.json
/// api/                                  <- optional
///   my_package:publisher.os-v0.wit
/// pkg/
///   api.zip                             <- built
///   manifest.json
///   process_i.wasm                      <- built
///   projess_j.wasm                      <- built
/// process_i/
///   src/
///     lib.rs
///   target/                             <- built
///     api/
///     wit/
/// process_j/
///   src/
///   target/                             <- built
///     api/
///     wit/
/// ```
#[instrument(level = "trace", skip_all)]
async fn compile_package(
    package_dir: &Path,
    skip_deps_check: bool,
    features: &str,
    url: Option<String>,
    default_world: Option<&str>,
    download_from: Option<&str>,
    local_dependencies: Vec<PathBuf>,
    add_paths_to_api: &Vec<PathBuf>,
    include: &HashSet<PathBuf>,
    exclude: &HashSet<PathBuf>,
    rewrite: bool,
    force: bool,
    verbose: bool,
    ignore_deps: bool, // for internal use; may cause problems when adding recursive deps
) -> Result<()> {
    let metadata = read_and_update_metadata(package_dir)?;
    let mut wasm_paths = HashSet::new();
    let (mut apis, dependencies) =
        check_and_populate_dependencies(package_dir, &metadata, skip_deps_check, verbose).await?;

    if !ignore_deps && !dependencies.is_empty() {
        fetch_dependencies(
            package_dir,
            &dependencies.iter().map(|s| s.to_string()).collect(),
            &mut apis,
            &mut wasm_paths,
            url.clone(),
            download_from,
            local_dependencies.clone(),
            features,
            default_world,
            include,
            exclude,
            rewrite,
            force,
            verbose,
        )
        .await?;
    }

    let wit_world = default_world
        .unwrap_or_else(|| match metadata.properties.wit_version {
            None => DEFAULT_WORLD_0_7_0,
            Some(0) | _ => DEFAULT_WORLD_0_8_0,
        })
        .to_string();

    let mut tasks = tokio::task::JoinSet::new();
    let features = features.to_string();
    for entry in fs::read_dir(package_dir)? {
        let Ok(entry) = entry else {
            continue;
        };
        let path = entry.path();
        if !is_cluded(&path, include, exclude) {
            continue;
        }
        tasks.spawn(compile_package_item(
            path,
            features.clone(),
            apis.clone(),
            wit_world.clone(),
            metadata.properties.wit_version,
            verbose.clone(),
        ));
    }
    while let Some(res) = tasks.join_next().await {
        res??;
    }

    // create a target/api/ dir: this will be zipped & published in pkg/
    //  In addition, exporters, below, will be placed here to complete the API
    let api_dir = package_dir.join("api");
    let target_api_dir = package_dir.join("target").join("api");
    if api_dir.exists() {
        copy_dir(&api_dir, &target_api_dir)?;
    } else if !target_api_dir.exists() {
        fs::create_dir_all(&target_api_dir)?;
    }

    if !ignore_deps {
        // find non-standard imports/exports -> compositions
        let (importers, exporters, others) = find_non_standard(package_dir, &mut wasm_paths)?;

        // compose
        for (import, import_paths) in importers {
            let Some(export_path) = exporters.get(&import) else {
                return Err(eyre!(
                    "Processes {import_paths:?} required export {import} not found in `pkg/`.",
                ));
            };
            let export_path = export_path.to_str().unwrap();
            for import_path in import_paths {
                let import_path_str = import_path.to_str().unwrap();
                run_command(
                    Command::new("wasm-tools").args([
                        "compose",
                        import_path_str,
                        "-d",
                        export_path,
                        "-o",
                        import_path_str,
                    ]),
                    false,
                )?;
            }
        }

        // copy others into pkg/
        for path in &others {
            fs::copy(
                path,
                package_dir
                    .join("pkg")
                    .join(path.file_name().and_then(|f| f.to_str()).unwrap()),
            )?;
        }
    }

    if target_api_dir.exists() {
        // zip & place API inside of pkg/ to publish API
        zip_api(package_dir, &target_api_dir, add_paths_to_api, &metadata)?;
    }

    Ok(())
}

#[instrument(level = "trace", skip_all)]
pub async fn execute(
    package_dir: &Path,
    no_ui: bool,
    ui_only: bool,
    include: &HashSet<PathBuf>,
    exclude: &HashSet<PathBuf>,
    skip_deps_check: bool,
    features: &str,
    url: Option<String>,
    download_from: Option<&str>,
    default_world: Option<&str>,
    local_dependencies: Vec<PathBuf>,
    add_paths_to_api: Vec<PathBuf>,
    rewrite: bool,
    reproducible: bool,
    force: bool,
    verbose: bool,
    ignore_deps: bool, // for internal use; may cause problems when adding recursive deps
) -> Result<()> {
    debug!(
        "execute:
    package_dir={package_dir:?},
    no_ui={no_ui},
    ui_only={ui_only},
    include={include:?},
    exclude={exclude:?},
    skip_deps_check={skip_deps_check},
    features={features},
    url={url:?},
    download_from={download_from:?},
    default_world={default_world:?},
    local_dependencies={local_dependencies:?},
    add_paths_to_api={add_paths_to_api:?},
    reproducible={reproducible},
    force={force},
    verbose={verbose},
    ignore_deps={ignore_deps},"
    );
    if no_ui && ui_only {
        return Err(eyre!(
            "Cannot set both `no_ui` and `ui_only` to true at the same time"
        ));
    }
    if !package_dir.join("pkg").exists() {
        if Some(".DS_Store") == package_dir.file_name().and_then(|s| s.to_str()) {
            info!("Skipping build of {:?}", package_dir);
            return Ok(());
        }
        return Err(eyre!(
            "Required `pkg/` dir not found within given input dir {:?} (or cwd, if none given).",
            package_dir,
        )
        .with_suggestion(|| "Please re-run targeting a package."));
    }
    let build_with_features_path = package_dir.join("target").join("build_with_features.txt");
    let build_with_cludes_path = package_dir.join("target").join("build_with_cludes.txt");
    let cludes = format!("include: {include:?}\nexclude: {exclude:?}");
    if !force
        && is_up_to_date(
            &build_with_features_path,
            &build_with_cludes_path,
            features,
            &cludes,
            package_dir,
        )?
    {
        return Ok(());
    }

    if reproducible {
        let version = env!("CARGO_PKG_VERSION");
        let source = package_dir.canonicalize().unwrap();
        let source = source.to_str().unwrap();
        // get latest version of image
        run_command(
            Command::new("docker").args(&["pull", &format!("nick1udwig/buildpackage:{version}")]),
            true,
        )?;
        run_command(
            Command::new("docker").args(&[
                "run",
                "--rm",
                "--mount",
                &format!("type=bind,source={source},target=/input"),
                &format!("nick1udwig/buildpackage:{version}"),
            ]),
            true,
        )?;
        return Ok(());
    }

    fs::create_dir_all(package_dir.join("target"))?;
    fs::write(&build_with_features_path, features)?;
    fs::write(&build_with_cludes_path, &cludes)?;

    check_process_lib_version(&package_dir.join("Cargo.toml"))?;

    // live_dir is the "dir that is being built" or is "live";
    //  if `!rewrite`, that is just `package_dir`;
    //  else, it is the modified copy that is in `target/rewrite/`
    let live_dir = if !rewrite {
        PathBuf::from(package_dir)
    } else {
        copy_and_rewrite_package(package_dir)?
    };

    let ui_dirs = get_ui_dirs(&live_dir, &include, &exclude)?;
    if !no_ui && !ui_dirs.is_empty() {
        if !skip_deps_check {
            let mut recv_kill = make_fake_kill_chan();
            let deps = check_js_deps()?;
            get_deps(deps, &mut recv_kill, verbose).await?;
        }
        let valid_node = get_newest_valid_node_version(None, None)?;
        for ui_dir in ui_dirs {
            compile_and_copy_ui(&ui_dir, valid_node.clone(), verbose).await?;
        }
    }

    if !ui_only {
        compile_package(
            &live_dir,
            skip_deps_check,
            features,
            url,
            default_world.clone(),
            download_from,
            local_dependencies,
            &add_paths_to_api,
            &include,
            &exclude,
            rewrite,
            force,
            verbose,
            ignore_deps,
        )
        .await?;
    }

    if rewrite {
        if package_dir.join("pkg").exists() {
            fs::remove_dir_all(package_dir.join("pkg"))?;
        }
        copy_dir(live_dir.join("pkg"), package_dir.join("pkg"))?;
    }

    let metadata = read_metadata(package_dir)?;
    let pkg_publisher = make_pkg_publisher(&metadata);
    let (_zip_filename, hash_string) = zip_pkg(package_dir, &pkg_publisher)?;
    info!("package zip hash: {hash_string}");

    Ok(())
}
