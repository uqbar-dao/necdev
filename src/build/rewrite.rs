use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use color_eyre::{eyre::eyre, Result};
use fs_err as fs;
use regex::Regex;
use syn::{__private::ToTokens, parse_str};
use toml_edit;
use tracing::{debug, instrument};

use crate::new::snake_to_upper_camel_case;

#[derive(Debug, Default)]
struct GeneratedProcesses {
    // original process name -> (generated process name -> (wasm path, content))
    processes: HashMap<String, HashMap<String, (String, String)>>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct GeneratedProcessesExternal {
    // original process name -> (generated process name -> wasm path)
    processes: HashMap<String, HashMap<String, String>>,
}

impl From<GeneratedProcesses> for GeneratedProcessesExternal {
    fn from(input: GeneratedProcesses) -> Self {
        let processes = input
            .processes
            .iter()
            .map(|(parent_name, child_to_content)| {
                (
                    parent_name.to_string(),
                    child_to_content
                        .iter()
                        .map(|(child_name, (path, _content))| {
                            (child_name.to_string(), path.to_string())
                        })
                        .collect(),
                )
            })
            .collect();
        GeneratedProcessesExternal { processes }
    }
}

#[derive(Debug, Clone)]
struct ArgInfo {
    name: String,
    ty: String,
}

#[derive(Debug, Clone)]
struct ReturnInfo {
    ty: String,
}

#[derive(Debug, Clone)]
struct FnSignature {
    args: Vec<ArgInfo>,
    ret: Option<ReturnInfo>,
}

#[derive(Debug)]
struct FnInfo {
    name: String,
    signature: FnSignature,
    body: String,
    dependencies: HashSet<String>,
}

#[derive(Debug)]
enum SpawnType {
    Closure { args: String, body: String },
    FnCall { name: String, args: Vec<String> },
}

#[derive(Debug)]
struct SpawnMatch {
    spawn_type: SpawnType,
    imports: Vec<String>,
    start_pos: usize,
    end_pos: usize,
}

#[derive(Debug, thiserror::Error)]
enum SpawnParseError {
    #[error("Parse failed due to malformed imports")]
    Imports,
    #[error("Spawn parse failed due to malformed closure: no closing pipe in closure")]
    NoClosingPipe,
    #[error("Spawn parse failed due to malformed closure: no opening brace `{{`")]
    NoOpeningBrace,
    #[error("Spawn parse failed due to malformed closure: no opening paren `(`")]
    NoOpeningParen,
    #[error("Spawn parse failed due to malformed closure: no opening bracket `[`")]
    UnclosedBrace,
    #[error("Spawn parse failed due to malformed closure: unclosed paren `(`")]
    UnclosedParen,
    #[error("Spawn parse failed due to malformed closure: unclosed bracket` `[`")]
    UnclosedBracket,
    #[error("Spawn parse failed: malformed function call")]
    MalformedFunctionCall,
    #[error("Spawn parse failed: no opening paren for arguments")]
    UnclosedArgsParen,
    #[error("Spawn parse failed: unclosed spawn paren")]
    UnclosedSpawnParen,
    #[error("Spawn parse failed: must start with `Spawn!(`")]
    InvalidSpawnSyntax,
}

// TODO: factor out with build::mod.rs::copy_dir()
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
            if src_path.file_name().and_then(|n| n.to_str()) == Some("target") {
                continue;
            }
            copy_dir(&src_path, &dst_path)?;
        } else {
            fs::copy(&src_path, &dst_path)?;
        }
    }
    Ok(())
}

fn make_args_struct_name(worker_name: &str) -> String {
    format!(
        "{}Args",
        snake_to_upper_camel_case(&worker_name.replace("-", "_"))
    )
}

#[instrument(level = "trace", skip_all)]
fn parse_fn_signature(args: &str) -> Result<FnSignature> {
    // Parse the argument string as Rust function parameters
    let fn_item: syn::ItemFn = parse_str(&format!("fn dummy({args}) {{}}"))?;

    // Extract the parameters from the function signature
    let args = fn_item
        .sig
        .inputs
        .into_iter()
        .filter_map(|param| {
            if let syn::FnArg::Typed(pat_type) = param {
                Some(ArgInfo {
                    name: pat_type.pat.into_token_stream().to_string(),
                    ty: pat_type.ty.into_token_stream().to_string(),
                })
            } else {
                None
            }
        })
        .collect();

    // Extract return type if present
    let ret = match fn_item.sig.output {
        syn::ReturnType::Default => None,
        syn::ReturnType::Type(_, ty) => Some(ReturnInfo {
            ty: ty.into_token_stream().to_string(),
        }),
    };

    Ok(FnSignature { args, ret })
}

fn generate_args_struct_type(struct_name: &str, args: &[ArgInfo]) -> String {
    let fields = args
        .iter()
        .map(|arg| format!("    {}: {},", arg.name, arg.ty))
        .collect::<Vec<_>>()
        .join("\n");

    format!(
        r#"#[derive(serde::Serialize, serde::Deserialize)]
struct {struct_name} {{
{fields}
}}"#
    )
}

fn generate_args_struct_instance(struct_name: &str, args: &[ArgInfo]) -> String {
    let fields = args
        .iter()
        .map(|arg| format!("            {0}: {0}.clone(),", arg.name))
        .collect::<Vec<_>>()
        .join("\n");

    format!(
        r#"let args = {struct_name} {{
{fields}
        }};"#
    )
}

fn generate_args_struct_destructure(struct_name: &str, args: &[ArgInfo]) -> String {
    let fields = args
        .iter()
        .map(|arg| arg.name.clone())
        .collect::<Vec<_>>()
        .join(", ");

    format!(r#"let {struct_name} {{ {fields} }}"#)
}

fn extract_imports(content: &str) -> Result<Vec<String>, SpawnParseError> {
    let imports_re = Regex::new(r"use\s+([^;]+);").map_err(|_| SpawnParseError::Imports)?;
    Ok(imports_re
        .captures_iter(content)
        .map(|cap| cap[1].trim().to_string())
        .collect())
}

fn extract_wit_bindgen(content: &str) -> Option<String> {
    // Look for wit_bindgen::generate! macro
    if let Some(start) = content.find("wit_bindgen::generate!") {
        let mut brace_count = 0;
        let mut in_macro = false;
        let mut saw_closing_brace = false;
        let mut saw_closing_paren = false;
        let mut macro_end = start;

        // Find the closing part of the macro by counting braces
        for (i, c) in content[start..].chars().enumerate() {
            match c {
                '{' => {
                    brace_count += 1;
                    in_macro = true;
                }
                '}' => {
                    brace_count -= 1;
                    if in_macro && brace_count == 0 {
                        saw_closing_brace = true;
                    }
                }
                ')' => {
                    if in_macro && saw_closing_brace && brace_count == 0 {
                        saw_closing_paren = true;
                    }
                }
                ';' => {
                    if in_macro && saw_closing_brace && saw_closing_paren && brace_count == 0 {
                        macro_end = start + i + 1;
                        break;
                    }
                }
                _ => {}
            }
        }

        Some(content[start..macro_end].to_string())
    } else {
        None
    }
}

#[instrument(level = "trace", skip_all)]
fn extract_functions(content: &str) -> Result<HashMap<String, FnInfo>> {
    let syntax_tree = syn::parse_file(content)?;
    let mut functions = HashMap::new();

    for item in syntax_tree.items {
        if let syn::Item::Fn(func) = item {
            let name = func.sig.ident.to_string();
            // Extract both args and return type
            let signature = FnSignature {
                args: func
                    .sig
                    .inputs
                    .iter()
                    .filter_map(|arg| {
                        if let syn::FnArg::Typed(pat_type) = arg {
                            Some(ArgInfo {
                                name: pat_type.pat.to_token_stream().to_string(),
                                ty: pat_type.ty.to_token_stream().to_string(),
                            })
                        } else {
                            None
                        }
                    })
                    .collect(),
                ret: match &func.sig.output {
                    syn::ReturnType::Default => None,
                    syn::ReturnType::Type(_, ty) => Some(ReturnInfo {
                        ty: ty.into_token_stream().to_string(),
                    }),
                },
            };

            let mut deps = HashSet::new();
            find_fn_calls(&func.block, &mut deps);

            functions.insert(
                name.clone(),
                FnInfo {
                    name,
                    signature,
                    body: func.block.to_token_stream().to_string(),
                    dependencies: deps,
                },
            );
        }
    }

    Ok(functions)
}

fn find_fn_calls(block: &syn::Block, deps: &mut HashSet<String>) {
    fn inspect_expr(expr: &syn::Expr, deps: &mut HashSet<String>) {
        match expr {
            syn::Expr::Call(call) => {
                // Check direct function call
                if let syn::Expr::Path(path) = &*call.func {
                    if let Some(ident) = path.path.get_ident() {
                        deps.insert(ident.to_string());
                    }
                }
                // Check arguments recursively
                for arg in &call.args {
                    inspect_expr(arg, deps);
                }
            }
            syn::Expr::Macro(mac) => {
                // Convert tokens to string and look for function calls
                let tokens = mac.mac.tokens.clone();
                let tokens_str = tokens.to_string();

                // Split on comma and look at each part
                for part in tokens_str.split(',') {
                    // Look for function call pattern: function_name(args)
                    if let Some(func_name) = part.trim().split('(').next() {
                        // Ignore format specifiers and other non-function tokens
                        if !func_name.contains('"') && !func_name.is_empty() {
                            deps.insert(func_name.trim().to_string());
                        }
                    }
                }

                // Still try to parse as expression for other cases
                if let Ok(expr) = syn::parse2::<syn::Expr>(tokens) {
                    inspect_expr(&expr, deps);
                }
            }
            syn::Expr::Block(block_expr) => {
                for stmt in &block_expr.block.stmts {
                    inspect_stmt(stmt, deps);
                }
            }
            _ => {}
        }
    }

    fn inspect_stmt(stmt: &syn::Stmt, deps: &mut HashSet<String>) {
        match stmt {
            syn::Stmt::Expr(expr, _) => inspect_expr(expr, deps),
            syn::Stmt::Local(local) => {
                if let Some(init) = &local.init {
                    inspect_expr(&init.expr, deps);
                }
            }
            syn::Stmt::Macro(mac_stmt) => {
                if let Ok(expr) = syn::parse2::<syn::Expr>(mac_stmt.mac.tokens.clone()) {
                    inspect_expr(&expr, deps);
                } else {
                    // Handle tokens directly for macro statements too
                    let tokens_str = mac_stmt.mac.tokens.to_string();
                    for part in tokens_str.split(',') {
                        if let Some(func_name) = part.trim().split('(').next() {
                            if !func_name.contains('"') && !func_name.is_empty() {
                                deps.insert(func_name.trim().to_string());
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }

    for stmt in &block.stmts {
        inspect_stmt(stmt, deps);
    }
}

fn parse_spawn_closure(input: &str) -> Result<(String, String, usize), SpawnParseError> {
    // Skip the "Spawn!(|" prefix since we know it's there
    let input_after_spawn = &input["Spawn!(|".len()..];

    // Find the closing "|"
    let pipe_end = input_after_spawn
        .find('|')
        .ok_or(SpawnParseError::NoClosingPipe)?;

    // Find the opening "{"
    let brace_start = input_after_spawn[pipe_end..]
        .find('{')
        .ok_or(SpawnParseError::NoOpeningBrace)?
        .saturating_add(pipe_end);

    // Find the closing "}" while handling nested braces
    let mut brace_count = 1;
    let mut brace_end = None;
    let mut paren_end = None;

    for (i, c) in input_after_spawn[brace_start + 1..].chars().enumerate() {
        match c {
            '{' => brace_count += 1,
            '}' => {
                brace_count -= 1;
                if brace_count == 0 {
                    brace_end = Some(brace_start + 1 + i);
                }
            }
            ')' => {
                if brace_count == 0 && brace_end.is_some() {
                    paren_end = Some(brace_start + 1 + i);
                    break;
                }
            }
            _ => {}
        }
    }

    let brace_end = brace_end.ok_or(SpawnParseError::UnclosedBrace)?;
    let paren_end = paren_end.ok_or(SpawnParseError::UnclosedParen)?;

    let args = input_after_spawn[..pipe_end].trim().to_string();
    let body = input_after_spawn[brace_start + 1..brace_end]
        .trim()
        .to_string();

    // Return the total length consumed so we know where to continue searching
    let total_consumed = "Spawn!(|".len() + paren_end + 1;

    Ok((args, body, total_consumed))
}

fn parse_spawn_fn_call(input: &str) -> Result<(String, Vec<String>, usize), SpawnParseError> {
    // Skip the "Spawn!(" prefix
    let input_after_spawn = &input["Spawn!(".len()..];

    // Find the function name (everything up to first '(' or whitespace)
    let name_end = input_after_spawn
        .find(|c: char| c == '(' || c.is_whitespace())
        .ok_or(SpawnParseError::MalformedFunctionCall)?;
    let name = input_after_spawn[..name_end].trim().to_string();

    // Find opening paren of args
    let args_start = input_after_spawn[name_end..]
        .find('(')
        .ok_or(SpawnParseError::NoOpeningParen)?
        .saturating_add(name_end);

    // Find closing paren while handling nested parens
    let mut paren_count = 1;
    let mut args_end = None;
    let mut closing_spawn_paren = None;

    for (i, c) in input_after_spawn[args_start + 1..].chars().enumerate() {
        match c {
            '(' => paren_count += 1,
            ')' => {
                paren_count -= 1;
                if paren_count == 0 {
                    args_end = Some(args_start + 1 + i);
                } else if paren_count == -1 {
                    // This is the closing paren of Spawn!(...)
                    closing_spawn_paren = Some(args_start + 1 + i);
                    break;
                }
            }
            _ => {}
        }
    }

    let args_end = args_end.ok_or(SpawnParseError::UnclosedArgsParen)?;
    let closing_spawn_paren = closing_spawn_paren.ok_or(SpawnParseError::UnclosedSpawnParen)?;

    // Parse args list by splitting on commas, handling nested stuff
    let args_str = input_after_spawn[args_start + 1..args_end].trim();
    let args = split_args(args_str)?;

    // Return total consumed length including both closing parens
    let total_consumed = "Spawn!(".len() + closing_spawn_paren + 1;

    Ok((name, args, total_consumed))
}

fn split_args(args: &str) -> Result<Vec<String>, SpawnParseError> {
    let mut result = Vec::new();
    let mut current = String::new();
    let mut paren_count = 0;
    let mut brace_count = 0;
    let mut bracket_count = 0;

    for c in args.chars() {
        match c {
            '(' => paren_count += 1,
            ')' => paren_count -= 1,
            '{' => brace_count += 1,
            '}' => brace_count -= 1,
            '[' => bracket_count += 1,
            ']' => bracket_count -= 1,
            ',' if paren_count == 0 && brace_count == 0 && bracket_count == 0 => {
                result.push(current.trim().to_string());
                current = String::new();
                continue;
            }
            _ => {}
        }
        current.push(c);
    }

    if !current.is_empty() {
        result.push(current.trim().to_string());
    }

    if paren_count != 0 {
        return Err(SpawnParseError::UnclosedParen);
    }
    if brace_count != 0 {
        return Err(SpawnParseError::UnclosedBrace);
    }
    if bracket_count != 0 {
        return Err(SpawnParseError::UnclosedBracket);
    }

    Ok(result)
}

fn parse_spawn_from(input: &str) -> Result<(SpawnType, usize), SpawnParseError> {
    if input.starts_with("Spawn!(|") {
        // Existing closure parsing logic
        let (args, body, consumed) = parse_spawn_closure(&input)?;
        Ok((SpawnType::Closure { args, body }, consumed))
    } else if input.starts_with("Spawn!(") {
        // Function call parsing logic
        debug!("parsing non-closure `Spawn!(`");
        let (name, args, consumed) = parse_spawn_fn_call(&input)?;
        Ok((SpawnType::FnCall { name, args }, consumed))
    } else {
        Err(SpawnParseError::InvalidSpawnSyntax)
    }
}

fn add_function_and_deps(
    name: &str,
    functions: &HashMap<String, FnInfo>,
    needed: &mut HashSet<String>,
) {
    needed.insert(name.to_string());
    if let Some(info) = functions.get(name) {
        for dep in &info.dependencies {
            add_function_and_deps(dep, functions, needed);
        }
    }
}

#[instrument(level = "trace", skip_all)]
fn generate_worker_process(
    process_name: &str,
    spawn_match: &SpawnMatch,
    functions: &HashMap<String, FnInfo>,
    imports: &[String],
    wit_bindgen: &str,
    args_type: &str,
    args_destructure: &str,
) -> Result<String> {
    let mut needed_fns = HashSet::new();

    //// Get return type if it's a function call
    //let return_type = match &spawn_match.spawn_type {
    //    SpawnType::FnCall { name, .. } => {
    //        if let Some(fn_info) = functions.get(name) {
    //            fn_info.signature.ret.clone()
    //        } else {
    //            None
    //        }
    //    }
    //    SpawnType::Closure { .. } => None, // Closures don't have return types in our context
    //};

    // Get list of functions we need to copy
    match &spawn_match.spawn_type {
        SpawnType::Closure { body, .. } => {
            // Parse body to find function calls
            // Add braces back before parsing
            let block_str = format!("{{{body}}}");
            let syntax_tree = syn::parse_str::<syn::Block>(&block_str)?;
            // First find direct function calls in the closure
            find_fn_calls(&syntax_tree, &mut needed_fns);
            debug!("generate_worker_process find_fn_calls needed_fns {needed_fns:?}");
            debug!("{:?}", functions.keys().collect::<Vec<_>>());
            // Then recursively add dependencies for each function found
            let direct_deps = needed_fns.clone(); // Clone before recursive traversal
            debug!("{direct_deps:?}");
            for name in direct_deps {
                add_function_and_deps(&name, functions, &mut needed_fns);
            }
        }
        SpawnType::FnCall { name, .. } => {
            // Add the called function and its dependencies
            debug!("fncall {name}");
            debug!("{:?}", functions.keys().collect::<Vec<_>>());
            add_function_and_deps(name, functions, &mut needed_fns);
        }
    }
    debug!("generate_worker_process found deps: {needed_fns:?}");

    let imports = imports
        .iter()
        .map(|i| format!("#[allow(unused_imports)]\nuse {i};\n"))
        .collect::<String>();

    // Generate function definitions preserving return types
    let function_definitions = needed_fns
        .iter()
        .filter_map(|name| functions.get(name))
        .map(|info| {
            let ret_type = info
                .signature
                .ret
                .as_ref()
                .map_or("".to_string(), |r| format!(" -> {}", r.ty));
            format!(
                "fn {}({}){}{}",
                info.name,
                info.signature
                    .args
                    .iter()
                    .map(|arg| format!("{}: {}", arg.name, arg.ty))
                    .collect::<Vec<_>>()
                    .join(", "),
                ret_type,
                info.body,
            )
        })
        .collect::<String>();

    debug!("{function_definitions}");

    let body = match &spawn_match.spawn_type {
        SpawnType::Closure { body, .. } => format!("{body};"),
        SpawnType::FnCall { name, args } => {
            format!("{name}({});", args.join(", "))
        }
    };

    let template = format!(
        r#"// Generated worker process for {process_name}
{imports}

{wit_bindgen}

{args_type}

{function_definitions}

call_init!(init);
fn init(our: Address) {{
    // Get args from parent
    let message = await_message().expect("Failed to get args from parent");
    {args_destructure} = serde_json::from_slice(&message.body()).unwrap();

    // Execute `Spawn!()` function body
    {body}
}}
"#,
    );

    Ok(template)
}

fn find_all_spawns(input: &str) -> Result<Vec<SpawnMatch>, SpawnParseError> {
    let mut results = Vec::new();
    let mut search_from = 0;
    let imports = extract_imports(input)?;

    while let Some(spawn_start) = input[search_from..].find("Spawn!(") {
        let absolute_start = search_from + spawn_start;

        let (spawn_type, consumed_len) = parse_spawn_from(&input[absolute_start..])?;

        results.push(SpawnMatch {
            spawn_type,
            imports: imports.clone(),
            start_pos: absolute_start,
            end_pos: absolute_start + consumed_len,
        });

        search_from = absolute_start + consumed_len;
    }

    Ok(results)
}

/// Rewrites the parent and stores information
/// for writing children in GeneratedProcess.
#[instrument(level = "trace", skip_all)]
fn rewrite_rust_file(
    process_name: &str,
    content: &str,
    generated: &mut GeneratedProcesses,
) -> Result<String> {
    let spawn_matches = find_all_spawns(content)?;
    let mut new_content = content.to_string();
    let functions = extract_functions(&content)?;
    debug!("got functions in {process_name}: {:#?}", functions);

    // Process spawns in reverse order to not invalidate positions
    for (i, spawn_match) in spawn_matches.iter().enumerate().rev() {
        let worker_name = format!("{process_name}-worker-{i}");
        let wasm_name = format!("{worker_name}.wasm");

        let (args_name, parsed_signature) = match &spawn_match.spawn_type {
            SpawnType::Closure { args, .. } => {
                let args_name = make_args_struct_name(&worker_name);
                let parsed_signature = parse_fn_signature(args)?;
                (args_name, parsed_signature)
            }
            SpawnType::FnCall { name, args: _ } => {
                let fn_info = functions
                    .get(name)
                    .ok_or_else(|| eyre!("Function {name} not found in parent"))?;
                // For function calls, use the function's argument names but
                // with the values supplied in the Spawn!() call
                let args_name = make_args_struct_name(&worker_name);
                (args_name, fn_info.signature.clone())
            }
        };

        let args_type = generate_args_struct_type(&args_name, &parsed_signature.args);
        let args_destructure = generate_args_struct_destructure(&args_name, &parsed_signature.args);

        // Generate worker process
        let wit_bindgen = extract_wit_bindgen(content).unwrap_or_else(|| {
            r#"wit_bindgen::generate!({
    path: "target/wit",
    world: "process-v0",
})"#
            .to_string()
        });

        let worker_code = generate_worker_process(
            process_name,
            spawn_match,
            &functions,
            &spawn_match.imports,
            &wit_bindgen,
            &args_type,
            &args_destructure,
        )?;

        // Track in generated processes
        generated
            .processes
            .entry(process_name.to_string())
            .or_default()
            .insert(worker_name.clone(), (wasm_name, worker_code));

        // Create replacement spawn code with appropriate args instantiation
        let args_instance = match &spawn_match.spawn_type {
            SpawnType::Closure { .. } => {
                // For closures, use the argument names directly
                generate_args_struct_instance(&args_name, &parsed_signature.args)
            }
            SpawnType::FnCall { args, .. } => {
                // For function calls, use the supplied argument values
                let fields = parsed_signature
                    .args
                    .iter()
                    .zip(args.iter())
                    .map(|(arg, value)| format!("            {}: {},", arg.name, value))
                    .collect::<Vec<_>>()
                    .join("\n");

                format!(
                    r#"let args = {args_name} {{
{fields}
            }};"#
                )
            }
        };

        // Create the replacement code
        let replacement = format!(
            r#"{{
        use hyperware_process_lib::{{spawn, OnExit, Request}};
        {args_type}

        {args_instance}

        let worker = spawn(
            None,
            &format!("{{}}:{{}}/pkg/{worker_name}.wasm", our.process.package_name, our.process.publisher_node),
            OnExit::None,
            vec![],
            vec![],
            false,
        ).expect("failed to spawn worker");
        Request::to((our.node(), worker))
            .body(serde_json::to_vec(&args).unwrap())
            .send()
            .expect("failed to initialize worker");
    }}"#,
        );

        // Replace in the content using positions
        new_content.replace_range(spawn_match.start_pos..spawn_match.end_pos, &replacement);
    }

    Ok(new_content)
}

/// For each process in package, rewrite rust files parents
/// and store information for writing children in GeneratedProcess.
#[instrument(level = "trace", skip_all)]
fn process_package(package_dir: &Path, generated: &mut GeneratedProcesses) -> Result<()> {
    if !package_dir.is_dir() {
        return Ok(());
    }

    for entry in fs::read_dir(package_dir)? {
        let entry = entry?;
        let path = entry.path();

        if path.is_dir() {
            if path.file_name().and_then(|n| n.to_str()) == Some("target") {
                continue;
            }
            process_package(&path, generated)?;
        } else if path.extension().and_then(|s| s.to_str()) == Some("rs") {
            let process_name = path
                .parent()
                .and_then(|p| p.parent())
                .and_then(|n| n.file_name())
                .and_then(|n| n.to_str())
                .ok_or_else(|| eyre!("Invalid process name"))?
                .to_string();

            let content = fs::read_to_string(&path)?;
            let new_content = rewrite_rust_file(&process_name, &content, generated)?;
            fs::write(&path, new_content)?;
            crate::build::run_command(std::process::Command::new("rustfmt").arg(&path), false)?;
        }
    }
    Ok(())
}

#[instrument(level = "trace", skip_all)]
fn create_child_processes(package_dir: &Path, generated: &GeneratedProcesses) -> Result<()> {
    for (process_name, workers) in &generated.processes {
        for (worker_name, (_, content)) in workers {
            let parent_dir = package_dir.join(process_name);
            let worker_dir = package_dir.join(worker_name);

            // Copy the source directory structure from parent
            let parent_src = parent_dir.join("src");
            let worker_src = worker_dir.join("src");
            debug!("{} {}", parent_src.display(), worker_src.display());
            copy_dir(&parent_src, &worker_src)?;

            // Overwrite lib.rs with our generated content
            let worker_lib = worker_src.join("lib.rs");
            fs::write(&worker_lib, content)?;
            crate::build::run_command(
                std::process::Command::new("rustfmt").arg(&worker_lib),
                false,
            )?;

            // Copy and modify Cargo.toml
            let parent_cargo = fs::read_to_string(parent_dir.join("Cargo.toml"))?;
            let mut doc = parent_cargo.parse::<toml_edit::DocumentMut>()?;

            // Update package name to worker name
            if let Some(package) = doc.get_mut("package") {
                if let Some(name) = package.get_mut("name") {
                    *name = toml_edit::value(worker_name.as_str());
                }
            }

            fs::write(worker_dir.join("Cargo.toml"), doc.to_string())?;
        }
    }
    Ok(())
}

#[instrument(level = "trace", skip_all)]
fn update_workspace_cargo_toml(package_dir: &Path, generated: &GeneratedProcesses) -> Result<()> {
    let cargo_toml_path = package_dir.join("Cargo.toml");
    let cargo_toml = fs::read_to_string(&cargo_toml_path)?;

    // Parse existing TOML
    let mut doc = cargo_toml.parse::<toml_edit::DocumentMut>()?;

    // Get or create workspace section
    let workspace = doc.entry("workspace").or_insert(toml_edit::table());

    // Get or create members array
    let members = workspace
        .as_table_mut()
        .ok_or_else(|| eyre!("workspace is not a table"))?
        .entry("members")
        .or_insert(toml_edit::array());

    let members_array = members
        .as_array_mut()
        .ok_or_else(|| eyre!("members is not an array"))?;

    // Add all worker packages
    for workers in generated.processes.values() {
        for worker_name in workers.keys() {
            members_array.push(worker_name);
        }
    }

    // Write back to file
    fs::write(cargo_toml_path, doc.to_string())?;

    Ok(())
}

#[instrument(level = "trace", skip_all)]
pub fn copy_and_rewrite_package(package_dir: &Path) -> Result<PathBuf> {
    debug!("Rewriting for {}...", package_dir.display());
    let rewrite_dir = package_dir.join("target").join("rewrite");
    if rewrite_dir.exists() {
        fs::remove_dir_all(&rewrite_dir)?;
    }
    fs::create_dir_all(&rewrite_dir)?;

    copy_dir(package_dir, &rewrite_dir)?;

    let mut generated = GeneratedProcesses::default();

    // Rewrite parents & gather info for writing children
    process_package(&rewrite_dir, &mut generated)?;

    // Create child processes
    create_child_processes(&rewrite_dir, &generated)?;

    // Update workspace Cargo.toml
    update_workspace_cargo_toml(&rewrite_dir, &generated)?;

    Ok(rewrite_dir)
}
