//! Security-Agent local runtime.

use security_agent::{LocalAgentAssets, run_builtin_tool, run_external_tool_with_default_timeout};
use std::fs;
use std::path::Path;
use std::process::ExitCode;

fn main() -> ExitCode {
    let assets = LocalAgentAssets::bundled();
    let mut arguments = std::env::args().skip(1);

    match arguments.next().as_deref() {
        None | Some("--offline-status") => {
            print_offline_status(&assets);
            ExitCode::SUCCESS
        }
        Some("--list-skills") => list_skills(&assets),
        Some("--show-skill") => show_skill(&assets, &mut arguments),
        Some("--list-tools") => list_tools(&assets),
        Some("--run-tool") => run_tool_command(&mut arguments),
        Some("--run-external-tool") => run_external_tool_command(&assets, &mut arguments),
        Some(command) => {
            eprintln!("unknown command: {command}");
            ExitCode::from(2)
        }
    }
}

fn print_offline_status(assets: &LocalAgentAssets) {
    let executable_tools = assets
        .tools()
        .iter()
        .filter(|tool| tool.is_installed())
        .count();
    let built_in_tools = assets.tools().iter().filter(|tool| tool.built_in).count();

    println!("network_required=false");
    println!("external_api_required=false");
    println!("embedded_skills={}", assets.skills().len());
    println!("cataloged_tool_definitions={}", assets.tools().len());
    println!("built_in_substitute_tools={built_in_tools}");
    println!("locally_executable_tools={executable_tools}");
}

fn list_skills(assets: &LocalAgentAssets) -> ExitCode {
    for skill in assets.skills() {
        println!("{}", skill.name);
    }
    ExitCode::SUCCESS
}

fn show_skill(assets: &LocalAgentAssets, arguments: &mut impl Iterator<Item = String>) -> ExitCode {
    let Some(name) = arguments.next() else {
        eprintln!("missing skill name");
        return ExitCode::from(2);
    };
    let Some(skill) = assets.skill(&name) else {
        eprintln!("unknown local skill: {name}");
        return ExitCode::from(2);
    };
    print!("{}", skill.content);
    ExitCode::SUCCESS
}

fn list_tools(assets: &LocalAgentAssets) -> ExitCode {
    for tool in assets.tools() {
        if tool.built_in {
            println!("{}\tbuilt-in-substitute", tool.definition.name);
        } else if let Some(path) = &tool.executable {
            println!(
                "{}\tcataloged\texecutable={}",
                tool.definition.name,
                path.display()
            );
        } else {
            println!(
                "{}\tcataloged\texecutable=not-installed",
                tool.definition.name
            );
        }
    }
    ExitCode::SUCCESS
}

/// Parses an optional trailing `--output <path>.txt` argument pair.
/// Returns `Ok(None)` if no more arguments remain, `Ok(Some(path))` if a
/// valid `.txt` output path was given, or `Err(exit_code)` describing why
/// parsing failed.
fn parse_output_argument(
    arguments: &mut impl Iterator<Item = String>,
) -> Result<Option<String>, ExitCode> {
    match arguments.next().as_deref() {
        None => Ok(None),
        Some("--output") => {
            let Some(path) = arguments.next() else {
                eprintln!("missing .txt output path");
                return Err(ExitCode::from(2));
            };
            if Path::new(&path)
                .extension()
                .and_then(|value| value.to_str())
                != Some("txt")
            {
                eprintln!("output path must use the .txt extension");
                return Err(ExitCode::from(2));
            }
            Ok(Some(path))
        }
        Some(argument) => {
            eprintln!("unknown tool argument: {argument}");
            Err(ExitCode::from(2))
        }
    }
}

fn run_tool_command(arguments: &mut impl Iterator<Item = String>) -> ExitCode {
    let Some(name) = arguments.next() else {
        eprintln!("missing tool name");
        return ExitCode::from(2);
    };
    let Some(input) = arguments.next() else {
        eprintln!("missing local input path");
        return ExitCode::from(2);
    };
    let output = match parse_output_argument(arguments) {
        Ok(output) => output,
        Err(code) => return code,
    };
    if let Some(argument) = arguments.next() {
        eprintln!("unexpected tool argument: {argument}");
        return ExitCode::from(2);
    }
    match run_builtin_tool(&name, Path::new(&input)) {
        Ok(report) => write_or_print_report(&name, report, output),
        Err(error) => {
            eprintln!("{error}");
            ExitCode::from(1)
        }
    }
}

/// Runs a real, cataloged (non-substitute) tool directly, e.g.
/// `--run-external-tool semgrep --version`. Only tools classified for
/// static local analysis (see `security_agent::registry::ExecutionClass`)
/// are wired up for direct execution; everything else is rejected with an
/// explanatory error.
fn run_external_tool_command(
    assets: &LocalAgentAssets,
    arguments: &mut impl Iterator<Item = String>,
) -> ExitCode {
    let Some(name) = arguments.next() else {
        eprintln!("missing tool name");
        return ExitCode::from(2);
    };
    let Some(tool) = assets.tool(&name) else {
        eprintln!("unknown cataloged tool: {name}");
        return ExitCode::from(2);
    };
    let tool_arguments: Vec<String> = arguments.collect();

    match run_external_tool_with_default_timeout(tool, &tool_arguments) {
        Ok(report) => {
            print!("{report}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{error}");
            ExitCode::from(1)
        }
    }
}

fn write_or_print_report(name: &str, report: String, output: Option<String>) -> ExitCode {
    if let Some(path) = output {
        match fs::write(&path, report) {
            Ok(()) => {
                println!("{name} report written to {path}");
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("failed to write {path}: {error}");
                ExitCode::from(1)
            }
        }
    } else {
        print!("{report}");
        ExitCode::SUCCESS
    }
}
