//! Security-Agent local runtime.

use security_agent::{LocalAgentAssets, run_builtin_tool};
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
        Some("--list-skills") => {
            for skill in assets.skills() {
                println!("{}", skill.name);
            }
            ExitCode::SUCCESS
        }
        Some("--show-skill") => {
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
        Some("--list-tools") => {
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
        Some("--run-tool") => {
            let Some(name) = arguments.next() else {
                eprintln!("missing tool name");
                return ExitCode::from(2);
            };
            let Some(input) = arguments.next() else {
                eprintln!("missing local input path");
                return ExitCode::from(2);
            };
            let output = match arguments.next().as_deref() {
                None => None,
                Some("--output") => {
                    let Some(path) = arguments.next() else {
                        eprintln!("missing .txt output path");
                        return ExitCode::from(2);
                    };
                    if Path::new(&path)
                        .extension()
                        .and_then(|value| value.to_str())
                        != Some("txt")
                    {
                        eprintln!("output path must use the .txt extension");
                        return ExitCode::from(2);
                    }
                    Some(path)
                }
                Some(argument) => {
                    eprintln!("unknown tool argument: {argument}");
                    return ExitCode::from(2);
                }
            };
            if let Some(argument) = arguments.next() {
                eprintln!("unexpected tool argument: {argument}");
                return ExitCode::from(2);
            }
            match run_builtin_tool(&name, Path::new(&input)) {
                Ok(report) => {
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
                Err(error) => {
                    eprintln!("{error}");
                    ExitCode::from(1)
                }
            }
        }
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
