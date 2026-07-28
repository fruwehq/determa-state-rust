//! Minimal host utility. No CLI profile is currently portable format-1 conformance.

use crate::load_bundle;
use std::fs;

pub fn run(args: Vec<String>) -> i32 {
    let mut arguments = args.into_iter().skip(1);
    match arguments.next().as_deref() {
        Some("--version") => {
            println!("determa-state 0.0.6");
            0
        }
        Some("validate") => {
            let Some(path) = arguments.next() else {
                eprintln!("usage: determa-state validate <bundle.yaml>");
                return 2;
            };
            let source = match fs::read_to_string(&path) {
                Ok(source) => source,
                Err(error) => {
                    eprintln!("{path}: {error}");
                    return 2;
                }
            };
            match load_bundle(&source) {
                Ok(_) => {
                    println!("valid");
                    0
                }
                Err(error) => {
                    eprintln!("{error}");
                    3
                }
            }
        }
        Some("--help") | Some("-h") | None => {
            println!(
                "determa-state 0.0.6\n\nusage:\n  determa-state validate <bundle.yaml>\n  determa-state --version"
            );
            0
        }
        Some(command) => {
            eprintln!("unknown command: {command}");
            2
        }
    }
}
