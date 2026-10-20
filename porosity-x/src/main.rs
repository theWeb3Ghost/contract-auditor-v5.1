use std::io::{self, Read};
use porosity_analyzer::analyze;

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();

    // Parse CLI args
    let mut bytecode: Option<String> = None;
    let mut address: Option<String> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--code" | "-c" => {
                if i + 1 < args.len() {
                    bytecode = Some(args[i + 1].clone());
                    i += 2;
                } else {
                    eprintln!("Error: --code requires a value");
                    std::process::exit(1);
                }
            }
            "--address" | "-a" => {
                if i + 1 < args.len() {
                    address = Some(args[i + 1].clone());
                    i += 2;
                } else {
                    eprintln!("Error: --address requires a value");
                    std::process::exit(1);
                }
            }
            "--help" | "-h" => {
                println!("Porosity-X Static Analysis Engine\n");
                println!("USAGE:");
                println!("    porosity-analyzer --code <BYTECODE> [--address <ADDR>]");
                println!("    echo <BYTECODE> | porosity-analyzer [--address <ADDR>]");
                println!("\nARGS:");
                println!("    --code <BYTECODE>     Hex-encoded runtime bytecode (with or without 0x prefix)");
                println!("    --address <ADDR>      Contract address (for reference, optional)");
                println!("\nOUTPUT:");
                println!("    JSON analysis result to stdout");
                return Ok(());
            }
            _ => {
                if args[i].starts_with("0x") || args[i].starts_with("--") {
                    if !args[i].starts_with("--") {
                        bytecode = Some(args[i].clone());
                    }
                } else {
                    // Assume it's raw bytecode
                    bytecode = Some(args[i].clone());
                }
                i += 1;
            }
        }
    }

    // Read bytecode from stdin if not provided
    if bytecode.is_none() {
        let mut input = String::new();
        io::stdin().read_to_string(&mut input)?;
        bytecode = Some(input.trim().to_string());
    }

    let bytecode = bytecode.unwrap_or_default();
    let address = address.unwrap_or_else(|| "0x0000000000000000000000000000000000000000".to_string());

    match analyze(&bytecode, &address) {
        Ok(result) => {
            println!("{}", serde_json::to_string_pretty(&result).unwrap());
            Ok(())
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            // Still output error info as JSON for machine parsing
            let error_json = serde_json::json!({
                "error": true,
                "message": e.to_string()
            });
            println!("{}", serde_json::to_string_pretty(&error_json).unwrap());
            std::process::exit(1);
        }
    }
}
