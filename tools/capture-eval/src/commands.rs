//! Report utilities do not execute a sensor or open a capture.
use std::ffi::OsString;
use std::path::Path;
use tracehound_eval::store::{compare, load_report, ReportStore};

pub fn run(args: &[OsString]) -> Option<Result<i32, String>> {
    let command = args.first()?.to_str()?;
    if !matches!(command, "history" | "open" | "compare" | "feed-update") {
        return None;
    }
    Some((|| {
        match command {
            "history" => {
                let store = match &args[1..] {
                    [] => ReportStore::default_location(),
                    [flag, directory] if flag == "--history-dir" => {
                        ReportStore::new(directory.into())
                    }
                    _ => {
                        return Err(
                            "usage: tracehound-eval history [--history-dir DIRECTORY]".into()
                        )
                    }
                };
                println!(
                    "{}",
                    serde_json::to_string_pretty(&store.list()?).map_err(|e| e.to_string())?
                );
            }
            "open" if args.len() == 2 => println!(
                "{}",
                serde_json::to_string_pretty(&load_report(Path::new(&args[1]))?)
                    .map_err(|e| e.to_string())?
            ),
            "compare" if args.len() == 3 => {
                let before = load_report(Path::new(&args[1]))?;
                let after = load_report(Path::new(&args[2]))?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&compare(&before, &after))
                        .map_err(|e| e.to_string())?
                );
            }
            "feed-update" if args.len() == 2 => {
                let feed = tracehound_eval::feed::update_public_mapping(Path::new(&args[1]))?;
                println!(
                    "Saved {} source-attributed TLS pairs to {}",
                    feed.entries.len(),
                    super::safe(&args[1].to_string_lossy())
                );
            }
            _ => {
                return Err(format!(
                    "invalid arguments for {command}; use --help for usage"
                ))
            }
        }
        Ok(0)
    })())
}
