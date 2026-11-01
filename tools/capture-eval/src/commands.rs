//! Report utilities do not execute a sensor or open a capture.
use std::ffi::OsString;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tracehound_eval::store::{compare, load_report, ReportStore};

fn open_case(
    path: &Path,
    interrupted: &Arc<AtomicBool>,
) -> Result<tracehound_eval::investigation::CaseIndex, String> {
    let mut case = tracehound_eval::investigation::CaseIndex::open(path)?;
    let flag = Arc::clone(interrupted);
    case.interrupt_when(move || flag.load(Ordering::Acquire))?;
    Ok(case)
}

pub fn run(args: &[OsString], interrupted: &Arc<AtomicBool>) -> Option<Result<i32, String>> {
    let command = args.first()?.to_str()?;
    if !matches!(
        command,
        "history"
            | "open"
            | "compare"
            | "feed-update"
            | "case"
            | "timeline"
            | "case-export"
            | "behavior-compare"
            | "packet-export"
    ) {
        return None;
    }
    Some((|| {
        match command {
            "case" if args.len() >= 2 => {
                let mut offset = 0;
                let mut limit = 1000;
                let mut query = String::new();
                let (pairs, remaining) = args[2..].as_chunks::<2>();
                for pair in pairs {
                    match pair[0].to_str() {
                        Some("--offset") => {
                            offset = pair[1]
                                .to_str()
                                .ok_or("offset must be an integer")?
                                .parse()
                                .map_err(|_| "invalid offset")?
                        }
                        Some("--limit") => {
                            limit = pair[1]
                                .to_str()
                                .ok_or("limit must be an integer")?
                                .parse()
                                .map_err(|_| "invalid limit")?
                        }
                        Some("--search") => {
                            query = pair[1].to_str().ok_or("search must be text")?.to_owned()
                        }
                        _ => {
                            return Err(
                                "case accepts --offset N, --limit N, and --search TEXT".into()
                            )
                        }
                    }
                }
                if !remaining.is_empty() {
                    return Err("missing case option value".into());
                }
                let case = open_case(Path::new(&args[1]), interrupted)?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(
                        &serde_json::json!({"overview":case.overview(),"hosts":case.search_hosts(&query,offset,limit)?,"offset":offset,"limit":limit.min(1000)})
                    )
                    .map_err(|e| e.to_string())?
                );
            }
            "timeline" if args.len() >= 3 => {
                let mut after = 0;
                let mut limit = 1000;
                let (pairs, remaining) = args[3..].as_chunks::<2>();
                for pair in pairs {
                    match pair[0].to_str() {
                        Some("--after") => {
                            after = pair[1]
                                .to_str()
                                .ok_or("cursor must be an integer")?
                                .parse()
                                .map_err(|_| "invalid cursor")?
                        }
                        Some("--limit") => {
                            limit = pair[1]
                                .to_str()
                                .ok_or("limit must be an integer")?
                                .parse()
                                .map_err(|_| "invalid limit")?
                        }
                        _ => return Err("timeline accepts --after ID and --limit N".into()),
                    }
                }
                if !remaining.is_empty() {
                    return Err("missing timeline option value".into());
                }
                let case = open_case(Path::new(&args[1]), interrupted)?;
                let host = args[2]
                    .to_str()
                    .ok_or("host must be an IP address")?
                    .parse()
                    .map_err(|_| "invalid host IP address")?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&case.timeline(host, after, limit)?)
                        .map_err(|e| e.to_string())?
                );
            }
            "case-export" if args.len() >= 4 => {
                let mut include_packets = false;
                let mut source = None;
                let mut options = args[4..].iter();
                while let Some(option) = options.next() {
                    match option.to_str() {
                        Some("--include-packets") => include_packets = true,
                        Some("--source") => {
                            source = Some(Path::new(
                                options
                                    .next()
                                    .ok_or("--source needs the original capture path")?,
                            ))
                        }
                        _ => {
                            return Err(
                                "case-export accepts --include-packets and --source CAPTURE".into(),
                            )
                        }
                    }
                }
                let host = args[2]
                    .to_str()
                    .ok_or("host must be an IP address")?
                    .parse()
                    .map_err(|_| "invalid host IP address")?;
                let result = tracehound_eval::case_export::export_host_with_source(
                    Path::new(&args[1]),
                    host,
                    Path::new(&args[3]),
                    include_packets,
                    source,
                    &|| interrupted.load(Ordering::Acquire),
                )?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&result).map_err(|e| e.to_string())?
                );
            }
            "behavior-compare"
                if args.len() == 4 || (args.len() == 6 && args[4] == "--seconds") =>
            {
                let host = args[3]
                    .to_str()
                    .ok_or("host must be an IP address")?
                    .parse()
                    .map_err(|_| "invalid host IP address")?;
                let seconds = if args.len() == 6 {
                    Some(
                        args[5]
                            .to_str()
                            .ok_or("seconds must be an integer")?
                            .parse()
                            .map_err(|_| "invalid comparison duration")?,
                    )
                } else {
                    None
                };
                println!(
                    "{}",
                    serde_json::to_string_pretty(
                        &tracehound_eval::baseline::compare_cases_cancellable(
                            Path::new(&args[1]),
                            Path::new(&args[2]),
                            host,
                            seconds,
                            Arc::clone(interrupted)
                        )?
                    )
                    .map_err(|e| e.to_string())?
                );
            }
            "packet-export" if args.len() == 4 || (args.len() == 6 && args[4] == "--source") => {
                let case = open_case(Path::new(&args[1]), interrupted)?;
                let numbers = args[2]
                    .to_str()
                    .ok_or("packet numbers must be comma-separated integers")?
                    .split(',')
                    .map(|text| text.parse().map_err(|_| "invalid packet number"))
                    .collect::<Result<Vec<_>, _>>()?;
                let count = tracehound_eval::case_export::export_packets(
                    &case,
                    &numbers,
                    Path::new(&args[3]),
                    (args.len() == 6).then(|| Path::new(&args[5])),
                    &|| interrupted.load(Ordering::Acquire),
                )?;
                println!("Exported {count} original packets");
            }
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
