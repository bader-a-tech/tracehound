use serde::Serialize;
use std::ffi::OsString;
use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use tracehound_eval::runtime::{CaptureJob, CaptureReport, JobReport, SensorOptions};
use tracehound_eval::suite::{SuiteJob, SuiteReport};
use tracehound_eval::Severity;
mod commands;

const HELP: &str = "tracehound-eval — analyse captures and check labelled detection expectations

USAGE
  tracehound-eval analyze CAPTURE [OPTIONS]
  tracehound-eval evaluate SUITE.json [OPTIONS]
  tracehound-eval corpus DIRECTORY [OPTIONS] [--manifest PATH]
  tracehound-eval history [--history-dir DIRECTORY]
  tracehound-eval open REPORT.json
  tracehound-eval compare BEFORE.json AFTER.json
  tracehound-eval feed-update NEW-FEED.json

OPTIONS
  --sensor PATH       Tracehound executable (default: tracehound on PATH)
  --rules DIR         Custom Tracehound rule directory
  --home-nets CIDRS   Comma-separated internal network prefixes
  --pair-feed PATH    Local source-attributed TLS pair feed (opt-in)
  --save-history      Save this report in private local history
  --history-dir DIR   Use a custom report history directory
  --min-severity LEVEL  Analysis reporting floor (default: low; evaluate uses each case)
  --json              Write the complete machine-readable report to stdout
  --output PATH       Also save a JSON report; refuses to overwrite an existing file
  --timeout SECONDS   Sensor timeout per capture (default: 300; 0 disables)
  --max-alerts N      Maximum alert records per capture (default: 1000000)
  -h, --help          Show this help
  --version           Show the version

Accepts user-supplied PCAP and PCAPNG files. Analysis requires no labels and
makes no accuracy claims. Evaluation requires a suite with explicit expectations.
Exit codes: 0 success, 1 detection mismatch, 2 input or execution error.
";

#[derive(Debug, PartialEq)]
enum Mode {
    Analyze,
    Evaluate,
    Corpus,
}

struct Options {
    mode: Mode,
    input: PathBuf,
    sensor: OsString,
    rules: Option<PathBuf>,
    home_nets: Option<OsString>,
    pair_feed: Option<PathBuf>,
    manifest: Option<PathBuf>,
    save_history: bool,
    history_dir: Option<PathBuf>,
    min_severity: Severity,
    json: bool,
    output: Option<PathBuf>,
    timeout: Duration,
    max_alerts: usize,
}

fn parse_options(args: impl IntoIterator<Item = OsString>) -> Result<Options, String> {
    let mut args = args.into_iter();
    let mode = match args.next().as_deref() {
        Some(s) if s == "analyze" => Mode::Analyze,
        Some(s) if s == "evaluate" => Mode::Evaluate,
        Some(s) if s == "corpus" => Mode::Corpus,
        _ => {
            return Err(
                "choose analyze CAPTURE or evaluate SUITE.json; use --help for usage".into(),
            )
        }
    };
    let mut opts = Options {
        mode,
        input: PathBuf::new(),
        sensor: "tracehound".into(),
        rules: None,
        home_nets: None,
        pair_feed: None,
        manifest: None,
        save_history: false,
        history_dir: None,
        min_severity: Severity::Low,
        json: false,
        output: None,
        timeout: Duration::from_secs(300),
        max_alerts: 1_000_000,
    };
    let mut severity_set = false;
    let mut positional = false;
    let mut literal = false;
    while let Some(arg) = args.next() {
        if !literal && arg == "--" {
            literal = true;
            continue;
        }
        if !literal && arg.to_string_lossy().starts_with('-') {
            if arg == "--json" {
                opts.json = true;
                continue;
            }
            if arg == "--save-history" {
                opts.save_history = true;
                continue;
            }
            let value = args
                .next()
                .ok_or_else(|| format!("{} requires a value", arg.to_string_lossy()))?;
            if value.is_empty() {
                return Err(format!(
                    "{} requires a non-empty value",
                    arg.to_string_lossy()
                ));
            }
            match arg.to_str() {
                Some("--sensor") => opts.sensor = value,
                Some("--rules") => opts.rules = Some(value.into()),
                Some("--home-nets") => opts.home_nets = Some(value),
                Some("--pair-feed") => opts.pair_feed = Some(value.into()),
                Some("--manifest") => opts.manifest = Some(value.into()),
                Some("--history-dir") => opts.history_dir = Some(value.into()),
                Some("--output") => opts.output = Some(value.into()),
                Some("--min-severity") => {
                    opts.min_severity = value.to_str().ok_or("severity must be UTF-8")?.parse()?;
                    severity_set = true;
                }
                Some("--timeout") => {
                    opts.timeout = Duration::from_secs(
                        value
                            .to_str()
                            .ok_or("timeout must be an integer")?
                            .parse()
                            .map_err(|_| "timeout must be a non-negative integer")?,
                    );
                }
                Some("--max-alerts") => {
                    opts.max_alerts = value
                        .to_str()
                        .ok_or("max-alerts must be an integer")?
                        .parse()
                        .map_err(|_| "max-alerts must be a positive integer")?;
                    if opts.max_alerts == 0 {
                        return Err("max-alerts must be positive".into());
                    }
                }
                _ => return Err(format!("unknown option {}", arg.to_string_lossy())),
            }
        } else {
            if positional {
                return Err("provide exactly one capture or suite file".into());
            }
            opts.input = arg.into();
            positional = true;
        }
    }
    if !positional || opts.input.as_os_str().is_empty() {
        return Err("a capture or suite file is required".into());
    }
    if opts.mode == Mode::Evaluate && severity_set {
        return Err("evaluate uses min_severity from each capture case".into());
    }
    if opts.mode != Mode::Corpus && opts.manifest.is_some() {
        return Err("--manifest applies to corpus only".into());
    }
    Ok(opts)
}

fn main() {
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    if wants_help(&args) || args.is_empty() {
        print!("{HELP}");
        return;
    }
    if args.len() == 1 && args[0] == "--version" {
        println!("tracehound-eval {}", env!("CARGO_PKG_VERSION"));
        return;
    }
    let interrupted = Arc::new(AtomicBool::new(false));
    let signal = Arc::clone(&interrupted);
    let outcome = (|| {
        ctrlc::set_handler(move || signal.store(true, Ordering::Release))
            .map_err(|e| format!("install interrupt handler: {e}"))?;
        if let Some(outcome) = commands::run(&args) {
            return outcome;
        }
        run(parse_options(args)?, &interrupted)
    })();
    match outcome {
        Ok(code) => std::process::exit(if interrupted.load(Ordering::Acquire) {
            130
        } else {
            code
        }),
        Err(error) => {
            eprintln!("tracehound-eval: {}", safe(&error));
            std::process::exit(if interrupted.load(Ordering::Acquire) {
                130
            } else {
                2
            });
        }
    }
}

fn wants_help(args: &[OsString]) -> bool {
    let mut value = false;
    for arg in args {
        if value {
            value = false;
            continue;
        }
        if arg == "--" {
            return false;
        }
        if arg == "--help" || arg == "-h" {
            return true;
        }
        if matches!(
            arg.to_str(),
            Some(
                "--sensor"
                    | "--rules"
                    | "--home-nets"
                    | "--output"
                    | "--min-severity"
                    | "--timeout"
                    | "--max-alerts"
                    | "--pair-feed"
                    | "--manifest"
                    | "--history-dir"
            )
        ) {
            value = true;
        } else if arg.to_string_lossy().starts_with('-')
            && arg != "--json"
            && arg != "--save-history"
        {
            return false;
        }
    }
    false
}

fn run(opts: Options, interrupted: &AtomicBool) -> Result<i32, String> {
    if let Some(output) = &opts.output {
        if output.exists() {
            return Err(format!(
                "report {} already exists; choose a new output path",
                output.display()
            ));
        }
    }
    match opts.mode {
        Mode::Analyze => {
            let job =
                CaptureJob::analyze(opts.input.clone(), sensor_options(&opts), opts.min_severity)
                    .map_err(|e| e.to_string())?;
            let result = wait_for_job(&job, interrupted)?;
            let JobReport::Analysis(output) = result.as_ref() else {
                return Err("analysis returned an unexpected report type".into());
            };
            let text = analysis_text(output);
            emit_report(&opts, output, &text)?;
            Ok(0)
        }
        Mode::Evaluate => {
            let job = SuiteJob::start(opts.input.clone(), sensor_options(&opts))?;
            let output = loop {
                if interrupted.load(Ordering::Acquire) {
                    job.cancel();
                }
                if let Some(result) = job.try_result() {
                    break result?;
                }
                thread::sleep(Duration::from_millis(10));
            };
            emit_report(&opts, output.as_ref(), &evaluation_text(&output))?;
            Ok(if output.passed { 0 } else { 1 })
        }
        Mode::Corpus => run_corpus(&opts, interrupted),
    }
}
fn wait_for_job(job: &CaptureJob, interrupted: &AtomicBool) -> Result<Arc<JobReport>, String> {
    loop {
        if interrupted.load(Ordering::Acquire) {
            job.cancel();
        }
        if let Some(result) = job.try_result() {
            return result.map_err(|e| e.to_string());
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn sensor_options(opts: &Options) -> SensorOptions {
    SensorOptions {
        executable: opts.sensor.clone(),
        rules: opts.rules.clone(),
        home_nets: opts.home_nets.clone(),
        pair_feed: opts.pair_feed.clone(),
        timeout: opts.timeout,
        max_alerts: opts.max_alerts,
    }
}
fn emit_report(opts: &Options, report: &impl Serialize, text: &str) -> Result<(), String> {
    let json =
        serde_json::to_string_pretty(report).map_err(|e| format!("serialize report: {e}"))?;
    if let Some(path) = &opts.output {
        tracehound_eval::store::write_new(path, report)?;
    }
    if opts.save_history {
        let store = opts
            .history_dir
            .clone()
            .map(tracehound_eval::store::ReportStore::new)
            .unwrap_or_else(tracehound_eval::store::ReportStore::default_location);
        let entry = store.save(report)?;
        eprintln!("Saved report in local history: {}", entry.id);
    }
    let mut stdout = io::stdout().lock();
    writeln!(stdout, "{}", if opts.json { &json } else { text })
        .map_err(|e| format!("write report: {e}"))
}

fn run_corpus(opts: &Options, interrupted: &AtomicBool) -> Result<i32, String> {
    use tracehound_eval::corpus::{fetch_verified_cancellable, CorpusManifest};
    let manifest = opts
        .manifest
        .as_deref()
        .map(CorpusManifest::load)
        .unwrap_or_else(CorpusManifest::builtin)?;
    if interrupted.load(Ordering::Acquire) {
        return Err("corpus operation cancelled".into());
    }
    let captures = fetch_verified_cancellable(&manifest, &opts.input, &|| {
        interrupted.load(Ordering::Acquire)
    })?;
    let mut reports = Vec::new();
    let mut observations = Vec::new();
    for capture in &captures {
        if interrupted.load(Ordering::Acquire) {
            return Err("corpus operation cancelled".into());
        }
        let mut options = sensor_options(opts);
        if opts.home_nets.is_none() {
            options.home_nets = capture.home_nets.as_ref().map(OsString::from);
        }
        let job = if let Some(case) = &capture.case {
            CaptureJob::evaluate(capture.path.clone(), options, case.clone())
        } else {
            CaptureJob::analyze(capture.path.clone(), options, opts.min_severity)
        }
        .map_err(|e| e.to_string())?;
        match wait_for_job(&job, interrupted)?.as_ref() {
            JobReport::Evaluation(report) => reports.push(report.as_ref().clone()),
            JobReport::Analysis(report) => observations.push(report.clone()),
        }
    }
    let evaluation = SuiteReport::from_cases(reports);
    let report = serde_json::json!({"schema_version":1,"mode":"corpus_evaluation","sources":captures,"evaluation":evaluation,"observations":observations});
    let mut text = if evaluation.captures.is_empty() {
        "No labelled captures: accuracy is unknown.\n".into()
    } else {
        evaluation_text(&evaluation)
    };
    if !observations.is_empty() {
        text.push_str(&format!(
            "\n{} unlabelled capture(s) analysed without accuracy metrics.\n",
            observations.len()
        ));
    }
    emit_report(opts, &report, &text)?;
    Ok(if evaluation.passed { 0 } else { 1 })
}

fn safe(value: &str) -> String {
    value
        .chars()
        .flat_map(|c| {
            if c.is_control() {
                c.escape_default().collect::<Vec<_>>()
            } else {
                vec![c]
            }
        })
        .collect()
}

fn finding_text(f: &tracehound_eval::Finding) -> String {
    let mut output = format!(
        "  [{}] {}  {}",
        f.alert.severity,
        safe(&f.alert.rule_id),
        f.alert
            .src
            .map(|s| s.to_string())
            .unwrap_or_else(|| "unknown".into())
    );
    if let Some(dst) = f.alert.dst {
        output.push_str(&format!(" -> {dst}"));
    }
    output.push_str(&format!(
        "  {} ({} occurrence(s))\n",
        safe(&f.alert.title),
        f.occurrences
    ));
    if !f.alert.evidence.is_null() {
        output.push_str(&format!("    evidence: {}\n", f.alert.evidence));
    }
    output
}

fn analysis_text(output: &CaptureReport) -> String {
    let report = &output.report;
    let mut text = format!(
        "Capture: {}\n{} unique findings at {} or above; {} alert records read.\n",
        safe(&output.capture.display().to_string()),
        report.findings.len(),
        report.min_severity,
        report.total_alerts
    );
    for finding in &report.findings {
        text.push_str(&finding_text(finding));
    }
    if report.findings.is_empty() {
        text.push_str("No findings at the selected reporting floor.\n");
    }
    text.push_str("Accuracy is unknown: this capture has no evaluation labels.");
    text
}

fn evaluation_text(output: &SuiteReport) -> String {
    let mut text = format!(
        "{}: {} capture(s) passed, {} failed.\n",
        if output.passed { "PASS" } else { "FAIL" },
        output.summary.passed,
        output.summary.failed
    );
    for report in &output.captures {
        text.push_str(&format!(
            "\n{} {}: {} expected matched, {} missed, {} unexpected finding(s).\n",
            if report.passed { "PASS" } else { "FAIL" },
            safe(&report.name),
            report.summary.matched_expectations,
            report.summary.missed_expectations,
            report.summary.unexpected_findings
        ));
        for missed in &report.missed_expectations {
            text.push_str(&format!(
                "  MISSED {} from {}{}\n",
                safe(&missed.rule_id),
                missed.src,
                missed.dst.map(|d| format!(" -> {d}")).unwrap_or_default()
            ));
        }
        for finding in &report.unexpected_findings {
            text.push_str(&finding_text(finding));
        }
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn options_reject_invalid_input_and_preserve_paths() {
        let parse = |values: &[&str]| parse_options(values.iter().map(OsString::from));
        assert!(parse(&["evaluate", "suite.json", "--min-severity", "high"]).is_err());
        assert!(parse(&["analyze", "file.pcap", "--max-alerts", "0"]).is_err());
        assert!(parse(&["analyze", "file.pcap", "--timeout", "-1"]).is_err());
        let opts = parse(&[
            "analyze",
            "capture with spaces.pcapng",
            "--sensor",
            "binary with spaces",
        ])
        .unwrap();
        assert_eq!(opts.input, PathBuf::from("capture with spaces.pcapng"));
        assert_eq!(opts.sensor, OsString::from("binary with spaces"));
        assert_eq!(safe("host\u{1b}[2J\n"), "host\\u{1b}[2J\\n");
        let help =
            |values: &[&str]| wants_help(&values.iter().map(OsString::from).collect::<Vec<_>>());
        assert!(help(&["analyze", "--help"]));
        assert!(!help(&["analyze", "--", "--help"]));
        assert!(!help(&["analyze", "capture.pcap", "--output", "--help"]));
    }
}
