use serde::Serialize;
use std::ffi::{OsStr, OsString};
use std::fs::{self, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};
use tracehound_eval::{
    analyze, evaluate, Alert, AnalysisReport, EvaluationReport, Severity, Suite,
};

const HELP: &str = "tracehound-eval — analyse captures and check labelled detection expectations

USAGE
  tracehound-eval analyze CAPTURE [OPTIONS]
  tracehound-eval evaluate SUITE.json [OPTIONS]

OPTIONS
  --sensor PATH       Tracehound executable (default: tracehound on PATH)
  --rules DIR         Custom Tracehound rule directory
  --home-nets CIDRS   Comma-separated internal network prefixes
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
}

struct Options {
    mode: Mode,
    input: PathBuf,
    sensor: OsString,
    rules: Option<PathBuf>,
    home_nets: Option<OsString>,
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
    Ok(opts)
}

#[derive(Serialize)]
struct AnalysisOutput {
    capture: PathBuf,
    #[serde(flatten)]
    report: AnalysisReport,
}

#[derive(Default, Serialize)]
struct SuiteSummary {
    captures: usize,
    passed: usize,
    failed: usize,
    expected_total: usize,
    matched_expectations: usize,
    missed_expectations: usize,
    unique_findings: usize,
    matched_findings: usize,
    unexpected_findings: usize,
    benign_findings: usize,
    precision: Option<f64>,
    recall: Option<f64>,
}

#[derive(Serialize)]
struct SuiteOutput {
    schema_version: u32,
    mode: &'static str,
    passed: bool,
    summary: SuiteSummary,
    captures: Vec<EvaluationReport>,
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
    match parse_options(args).and_then(run) {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            eprintln!("tracehound-eval: {}", safe(&error));
            std::process::exit(2);
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
            )
        ) {
            value = true;
        } else if arg.to_string_lossy().starts_with('-') && arg != "--json" {
            return false;
        }
    }
    false
}

fn run(opts: Options) -> Result<i32, String> {
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
            let alerts = run_sensor(&opts, &opts.input)?;
            let output = AnalysisOutput {
                capture: opts.input.clone(),
                report: analyze(&alerts, opts.min_severity)?,
            };
            let text = analysis_text(&output);
            emit_report(&opts, &output, &text)?;
            Ok(0)
        }
        Mode::Evaluate => {
            let bytes = fs::read(&opts.input)
                .map_err(|e| format!("read suite {}: {e}", opts.input.display()))?;
            let suite: Suite =
                serde_json::from_slice(&bytes).map_err(|e| format!("invalid suite: {e}"))?;
            suite.validate()?;
            let base = opts.input.parent().unwrap_or_else(|| Path::new("."));
            // Validate all input paths before executing any capture. Paths are
            // passed as process arguments, never interpreted by a shell.
            let paths: Vec<PathBuf> = suite
                .captures
                .iter()
                .map(|case| base.join(&case.capture))
                .collect();
            for path in &paths {
                validate_capture(path)?;
            }
            let mut reports = Vec::with_capacity(suite.captures.len());
            for (case, path) in suite.captures.iter().zip(paths.iter()) {
                let alerts =
                    run_sensor(&opts, path).map_err(|e| format!("case {}: {e}", case.name))?;
                reports.push(evaluate(case, &alerts)?);
            }
            let mut summary = SuiteSummary {
                captures: reports.len(),
                ..Default::default()
            };
            for report in &reports {
                summary.passed += usize::from(report.passed);
                summary.failed += usize::from(!report.passed);
                summary.expected_total += report.summary.expected_total;
                summary.matched_expectations += report.summary.matched_expectations;
                summary.missed_expectations += report.summary.missed_expectations;
                summary.unique_findings += report.summary.unique_findings;
                summary.matched_findings += report.summary.matched_findings;
                summary.unexpected_findings += report.summary.unexpected_findings;
                summary.benign_findings += report.summary.benign_findings;
            }
            summary.precision = ratio(summary.matched_findings, summary.unique_findings);
            summary.recall = ratio(summary.matched_expectations, summary.expected_total);
            let passed = summary.failed == 0;
            let output = SuiteOutput {
                schema_version: 1,
                mode: "evaluation_suite",
                passed,
                summary,
                captures: reports,
            };
            let text = evaluation_text(&output);
            emit_report(&opts, &output, &text)?;
            Ok(if passed { 0 } else { 1 })
        }
    }
}

fn ratio(n: usize, d: usize) -> Option<f64> {
    (d != 0).then(|| n as f64 / d as f64)
}

fn validate_capture(path: &Path) -> Result<(), String> {
    if !path.is_file() {
        return Err(format!("capture {} is not a readable file", path.display()));
    }
    Ok(())
}

// Always ask the sensor for every severity. Filtering belongs to the evaluator
// so that labels and the report use exactly the same reporting floor.
fn run_sensor(opts: &Options, path: &Path) -> Result<Vec<Alert>, String> {
    validate_capture(path)?;
    let capture_path =
        fs::canonicalize(path).map_err(|e| format!("open capture {}: {e}", path.display()))?;
    let mut command = Command::new(&opts.sensor);
    command.args([
        OsStr::new("replay"),
        capture_path.as_os_str(),
        OsStr::new("-json"),
        OsStr::new("-quiet"),
        OsStr::new("-min-severity"),
        OsStr::new("info"),
    ]);
    if let Some(rules) = &opts.rules {
        command.arg("-rules").arg(rules);
    }
    if let Some(nets) = &opts.home_nets {
        command.arg("-home-nets").arg(nets);
    }
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(Stdio::null())
        .spawn()
        .map_err(|e| {
            format!(
                "start sensor {}: {e}; use --sensor PATH to select the Tracehound executable",
                Path::new(&opts.sensor).display()
            )
        })?;
    let stdout = child.stdout.take().ok_or("sensor stdout unavailable")?;
    let stderr = child.stderr.take().ok_or("sensor stderr unavailable")?;
    let max_alerts = opts.max_alerts;
    let (tx, rx) = mpsc::channel();
    let reader = thread::spawn(move || {
        let _ = tx.send(read_alerts(stdout, max_alerts));
    });
    let errors = thread::spawn(move || bounded_stderr(stderr));
    let start = Instant::now();
    let mut alerts = None;
    let status = loop {
        if alerts.is_none() {
            match rx.try_recv() {
                Ok(Ok(parsed)) => alerts = Some(parsed),
                Ok(Err(error)) => {
                    stop_child(&mut child);
                    let _ = reader.join();
                    let _ = errors.join();
                    return Err(error);
                }
                Err(mpsc::TryRecvError::Disconnected) => {
                    stop_child(&mut child);
                    let _ = reader.join();
                    let _ = errors.join();
                    return Err("sensor output reader failed".into());
                }
                Err(mpsc::TryRecvError::Empty) => {}
            }
        }
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {}
            Err(error) => {
                stop_child(&mut child);
                let _ = reader.join();
                let _ = errors.join();
                return Err(format!("wait for sensor: {error}"));
            }
        }
        if !opts.timeout.is_zero() && start.elapsed() >= opts.timeout {
            stop_child(&mut child);
            let _ = reader.join();
            let _ = errors.join();
            return Err(format!(
                "sensor exceeded {} seconds; adjust --timeout for larger captures",
                opts.timeout.as_secs()
            ));
        }
        thread::sleep(Duration::from_millis(10));
    };
    let stderr = errors.join().map_err(|_| "sensor stderr reader failed")?;
    reader.join().map_err(|_| "sensor stdout reader failed")?;
    if !status.success() {
        return Err(format!(
            "sensor exited with {status}: {}",
            String::from_utf8_lossy(&stderr).trim()
        ));
    }
    match alerts {
        Some(alerts) => Ok(alerts),
        None => rx.recv().map_err(|_| "sensor output reader failed")?,
    }
}

fn stop_child(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

fn bounded_stderr(mut stream: impl Read) -> Vec<u8> {
    let mut output = Vec::new();
    let mut buffer = [0; 8192];
    while let Ok(n) = stream.read(&mut buffer) {
        if n == 0 {
            break;
        }
        let keep = n.min(65536usize.saturating_sub(output.len()));
        output.extend_from_slice(&buffer[..keep]);
    }
    output
}

fn read_alerts(stream: impl Read, max_alerts: usize) -> Result<Vec<Alert>, String> {
    let mut reader = BufReader::new(stream);
    let mut alerts = Vec::new();
    let mut line = Vec::new();
    let mut line_number = 0;
    loop {
        line.clear();
        let count = reader
            .by_ref()
            .take(1_048_577)
            .read_until(b'\n', &mut line)
            .map_err(|e| format!("read sensor output: {e}"))?;
        if count == 0 {
            break;
        }
        line_number += 1;
        if line.len() > 1_048_576 {
            return Err(format!("sensor JSON line {line_number} exceeds 1 MiB"));
        }
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        if alerts.len() >= max_alerts {
            return Err(format!("sensor exceeded {max_alerts} alert records; adjust --max-alerts or narrow the capture"));
        }
        alerts.push(
            serde_json::from_slice(&line)
                .map_err(|e| format!("invalid sensor JSON at line {line_number}: {e}"))?,
        );
    }
    Ok(alerts)
}

fn emit_report(opts: &Options, report: &impl Serialize, text: &str) -> Result<(), String> {
    let json =
        serde_json::to_string_pretty(report).map_err(|e| format!("serialize report: {e}"))?;
    if let Some(path) = &opts.output {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|e| format!("create report {}: {e}", path.display()))?;
        writeln!(file, "{json}").map_err(|e| format!("write report {}: {e}", path.display()))?;
    }
    let mut stdout = io::stdout().lock();
    writeln!(stdout, "{}", if opts.json { &json } else { text })
        .map_err(|e| format!("write report: {e}"))
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

fn analysis_text(output: &AnalysisOutput) -> String {
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

fn evaluation_text(output: &SuiteOutput) -> String {
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
    fn reader_reports_malformed_output_and_limits() {
        assert!(read_alerts("not json\n".as_bytes(), 10)
            .unwrap_err()
            .contains("line 1"));
        let data = b"{\"rule_id\":\"TH-0001\",\"severity\":\"high\",\"src\":\"10.0.0.1\"}\n";
        assert!(read_alerts(data.as_slice().repeat(2).as_slice(), 1)
            .unwrap_err()
            .contains("exceeded 1"));
        assert!(read_alerts(vec![b'x'; 1_048_577].as_slice(), 1)
            .unwrap_err()
            .contains("1 MiB"));
    }

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
