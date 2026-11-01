use serde_json::json;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc,
};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tracehound_eval::investigation::CaseBuilder;

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);
struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "tracehound-export-bounds-{}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        for folder in ["export", "cancelled-export"] {
            let path = self.0.join(folder);
            for file in [
                "investigation.html",
                "investigation.json",
                "evidence.pcapng",
                "SHA256SUMS.txt",
            ] {
                let _ = fs::remove_file(path.join(file));
            }
            let _ = fs::remove_dir(path);
        }
        for file in ["source.pcap", "case.sqlite", "case.sqlite-journal"] {
            let _ = fs::remove_file(self.0.join(file));
        }
        let _ = fs::remove_dir(&self.0);
    }
}

fn build_case(directory: &Path, limited: bool) -> PathBuf {
    let source = directory.join("source.pcap");
    let destination = directory.join("case.sqlite");
    let mut bytes = Vec::new();
    bytes.extend(0xa1b2c3d4u32.to_le_bytes());
    bytes.extend(2u16.to_le_bytes());
    bytes.extend(4u16.to_le_bytes());
    for value in [0u32, 0, 65535, 1] {
        bytes.extend(value.to_le_bytes());
    }
    let mut frame = vec![0u8; 54];
    frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
    frame[14] = 0x45;
    frame[16..18].copy_from_slice(&40u16.to_be_bytes());
    frame[22] = 64;
    frame[23] = 6;
    frame[26..30].copy_from_slice(&[10, 0, 0, 5]);
    frame[30..34].copy_from_slice(&[198, 51, 100, 9]);
    frame[34..36].copy_from_slice(&40_000u16.to_be_bytes());
    frame[36..38].copy_from_slice(&443u16.to_be_bytes());
    frame[46] = 0x50;
    frame[47] = 2;
    for value in [1u32, 0, 54, 54] {
        bytes.extend(value.to_le_bytes());
    }
    bytes.extend(frame);
    fs::write(&source, bytes).unwrap();
    let mut builder = CaseBuilder::create(&source, &destination).unwrap();
    let mut reference = None;
    let enrichment = tracehound_eval::capture::scan_capture_events(
        &source,
        None,
        &|| false,
        &mut |event, decoded| {
            reference = Some(event.reference.clone());
            builder.push(event, decoded)
        },
    )
    .unwrap();
    if limited {
        let reference = reference.unwrap();
        builder
            .event(
                reference.timestamp_ns,
                "finding",
                "10.0.0.5".parse().unwrap(),
                None,
                "Bounded detector evidence".into(),
                "detector_evidence",
                &[reference],
                true,
                &json!({"rule_id":"TH-0003"}),
            )
            .unwrap();
    }
    builder.finish(&enrichment, json!({"mode":"test"})).unwrap();
    destination
}

#[test]
fn supporting_reference_limits_remain_visible_in_json_and_html_exports() {
    let directory = Directory::new();
    let case = build_case(&directory.0, true);
    let exported = tracehound_eval::case_export::export_host(
        &case,
        "10.0.0.5".parse().unwrap(),
        &directory.0.join("export"),
        false,
        &|| false,
    )
    .unwrap();
    assert!(exported.supporting_evidence_truncated);
    assert!(!exported.packets_truncated);
    let document: serde_json::Value =
        serde_json::from_slice(&fs::read(exported.json).unwrap()).unwrap();
    assert_eq!(document["supporting_evidence_truncated"], true);
    assert_eq!(document["packets_truncated"], false);
    let html = fs::read_to_string(exported.html).unwrap();
    assert!(html.contains("Supporting packet references were limited"));
    assert!(html.contains("bounded evidence examples"));
}

#[test]
fn cancellation_interrupts_a_running_sqlite_timeline_query() {
    let directory = Directory::new();
    let case = build_case(&directory.0, false);
    // A generated read-only view forces a long SQLite sort without writing a
    // huge test database. Cancellation must interrupt inside the query itself.
    let database = rusqlite::Connection::open(&case).unwrap();
    database.execute_batch("DROP TABLE events;CREATE VIEW events AS WITH RECURSIVE sequence(id) AS (SELECT 1 UNION ALL SELECT id+1 FROM sequence WHERE id<100000000) SELECT id,100000000-id AS timestamp_ns,'dns' AS kind,'10.0.0.5' AS host,'198.51.100.9' AS peer,'query' AS summary,'packet' AS evidence_kind,'[]' AS packets,0 AS refs_truncated,'{}' AS details FROM sequence;").unwrap();
    drop(database);
    let cancelled = Arc::new(AtomicBool::new(false));
    let signal = Arc::clone(&cancelled);
    let trigger = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(50));
        signal.store(true, Ordering::Release);
    });
    let started = Instant::now();
    let destination = directory.0.join("cancelled-export");
    let error = tracehound_eval::case_export::export_host(
        &case,
        "10.0.0.5".parse().unwrap(),
        &destination,
        false,
        &|| cancelled.load(Ordering::Acquire),
    )
    .unwrap_err();
    trigger.join().unwrap();
    assert!(
        error.contains("interrupted") || error.contains("cancelled"),
        "{error}"
    );
    assert!(started.elapsed() < Duration::from_secs(2));
    assert!(!destination.exists());
}
