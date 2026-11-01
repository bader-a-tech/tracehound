//! Pinned external capture downloads and provenance for reproducible evaluation.

use crate::{CaptureCase, Expectation, Severity};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

pub const BUILTIN_MANIFEST: &str = include_str!("../data/corpus.json");
const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;
const MAX_CAPTURE_BYTES: u64 = 2 * 1024 * 1024 * 1024;
static NEXT_DOWNLOAD: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CorpusManifest {
    pub schema_version: u32,
    pub captures: Vec<CorpusEntry>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CorpusEntry {
    pub id: String,
    pub filename: String,
    pub url: String,
    pub sha256: String,
    pub bytes: u64,
    pub source_url: String,
    pub license: String,
    pub description: String,
    pub classification: String,
    #[serde(default)]
    pub home_nets: Option<String>,
    /// None means observation only; Some([]) explicitly expects no findings.
    #[serde(default)]
    pub expected: Option<Vec<Expectation>>,
    #[serde(default)]
    pub benign_hosts: Vec<IpAddr>,
    #[serde(default)]
    pub min_severity: Severity,
    /// Reviewed whole-capture monitoring windows. Never inferred merely from
    /// the first/last packet or an unlabelled trace's idle gaps.
    #[serde(default)]
    pub benign_exposure: Vec<BenignExposure>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BenignExposure {
    pub host: IpAddr,
    pub monitored_seconds: f64,
    pub rule_ids: Vec<String>,
    pub source_url: String,
    pub basis: String,
    pub assumptions: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct VerifiedCapture {
    pub id: String,
    pub path: PathBuf,
    pub sha256: String,
    pub bytes: u64,
    pub source_url: String,
    pub license: String,
    pub classification: String,
    pub description: String,
    pub home_nets: Option<String>,
    pub case: Option<CaptureCase>,
    #[serde(default)]
    pub benign_exposure: Vec<BenignExposure>,
}

impl CorpusManifest {
    pub fn builtin() -> Result<Self, String> {
        let manifest: Self = serde_json::from_str(BUILTIN_MANIFEST)
            .map_err(|e| format!("parse built-in corpus: {e}"))?;
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn load(path: &Path) -> Result<Self, String> {
        let file = File::open(path).map_err(|e| format!("read corpus {}: {e}", path.display()))?;
        let mut bytes = Vec::new();
        file.take(MAX_MANIFEST_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| format!("read corpus {}: {e}", path.display()))?;
        if bytes.len() as u64 > MAX_MANIFEST_BYTES {
            return Err("corpus manifest exceeds 1 MiB".into());
        }
        let manifest: Self = serde_json::from_slice(&bytes)
            .map_err(|e| format!("parse corpus {}: {e}", path.display()))?;
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != 1 || self.captures.is_empty() {
            return Err("corpus requires schema_version 1 and at least one capture".into());
        }
        let mut ids = BTreeSet::new();
        let mut names = BTreeSet::new();
        for entry in &self.captures {
            if entry.id.trim().is_empty() || !ids.insert(&entry.id) {
                return Err(format!("empty or duplicate corpus id {:?}", entry.id));
            }
            if !safe_filename(&entry.filename) || !names.insert(entry.filename.to_lowercase()) {
                return Err(format!(
                    "unsafe or duplicate capture filename {:?}",
                    entry.filename
                ));
            }
            if !https_url(&entry.url) || !https_url(&entry.source_url) {
                return Err(format!(
                    "corpus {} requires HTTPS source and download URLs without credentials",
                    entry.id
                ));
            }
            if entry.sha256.len() != 64 || !entry.sha256.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(format!("corpus {} requires a SHA-256 digest", entry.id));
            }
            if entry.bytes == 0 || entry.bytes > MAX_CAPTURE_BYTES {
                return Err(format!(
                    "corpus {} size must be 1 byte through 2 GiB",
                    entry.id
                ));
            }
            if entry.license.trim().is_empty()
                || entry.description.trim().is_empty()
                || entry.classification.trim().is_empty()
            {
                return Err(format!(
                    "corpus {} requires license, description, and classification",
                    entry.id
                ));
            }
            if let Some(case) = entry.case(PathBuf::from(&entry.filename)) {
                case.validate()?;
            } else if !entry.benign_hosts.is_empty() {
                return Err(format!(
                    "corpus {} has benign labels but no explicit expected list",
                    entry.id
                ));
            }
            let mut exposed = BTreeSet::new();
            for exposure in &entry.benign_exposure {
                if !entry.benign_hosts.contains(&exposure.host)
                    || !exposure.monitored_seconds.is_finite()
                    || exposure.monitored_seconds <= 0.0
                    || exposure.monitored_seconds > 366.0 * 24.0 * 3600.0
                    || exposure.rule_ids.is_empty()
                    || !https_url(&exposure.source_url)
                    || exposure.basis.trim().is_empty()
                    || exposure.assumptions.is_empty()
                {
                    return Err(format!(
                        "corpus {} has unsupported benign exposure metadata",
                        entry.id
                    ));
                }
                for rule in &exposure.rule_ids {
                    if rule.trim().is_empty() || !exposed.insert((exposure.host, rule)) {
                        return Err(format!(
                            "corpus {} has duplicate or invalid exposure rules",
                            entry.id
                        ));
                    }
                }
            }
        }
        Ok(())
    }
}

impl CorpusEntry {
    fn case(&self, path: PathBuf) -> Option<CaptureCase> {
        self.expected.as_ref().map(|expected| CaptureCase {
            name: self.id.clone(),
            capture: path,
            expected: expected.clone(),
            benign_hosts: self.benign_hosts.clone(),
            min_severity: self.min_severity,
        })
    }
}

fn https_url(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("https://") else {
        return false;
    };
    let host = rest.split('/').next().unwrap_or_default();
    !host.is_empty() && !host.contains('@') && !value.chars().any(char::is_control)
}

fn safe_filename(value: &str) -> bool {
    let stem = value
        .split('.')
        .next()
        .unwrap_or_default()
        .to_ascii_uppercase();
    let reserved = matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || (stem.len() == 4
            && (stem.starts_with("COM") || stem.starts_with("LPT"))
            && stem.as_bytes()[3].is_ascii_digit());
    !reserved
        && !value.starts_with('.')
        && !value.ends_with('.')
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        && matches!(
            Path::new(value).extension().and_then(|s| s.to_str()),
            Some("pcap" | "pcapng" | "cap")
        )
}

/// Download missing captures, verifying pinned length and SHA-256 before making
/// them available. Existing valid files are reused; invalid files are preserved
/// and reported, never overwritten. Capture bytes remain in the chosen folder.
pub fn fetch_verified(
    manifest: &CorpusManifest,
    directory: &Path,
) -> Result<Vec<VerifiedCapture>, String> {
    fetch_verified_cancellable(manifest, directory, &|| false)
}

/// Cancel between files and buffered reads. A blocked HTTPS read is bounded by
/// the request's 30-second timeout. Previously verified cache files are kept.
pub fn fetch_verified_cancellable(
    manifest: &CorpusManifest,
    directory: &Path,
    cancelled: &dyn Fn() -> bool,
) -> Result<Vec<VerifiedCapture>, String> {
    manifest.validate()?;
    check_cancelled(cancelled)?;
    fs::create_dir_all(directory)
        .map_err(|e| format!("create corpus directory {}: {e}", directory.display()))?;
    let directory =
        fs::canonicalize(directory).map_err(|e| format!("resolve corpus directory: {e}"))?;
    let config = ureq::Agent::config_builder()
        .https_only(true)
        .timeout_global(Some(Duration::from_secs(30)))
        .build();
    let agent: ureq::Agent = config.into();
    let mut verified = Vec::with_capacity(manifest.captures.len());
    for entry in &manifest.captures {
        check_cancelled(cancelled)?;
        let path = directory.join(&entry.filename);
        if path.exists() {
            verify_file(entry, &path, cancelled)?;
        } else {
            let mut response = agent
                .get(&entry.url)
                .call()
                .map_err(|e| format!("download {}: {e}", entry.id))?;
            check_cancelled(cancelled)?;
            persist_verified(entry, &path, response.body_mut().as_reader(), cancelled)?;
        }
        check_cancelled(cancelled)?;
        verified.push(VerifiedCapture {
            id: entry.id.clone(),
            path: path.clone(),
            sha256: entry.sha256.to_ascii_lowercase(),
            bytes: entry.bytes,
            source_url: entry.source_url.clone(),
            license: entry.license.clone(),
            classification: entry.classification.clone(),
            description: entry.description.clone(),
            home_nets: entry.home_nets.clone(),
            case: entry.case(path),
            benign_exposure: entry.benign_exposure.clone(),
        });
    }
    check_cancelled(cancelled)?;
    Ok(verified)
}

fn check_cancelled(cancelled: &dyn Fn() -> bool) -> Result<(), String> {
    if cancelled() {
        Err("corpus download cancelled".into())
    } else {
        Ok(())
    }
}

fn verify_file(
    entry: &CorpusEntry,
    path: &Path,
    cancelled: &dyn Fn() -> bool,
) -> Result<(), String> {
    let file = File::open(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut bytes = 0u64;
    let mut reader = file.take(entry.bytes + 1);
    let mut buffer = [0; 64 * 1024];
    loop {
        check_cancelled(cancelled)?;
        let count = reader
            .read(&mut buffer)
            .map_err(|e| format!("read {}: {e}", path.display()))?;
        if count == 0 {
            break;
        }
        bytes += count as u64;
        hasher.update(&buffer[..count]);
    }
    check_cancelled(cancelled)?;
    check_digest(entry, bytes, &format!("{:x}", hasher.finalize()))
}

fn check_digest(entry: &CorpusEntry, bytes: u64, digest: &str) -> Result<(), String> {
    if bytes != entry.bytes || !digest.eq_ignore_ascii_case(&entry.sha256) {
        return Err(format!(
            "corpus {} failed pinned size/SHA-256 verification; existing files are preserved",
            entry.id
        ));
    }
    Ok(())
}

struct Download {
    path: PathBuf,
    output: Option<File>,
    remove_on_drop: bool,
}
impl Drop for Download {
    fn drop(&mut self) {
        // Close the handle before deleting on Windows. This guard is created
        // only after exclusive file creation succeeds, so it never removes a
        // temporary file owned by another download.
        self.output.take();
        if self.remove_on_drop {
            let _ = fs::remove_file(&self.path);
        }
    }
}

fn persist_verified(
    entry: &CorpusEntry,
    target: &Path,
    mut reader: impl Read,
    cancelled: &dyn Fn() -> bool,
) -> Result<(), String> {
    check_cancelled(cancelled)?;
    let temporary = target.with_extension(format!(
        "download-{}-{}",
        std::process::id(),
        NEXT_DOWNLOAD.fetch_add(1, Ordering::Relaxed)
    ));
    let output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .map_err(|e| format!("create corpus download: {e}"))?;
    let mut guard = Download {
        path: temporary,
        output: Some(output),
        remove_on_drop: true,
    };
    let output = guard
        .output
        .as_mut()
        .expect("new download has an open file");
    let mut hasher = Sha256::new();
    let mut count = 0u64;
    let mut buffer = [0; 64 * 1024];
    loop {
        check_cancelled(cancelled)?;
        let limit = buffer.len().min((entry.bytes + 1 - count) as usize);
        if limit == 0 {
            break;
        }
        let n = reader
            .read(&mut buffer[..limit])
            .map_err(|e| format!("download {}: {e}", entry.id))?;
        check_cancelled(cancelled)?;
        if n == 0 {
            break;
        }
        count += n as u64;
        hasher.update(&buffer[..n]);
        output
            .write_all(&buffer[..n])
            .map_err(|e| format!("write corpus {}: {e}", entry.id))?;
    }
    check_digest(entry, count, &format!("{:x}", hasher.finalize()))?;
    output
        .sync_all()
        .map_err(|e| format!("flush corpus {}: {e}", entry.id))?;
    guard.output.take();
    check_cancelled(cancelled)?;
    // Use atomic, exclusive publication where the filesystem permits hard links.
    // Removable filesystems and restricted Windows environments may deny links;
    // an exclusive, guarded copy still preserves any concurrently created file.
    if fs::hard_link(&guard.path, target).is_err() {
        let output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(target)
            .map_err(|e| format!("publish verified corpus {}: {e}", entry.id))?;
        let mut published = Download {
            path: target.to_path_buf(),
            output: Some(output),
            remove_on_drop: true,
        };
        let mut input =
            File::open(&guard.path).map_err(|e| format!("read verified download: {e}"))?;
        let mut hasher = Sha256::new();
        let mut count = 0u64;
        loop {
            check_cancelled(cancelled)?;
            let length = input
                .read(&mut buffer)
                .map_err(|e| format!("read verified download: {e}"))?;
            check_cancelled(cancelled)?;
            if length == 0 {
                break;
            }
            count += length as u64;
            if count > entry.bytes {
                return Err(format!(
                    "verified download {} changed during publication",
                    entry.id
                ));
            }
            hasher.update(&buffer[..length]);
            published
                .output
                .as_mut()
                .expect("publication has an open file")
                .write_all(&buffer[..length])
                .map_err(|e| format!("publish verified corpus {}: {e}", entry.id))?;
        }
        check_digest(entry, count, &format!("{:x}", hasher.finalize()))?;
        published
            .output
            .as_mut()
            .expect("publication has an open file")
            .sync_all()
            .map_err(|e| format!("flush published corpus: {e}"))?;
        published.remove_on_drop = false;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_metadata_is_complete_and_labelled_cases_are_explicit() {
        let manifest = CorpusManifest::builtin().unwrap();
        assert_eq!(manifest.captures.len(), 7);
        assert_eq!(
            manifest
                .captures
                .iter()
                .filter(|capture| capture.expected.is_some())
                .count(),
            6
        );
        assert!(manifest
            .captures
            .iter()
            .any(|capture| capture.expected.is_none()
                && capture.classification.contains("observation")));
    }

    #[test]
    fn extended_exposure_requires_reviewed_benign_labels_and_source_assumptions() {
        let mut manifest: CorpusManifest =
            serde_json::from_str(include_str!("../data/corpus-extended.json")).unwrap();
        manifest.validate().unwrap();
        let capture = manifest
            .captures
            .iter_mut()
            .find(|capture| !capture.benign_exposure.is_empty())
            .unwrap();
        capture.benign_exposure[0].assumptions.clear();
        assert!(manifest.validate().is_err());
    }

    #[test]
    fn traversal_credentials_and_conflicting_labels_are_rejected() {
        for filename in [
            "../escape.pcap",
            "CON.pcap",
            ".hidden.pcap",
            "capture.PCAP",
            "file.pcap.",
        ] {
            let mut manifest = CorpusManifest::builtin().unwrap();
            manifest.captures[0].filename = filename.into();
            assert!(manifest.validate().is_err(), "accepted {filename}");
        }
        let mut manifest = CorpusManifest::builtin().unwrap();
        manifest.captures[0].url = "https://user:secret@example.com/capture.pcap".into();
        assert!(manifest.validate().is_err());
        let mut manifest = CorpusManifest::builtin().unwrap();
        manifest.captures[1].benign_hosts = vec!["147.32.80.37".parse().unwrap()];
        assert!(manifest.validate().is_err());
    }

    #[test]
    fn corrupt_downloads_do_not_create_final_capture_files() {
        let manifest = CorpusManifest::builtin().unwrap();
        let entry = &manifest.captures[0];
        let root = std::env::temp_dir().join(format!(
            "tracehound-corpus-{}-{}",
            std::process::id(),
            NEXT_DOWNLOAD.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        let target = root.join(&entry.filename);
        assert!(
            persist_verified(entry, &target, b"incorrect capture".as_slice(), &|| false).is_err()
        );
        assert!(!target.exists());
        assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
        fs::remove_dir(&root).unwrap();
    }

    #[test]
    fn verified_downloads_preserve_existing_files_and_reuse_valid_cache() {
        let mut manifest = CorpusManifest::builtin().unwrap();
        manifest.captures.truncate(1);
        let payload = b"locally verified capture bytes";
        let entry = &mut manifest.captures[0];
        entry.bytes = payload.len() as u64;
        entry.sha256 = format!("{:x}", Sha256::digest(payload));
        let root = std::env::temp_dir().join(format!(
            "tracehound-corpus-{}-{}",
            std::process::id(),
            NEXT_DOWNLOAD.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        let target = root.join(&entry.filename);
        persist_verified(entry, &target, payload.as_slice(), &|| false).unwrap();
        verify_file(entry, &target, &|| false).unwrap();
        assert!(persist_verified(entry, &target, payload.as_slice(), &|| false).is_err());
        assert_eq!(fs::read(&target).unwrap(), payload);
        assert_eq!(fs::read_dir(&root).unwrap().count(), 1);
        let fetched = fetch_verified(&manifest, &root).unwrap();
        assert_eq!(fetched.len(), 1);
        assert!(fetched[0].case.is_some());
        fs::write(&target, b"changed by another process").unwrap();
        assert!(fetch_verified(&manifest, &root).is_err());
        assert_eq!(fs::read(&target).unwrap(), b"changed by another process");
        fs::remove_file(&target).unwrap();
        fs::remove_dir(&root).unwrap();
    }

    #[test]
    fn cancellation_during_download_removes_owned_partial_and_keeps_cached_files() {
        use std::cell::Cell;
        struct CancelAfterRead<'a> {
            cancelled: &'a Cell<bool>,
        }
        impl Read for CancelAfterRead<'_> {
            fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
                buffer[0] = 1;
                self.cancelled.set(true);
                Ok(1)
            }
        }
        let manifest = CorpusManifest::builtin().unwrap();
        let root = std::env::temp_dir().join(format!(
            "tracehound-corpus-{}-{}",
            std::process::id(),
            NEXT_DOWNLOAD.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        let cached = root.join("previous.pcap");
        fs::write(&cached, b"previous capture").unwrap();
        let target = root.join(&manifest.captures[0].filename);
        let cancelled = Cell::new(false);
        let result = persist_verified(
            &manifest.captures[0],
            &target,
            CancelAfterRead {
                cancelled: &cancelled,
            },
            &|| cancelled.get(),
        );
        assert!(result.unwrap_err().contains("cancelled"));
        assert!(!target.exists());
        assert_eq!(fs::read(&cached).unwrap(), b"previous capture");
        assert_eq!(fs::read_dir(&root).unwrap().count(), 1);
        assert!(fetch_verified_cancellable(&manifest, &root, &|| true)
            .unwrap_err()
            .contains("cancelled"));
        fs::remove_file(cached).unwrap();
        fs::remove_dir(root).unwrap();
    }
}
