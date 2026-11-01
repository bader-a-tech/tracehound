//! Bundle dependency license and notice files from already downloaded sources.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Serialize)]
struct Dependency {
    ecosystem: &'static str,
    name: String,
    version: String,
    license: String,
    source: String,
    source_archive: String,
    notice_note: Option<String>,
    notice_sources: Vec<NoticeSource>,
    files: Vec<String>,
}

#[derive(Clone, Deserialize, Serialize)]
struct NoticeSource {
    path: String,
    source_url: String,
    sha256: String,
}
#[derive(Deserialize)]
struct CuratedCrate {
    name: String,
    version: String,
    revision: String,
    note: String,
    files: Vec<NoticeSource>,
}
#[derive(Deserialize)]
struct CuratedNotices {
    schema_version: u32,
    crates: Vec<CuratedCrate>,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("dependency notice collection failed: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() != 2 {
        return Err("usage: release-notices REPOSITORY_ROOT NEW_LICENSE_DIRECTORY".into());
    }
    let repository = fs::canonicalize(&args[0]).map_err(|e| format!("resolve repository: {e}"))?;
    let notice_root = repository.join("tools/capture-eval/data/third-party");
    let curated: CuratedNotices = serde_json::from_slice(
        &fs::read(notice_root.join("manifest.json"))
            .map_err(|e| format!("read curated notice ledger: {e}"))?,
    )
    .map_err(|e| format!("parse curated notice ledger: {e}"))?;
    if curated.schema_version != 1 {
        return Err("unsupported notice ledger version".into());
    }
    let destination = PathBuf::from(&args[1]);
    fs::create_dir(&destination).map_err(|e| format!("create new license directory: {e}"))?;
    let rustc = checked(Command::new("rustc").arg("-vV"))?;
    let version = String::from_utf8(rustc).map_err(|e| format!("rustc version: {e}"))?;
    let host = version
        .lines()
        .find_map(|line| line.strip_prefix("host: "))
        .ok_or("rustc omitted host target")?;
    let metadata = checked(
        Command::new("cargo")
            .current_dir(&repository)
            .args([
                "metadata",
                "--locked",
                "--offline",
                "--format-version",
                "1",
                "--all-features",
                "--filter-platform",
                host,
                "--manifest-path",
            ])
            .arg(repository.join("tools/capture-eval/Cargo.toml")),
    )?;
    let metadata: Value =
        serde_json::from_slice(&metadata).map_err(|e| format!("Cargo metadata: {e}"))?;
    let resolved: BTreeSet<_> = metadata["resolve"]["nodes"]
        .as_array()
        .ok_or("Cargo metadata omitted resolved dependencies")?
        .iter()
        .filter_map(|node| node["id"].as_str())
        .collect();
    let mut dependencies = Vec::new();
    for package in metadata["packages"]
        .as_array()
        .ok_or("Cargo metadata omitted packages")?
    {
        if package["source"].is_null() || !resolved.contains(string(package, "id")?) {
            continue;
        }
        let name = string(package, "name")?;
        let version = string(package, "version")?;
        let manifest = Path::new(string(package, "manifest_path")?);
        let directory = manifest.parent().ok_or("crate manifest has no directory")?;
        let mut files = license_files(directory)?;
        if let Some(path) = package["license_file"].as_str() {
            let path = directory.join(path);
            if path.is_file() && !files.contains(&path) {
                files.push(path);
            }
        }
        let source = package["repository"]
            .as_str()
            .unwrap_or_else(|| package["source"].as_str().unwrap_or_default())
            .to_owned();
        let source_archive = if string(package, "source")?.starts_with("registry+") {
            format!("https://crates.io/api/v1/crates/{name}/{version}/download")
        } else {
            string(package, "source")?.to_owned()
        };
        let mut dependency = Dependency {
            ecosystem: "Rust",
            name: name.into(),
            version: version.into(),
            license: package["license"]
                .as_str()
                .unwrap_or("See upstream license files")
                .into(),
            source,
            source_archive,
            notice_note: None,
            notice_sources: Vec::new(),
            files: Vec::new(),
        };
        if let Some(entry) = curated
            .crates
            .iter()
            .find(|entry| entry.name == name && entry.version == version)
        {
            let vcs: Value = serde_json::from_slice(
                &fs::read(directory.join(".cargo_vcs_info.json"))
                    .map_err(|e| format!("read package provenance: {e}"))?,
            )
            .map_err(|e| format!("read package provenance: {e}"))?;
            if vcs["git"]["sha1"] != entry.revision {
                return Err(format!(
                    "curated license revision differs for {name} {version}"
                ));
            }
            let notice_root = fs::canonicalize(&notice_root)
                .map_err(|e| format!("resolve notice sources: {e}"))?;
            for source in &entry.files {
                let file = fs::canonicalize(notice_root.join(&source.path))
                    .map_err(|e| format!("read pinned notice {}: {e}", source.path))?;
                if !file.starts_with(&notice_root) {
                    return Err("notice path escapes curated directory".into());
                }
                let bytes = fs::read(&file).map_err(|e| format!("read pinned notice: {e}"))?;
                if format!("{:x}", Sha256::digest(&bytes)) != source.sha256 {
                    return Err(format!("pinned notice digest changed: {}", source.path));
                }
                files.push(file);
            }
            dependency.notice_sources = entry.files.clone();
            if !entry.note.is_empty() {
                dependency.notice_note = Some(entry.note.clone());
            }
        }
        dependency.files = copy_notices(&destination, directory, &dependency, &files)?;
        dependencies.push(dependency);
    }
    let modules = checked(
        Command::new("go")
            .current_dir(&repository)
            .env("GOPROXY", "off")
            .env("GOSUMDB", "off")
            .env("GOTOOLCHAIN", "local")
            .args(["list", "-deps", "-json", "./cmd/tracehound"]),
    )?;
    let mut seen_go = BTreeSet::new();
    for package in serde_json::Deserializer::from_slice(&modules).into_iter::<Value>() {
        let package = package.map_err(|e| format!("Go dependency metadata: {e}"))?;
        let Some(module) = package.get("Module") else {
            continue;
        };
        if module["Main"] == true {
            continue;
        }
        let source_module = module.get("Replace").unwrap_or(module);
        let name = string(module, "Path")?;
        let version = module["Version"].as_str().unwrap_or("local");
        if !seen_go.insert(format!("{name}@{version}")) {
            continue;
        }
        let directory = Path::new(string(source_module, "Dir")?);
        let files = license_files(directory)?;
        let source_name = string(source_module, "Path")?;
        let source_version = source_module["Version"].as_str().unwrap_or(version);
        let mut dependency = Dependency {
            ecosystem: "Go",
            name: name.into(),
            version: version.into(),
            license: "See bundled upstream license files".into(),
            source: format!("https://pkg.go.dev/{source_name}@{source_version}"),
            source_archive: format!(
                "https://proxy.golang.org/{}/@v/{}.zip",
                escape_go_module(source_name),
                escape_go_module(source_version)
            ),
            notice_note: None,
            notice_sources: Vec::new(),
            files: Vec::new(),
        };
        dependency.files = copy_notices(&destination, directory, &dependency, &files)?;
        dependencies.push(dependency);
    }
    let sysroot = checked(Command::new("rustc").args(["--print", "sysroot"]))?;
    let sysroot = PathBuf::from(
        String::from_utf8(sysroot)
            .map_err(|e| e.to_string())?
            .trim(),
    );
    let rust_version = version
        .lines()
        .find_map(|line| line.strip_prefix("release: "))
        .ok_or("rustc omitted release version")?;
    let rust_commit = version
        .lines()
        .find_map(|line| line.strip_prefix("commit-hash: "))
        .ok_or("rustc omitted commit hash")?;
    let mut rust_standard = Dependency {
        ecosystem: "Rust toolchain",
        name: "Rust standard library".into(),
        version: rust_version.into(),
        license: "MIT OR Apache-2.0; see bundled copyright notices".into(),
        source: format!("https://github.com/rust-lang/rust/tree/{rust_commit}"),
        source_archive: format!("https://github.com/rust-lang/rust/archive/{rust_commit}.tar.gz"),
        notice_note: None,
        notice_sources: Vec::new(),
        files: Vec::new(),
    };
    let mut files: Vec<_> = [
        "LICENSE-MIT",
        "LICENSE-APACHE",
        "COPYRIGHT",
        "share/doc/rust/COPYRIGHT",
        "share/doc/rust/COPYRIGHT-library.html",
        "share/doc/COPYING.RUNTIME",
        "share/doc/COPYING3",
    ]
    .iter()
    .map(|path| sysroot.join(path))
    .filter(|path| path.is_file())
    .collect();
    let rust_licenses = sysroot.join("share/doc/rust/licenses");
    if rust_licenses.is_dir() {
        for file in fs::read_dir(rust_licenses).map_err(|e| e.to_string())? {
            let file = file.map_err(|e| e.to_string())?;
            if file.file_type().map_err(|e| e.to_string())?.is_file() {
                files.push(file.path());
            }
        }
    }
    rust_standard.files = copy_notices(&destination, &sysroot, &rust_standard, &files)?;
    dependencies.push(rust_standard);
    let go_environment = checked(Command::new("go").current_dir(&repository).args([
        "env",
        "-json",
        "GOROOT",
        "GOVERSION",
    ]))?;
    let go_environment: Value =
        serde_json::from_slice(&go_environment).map_err(|e| e.to_string())?;
    let go_root = PathBuf::from(string(&go_environment, "GOROOT")?);
    let go_version = string(&go_environment, "GOVERSION")?;
    let mut go_standard = Dependency {
        ecosystem: "Go toolchain",
        name: "Go standard library".into(),
        version: go_version.into(),
        license: "BSD-3-Clause; see bundled patent and contributor notices".into(),
        source: format!("https://github.com/golang/go/tree/{go_version}"),
        source_archive: format!("https://go.dev/dl/{go_version}.src.tar.gz"),
        notice_note: None,
        notice_sources: Vec::new(),
        files: Vec::new(),
    };
    let files: Vec<_> = ["LICENSE", "PATENTS", "AUTHORS", "CONTRIBUTORS"]
        .iter()
        .map(|path| go_root.join(path))
        .filter(|path| path.is_file())
        .collect();
    go_standard.files = copy_notices(&destination, &go_root, &go_standard, &files)?;
    dependencies.push(go_standard);
    dependencies.sort_by(|a, b| {
        (a.ecosystem, &a.name, &a.version).cmp(&(b.ecosystem, &b.name, &b.version))
    });
    let catalog =
        serde_json::json!({"schema_version": 1, "target": host, "dependencies": dependencies});
    fs::write(
        destination.join("catalog.json"),
        serde_json::to_vec_pretty(&catalog).map_err(|e| e.to_string())?,
    )
    .map_err(|e| format!("write license catalog: {e}"))?;
    fs::write(destination.join("README.md"), "# Third-party notices\n\nThis directory preserves license, copyright, and notice files from the upstream Rust and Go dependency sources used for this platform. See catalog.json for package versions, declared Rust license expressions, source locations, source archives, and the copied file paths. The project license is in ../LICENSE; dependency terms remain their own. This catalog may include build and test dependencies resolved with the application.\n")
        .map_err(|e| format!("write notice index: {e}"))?;
    println!(
        "Bundled notices for {} dependencies ({host})",
        dependencies.len()
    );
    Ok(())
}

fn string<'a>(value: &'a Value, field: &str) -> Result<&'a str, String> {
    value[field]
        .as_str()
        .ok_or_else(|| format!("dependency metadata omitted {field}"))
}

fn checked(command: &mut Command) -> Result<Vec<u8>, String> {
    let output = command
        .output()
        .map_err(|e| format!("read installed toolchain metadata: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "metadata command exited {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(output.stdout)
}

fn escape_go_module(value: &str) -> String {
    value
        .chars()
        .flat_map(|c| {
            if c.is_ascii_uppercase() {
                vec!['!', c.to_ascii_lowercase()]
            } else {
                vec![c]
            }
        })
        .collect()
}

fn license_files(root: &Path) -> Result<Vec<PathBuf>, String> {
    let mut directories = vec![(root.to_path_buf(), 0)];
    let mut files = Vec::new();
    while let Some((directory, depth)) = directories.pop() {
        for entry in fs::read_dir(&directory)
            .map_err(|e| format!("read dependency {}: {e}", directory.display()))?
        {
            let entry = entry.map_err(|e| format!("read dependency entry: {e}"))?;
            let kind = entry
                .file_type()
                .map_err(|e| format!("read dependency file type: {e}"))?;
            let name = entry.file_name().to_string_lossy().to_ascii_uppercase();
            if kind.is_symlink() {
                continue;
            }
            if kind.is_dir()
                && depth < 8
                && !matches!(name.as_str(), ".GIT" | "TARGET" | "NODE_MODULES")
            {
                directories.push((entry.path(), depth + 1));
            } else if kind.is_file()
                && ([
                    "LICENSE",
                    "LICENCE",
                    "COPYING",
                    "COPYRIGHT",
                    "NOTICE",
                    "AUTHORS",
                ]
                .iter()
                .any(|prefix| name.starts_with(prefix))
                    || name.contains("LICENSE")
                    || matches!(name.as_str(), "OFL.TXT" | "UFL.TXT")
                    || (name.ends_with(".TXT")
                        && entry.path().components().any(|part| {
                            part.as_os_str()
                                .to_string_lossy()
                                .eq_ignore_ascii_case("fonts")
                        })))
            {
                files.push(entry.path());
            }
        }
    }
    files.sort();
    Ok(files)
}

fn copy_notices(
    destination: &Path,
    root: &Path,
    dependency: &Dependency,
    files: &[PathBuf],
) -> Result<Vec<String>, String> {
    if files.is_empty() {
        return Err(format!(
            "{} {} has no packaged license/notice file in {}; inspect its source before shipping",
            dependency.name,
            dependency.version,
            root.display()
        ));
    }
    let identity = format!(
        "{}-{}-{}",
        dependency.ecosystem.to_ascii_lowercase(),
        dependency.name,
        dependency.version
    );
    let safe: String = identity
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
                c
            } else {
                '_'
            }
        })
        .collect();
    let digest = format!("{:x}", Sha256::digest(identity.as_bytes()));
    let directory = destination.join(format!("{safe}-{}", &digest[..8]));
    fs::create_dir(&directory).map_err(|e| format!("create dependency notice directory: {e}"))?;
    let mut copied = Vec::new();
    for (index, file) in files.iter().enumerate() {
        let metadata =
            fs::metadata(file).map_err(|e| format!("read notice {}: {e}", file.display()))?;
        if metadata.len() > 4 * 1024 * 1024 {
            return Err(format!(
                "notice {} exceeds 4 MiB; inspect it before shipping",
                file.display()
            ));
        }
        let relative = file
            .strip_prefix(root)
            .ok()
            .and_then(|p| p.to_str())
            .unwrap_or_else(|| {
                file.file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or("declared-license")
            });
        let safe_name: String = relative
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        let output = match file.strip_prefix(root) {
            Ok(relative)
                if relative
                    .components()
                    .all(|part| matches!(part, std::path::Component::Normal(_))) =>
            {
                directory.join(relative)
            }
            _ => directory.join(format!("{index:03}-{safe_name}")),
        };
        if let Some(parent) = output.parent() {
            fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        fs::copy(file, &output).map_err(|e| format!("copy notice {}: {e}", file.display()))?;
        copied.push(
            output
                .strip_prefix(destination)
                .map_err(|e| e.to_string())?
                .to_string_lossy()
                .replace('\\', "/"),
        );
    }
    Ok(copied)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn curated_notice_ledger_preserves_pinned_sources_and_bytes() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("data/third-party");
        let ledger: CuratedNotices =
            serde_json::from_slice(&fs::read(root.join("manifest.json")).unwrap()).unwrap();
        assert_eq!(ledger.schema_version, 1);
        let mut packages = BTreeSet::new();
        for package in ledger.crates {
            assert!(
                packages.insert((package.name, package.version)),
                "duplicate notice fallback"
            );
            assert_eq!(package.revision.len(), 40);
            assert!(!package.files.is_empty());
            for source in package.files {
                assert!(source.source_url.starts_with("https://"));
                assert!(Path::new(&source.path)
                    .components()
                    .all(|part| matches!(part, std::path::Component::Normal(_))));
                let bytes = fs::read(root.join(source.path)).unwrap();
                assert_eq!(format!("{:x}", Sha256::digest(&bytes)), source.sha256);
            }
        }
    }
}
