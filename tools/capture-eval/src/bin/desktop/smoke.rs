//! Explicit CI-only native rendering checks. Normal startup never opens or
//! analyzes a capture automatically and never writes a screenshot.
use eframe::egui;
use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

#[derive(Default)]
pub struct Startup {
    pub capture: Option<PathBuf>,
    pub smoke: Option<Config>,
}
pub struct Config {
    pub case: Option<PathBuf>,
    pub output: Option<PathBuf>,
    pub timeout: Duration,
}
pub fn parse(args: impl IntoIterator<Item = OsString>) -> Result<Startup, String> {
    let mut args = args.into_iter();
    let mut capture = None;
    let mut case = None;
    let mut output = None;
    let mut basic = false;
    let mut exit = false;
    let mut timeout = 30u64;
    let mut timeout_set = false;
    let mut literal = false;
    while let Some(arg) = args.next() {
        if !literal && arg == "--" {
            literal = true;
            continue;
        }
        if !literal && arg == "--smoke-test" {
            basic = true;
            continue;
        }
        if !literal && arg == "--smoke-exit" {
            exit = true;
            continue;
        }
        if !literal
            && matches!(
                arg.to_str(),
                Some("--smoke-case" | "--smoke-output" | "--smoke-timeout")
            )
        {
            let value = args
                .next()
                .filter(|value| !value.is_empty())
                .ok_or_else(|| format!("{} requires a value", arg.to_string_lossy()))?;
            match arg.to_str() {
                Some("--smoke-case") => {
                    if case.replace(PathBuf::from(value)).is_some() {
                        return Err("--smoke-case was repeated".into());
                    }
                }
                Some("--smoke-output") => {
                    if output.replace(PathBuf::from(value)).is_some() {
                        return Err("--smoke-output was repeated".into());
                    }
                }
                _ => {
                    timeout_set = true;
                    timeout = value
                        .to_str()
                        .ok_or("smoke timeout must be an integer")?
                        .parse()
                        .map_err(|_| "smoke timeout must be an integer")?;
                    if !(1..=300).contains(&timeout) {
                        return Err("smoke timeout must be between 1 and 300 seconds".into());
                    }
                }
            }
        } else {
            if arg.is_empty() {
                return Err("startup capture path must not be empty".into());
            }
            if !literal && arg.to_string_lossy().starts_with('-') {
                return Err(format!("unknown option {}", arg.to_string_lossy()));
            }
            if capture.replace(PathBuf::from(arg)).is_some() {
                return Err("provide at most one startup capture path".into());
            }
        }
    }
    if case.is_some() != output.is_some() {
        return Err("--smoke-case and --smoke-output must be used together".into());
    }
    if case.is_some() && !exit {
        return Err("case screenshot mode requires --smoke-exit".into());
    }
    if case.is_none() && exit && !basic {
        return Err("--smoke-exit requires a smoke mode".into());
    }
    if capture.is_some() && case.is_some() {
        return Err("choose a startup capture or a smoke case".into());
    }
    let smoke = (basic || case.is_some()).then_some(Config {
        case,
        output,
        timeout: Duration::from_secs(timeout),
    });
    if timeout_set && smoke.is_none() {
        return Err("--smoke-timeout requires a smoke mode".into());
    }
    Ok(Startup { capture, smoke })
}

pub struct NativeSmoke {
    case: bool,
    output: Option<PathBuf>,
    timeout: Duration,
    started: Instant,
    ready_frames: usize,
    requested: bool,
    receiver: Option<mpsc::Receiver<Result<(), String>>>,
    outcome: Arc<AtomicI32>,
    finished: bool,
    writing: Arc<AtomicBool>,
    cancelled: Arc<AtomicBool>,
}
impl NativeSmoke {
    pub fn new(config: Config, outcome: Arc<AtomicI32>) -> Self {
        Self {
            case: config.case.is_some(),
            output: config.output,
            timeout: config.timeout,
            started: Instant::now(),
            ready_frames: 0,
            requested: false,
            receiver: None,
            outcome,
            finished: false,
            writing: Arc::new(AtomicBool::new(false)),
            cancelled: Arc::new(AtomicBool::new(false)),
        }
    }
    pub fn writing(&self) -> bool {
        self.writing.load(Ordering::Acquire)
    }
    pub fn advance(&mut self, desktop: &mut super::Desktop, ctx: &egui::Context) {
        if self.finished {
            return;
        }
        ctx.request_repaint_after(Duration::from_millis(20));
        if self.started.elapsed() >= self.timeout {
            self.cancelled.store(true, Ordering::Release);
            if self.writing() {
                desktop.closing = true;
                desktop.investigation.cancel();
                return;
            }
            self.finish(desktop, ctx, Err("Native GUI smoke test timed out.".into()));
            return;
        }
        if let Some(receiver) = &self.receiver {
            match receiver.try_recv() {
                Ok(result) => {
                    self.finish(desktop, ctx, result);
                    return;
                }
                Err(mpsc::TryRecvError::Disconnected) => {
                    self.finish(
                        desktop,
                        ctx,
                        Err("Native screenshot worker closed without a result.".into()),
                    );
                    return;
                }
                Err(mpsc::TryRecvError::Empty) => {}
            }
        }
        if self.requested {
            return;
        }
        if self.case {
            match desktop.investigation.smoke_ready() {
                Ok(true) => {}
                Ok(false) => {
                    self.ready_frames = 0;
                    return;
                }
                Err(error) => {
                    self.finish(desktop, ctx, Err(error));
                    return;
                }
            }
        }
        self.ready_frames += 1;
        if self.ready_frames < 3 {
            return;
        }
        self.requested = true;
        let (sender, receiver) = mpsc::channel();
        self.receiver = Some(receiver);
        let output = self.output.clone();
        let repaint = ctx.clone();
        let writing = Arc::clone(&self.writing);
        let cancelled = Arc::clone(&self.cancelled);
        ctx.request_screenshot(move |image| {
            writing.store(true, Ordering::Release);
            if cancelled.load(Ordering::Acquire) {
                writing.store(false, Ordering::Release);
                let _ = sender.send(Err("Native screenshot cancelled.".into()));
                repaint.request_repaint();
                return;
            }
            std::thread::spawn(move || {
                let result = save_image(&image, output.as_deref(), &|| {
                    cancelled.load(Ordering::Acquire)
                });
                writing.store(false, Ordering::Release);
                let _ = sender.send(result);
                repaint.request_repaint();
            });
        });
    }
    fn finish(
        &mut self,
        desktop: &mut super::Desktop,
        ctx: &egui::Context,
        result: Result<(), String>,
    ) {
        self.finished = true;
        match result {
            Ok(()) => {
                self.outcome.store(0, Ordering::Release);
            }
            Err(error) => {
                eprintln!("Tracehound GUI smoke test: {error}");
                desktop.error = Some(error);
                self.outcome.store(2, Ordering::Release);
            }
        }
        desktop.closing = true;
        desktop.investigation.cancel();
        if let Some(task) = &desktop.task {
            task.cancel();
        }
        if !desktop.busy() {
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
        }
    }
}

fn save_image(
    image: &egui::ColorImage,
    path: Option<&std::path::Path>,
    cancelled: &dyn Fn() -> bool,
) -> Result<(), String> {
    if cancelled() {
        return Err("Native screenshot cancelled.".into());
    }
    let [width, height] = image.size;
    if width < 32
        || height < 32
        || width > 8192
        || height > 8192
        || image.pixels.len() != width * height
    {
        return Err("Renderer returned an invalid screenshot size.".into());
    }
    if image
        .pixels
        .first()
        .is_none_or(|first| image.pixels.iter().all(|pixel| pixel == first))
    {
        return Err("Renderer returned a blank screenshot.".into());
    }
    let Some(path) = path else {
        return Ok(());
    };
    use image::ImageEncoder;
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|e| format!("Create new screenshot {}: {e}", path.display()))?;
    let result = (|| {
        let rgba: Vec<u8> = image
            .pixels
            .iter()
            .flat_map(|pixel| pixel.to_array())
            .collect();
        image::codecs::png::PngEncoder::new(&mut file)
            .write_image(
                &rgba,
                width as u32,
                height as u32,
                image::ExtendedColorType::Rgba8,
            )
            .map_err(|e| format!("Encode screenshot: {e}"))?;
        if cancelled() {
            return Err("Native screenshot cancelled.".into());
        }
        file.flush()
            .and_then(|()| file.sync_all())
            .map_err(|e| format!("Save screenshot: {e}"))
    })();
    drop(file);
    if result.is_err() {
        let _ = std::fs::remove_file(path);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn startup_capture_is_selection_only_and_smoke_arguments_are_explicit() {
        let parse = |args: &[&str]| parse(args.iter().map(OsString::from));
        let capture = parse(&["capture with spaces.pcapng"]).unwrap();
        assert!(capture.smoke.is_none());
        assert_eq!(
            capture.capture.unwrap(),
            PathBuf::from("capture with spaces.pcapng")
        );
        assert!(parse(&["--smoke-test"]).unwrap().smoke.is_some());
        assert!(parse(&[
            "--smoke-case",
            "case.db",
            "--smoke-output",
            "new.png",
            "--smoke-exit"
        ])
        .unwrap()
        .smoke
        .is_some());
        assert!(parse(&["--smoke-case", "case.db"]).is_err());
        assert!(parse(&["--smoke-output", "new.png"]).is_err());
        assert!(parse(&["--smoke-exit"]).is_err());
        assert!(parse(&["--smoke-test", "--smoke-timeout", "0"]).is_err());
    }
    #[test]
    fn smoke_requires_real_nonblank_native_pixels() {
        let image = egui::ColorImage::filled([64, 64], egui::Color32::BLACK);
        assert!(save_image(&image, None, &|| false).is_err());
        let mut image = image;
        image.pixels[10] = egui::Color32::WHITE;
        assert!(save_image(&image, None, &|| false).is_ok());
    }
}
