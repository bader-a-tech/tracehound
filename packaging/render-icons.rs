//! Dependency-free raster assets for native package launchers.
use std::{fs, path::Path};
fn crc(bytes: &[u8]) -> u32 {
    let mut crc = !0u32;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ if crc & 1 != 0 { 0xedb88320 } else { 0 };
        }
    }
    !crc
}
fn chunk(output: &mut Vec<u8>, kind: &[u8; 4], data: &[u8]) {
    output.extend((data.len() as u32).to_be_bytes());
    output.extend(kind);
    output.extend(data);
    let mut bytes = Vec::from(*kind);
    bytes.extend(data);
    output.extend(crc(&bytes).to_be_bytes());
}
fn circle(x: f64, y: f64, cx: f64, cy: f64, r: f64) -> bool {
    (x - cx).powi(2) + (y - cy).powi(2) <= r * r
}
fn icon(size: u32) -> Vec<u8> {
    let mut pixels = Vec::with_capacity((size * size * 4) as usize);
    for row in 0..size {
        for column in 0..size {
            let x = (column as f64 + 0.5) / size as f64;
            let y = (row as f64 + 0.5) / size as f64;
            let corner_x = (x - 0.5).abs() - 0.29;
            let corner_y = (y - 0.5).abs() - 0.29;
            let inside = corner_x.max(0.0).powi(2) + corner_y.max(0.0).powi(2) <= 0.19f64.powi(2);
            let mut color = if inside {
                [14, 28, 47, 255]
            } else {
                [0, 0, 0, 0]
            };
            if ((x - 0.5) / 0.23).powi(2) + ((y - 0.62) / 0.17).powi(2) <= 1.0
                || [(0.26, 0.4), (0.42, 0.29), (0.6, 0.3), (0.75, 0.43)]
                    .iter()
                    .any(|(cx, cy)| circle(x, y, *cx, *cy, 0.082))
            {
                color = [220, 236, 246, 255];
            }
            if (0.3..=0.7).contains(&x) && (y - 0.86).abs() < 0.013
                || [0.3, 0.5, 0.7]
                    .iter()
                    .any(|cx| circle(x, y, *cx, 0.86, 0.027))
            {
                color = [64, 207, 189, 255];
            }
            pixels.extend(color);
        }
    }
    pixels
}
fn png(size: u32) -> Vec<u8> {
    let pixels = icon(size);
    let mut raw = Vec::with_capacity(pixels.len() + size as usize);
    for row in pixels.chunks((size * 4) as usize) {
        raw.push(0);
        raw.extend(row);
    }
    let mut compressed = vec![0x78, 0x01];
    let blocks = raw.chunks(65535);
    let count = blocks.len();
    for (index, block) in blocks.enumerate() {
        compressed.push(u8::from(index + 1 == count));
        let len = block.len() as u16;
        compressed.extend(len.to_le_bytes());
        compressed.extend((!len).to_le_bytes());
        compressed.extend(block);
    }
    let (mut a, mut b) = (1u32, 0u32);
    for byte in &raw {
        a = (a + u32::from(*byte)) % 65521;
        b = (b + a) % 65521;
    }
    compressed.extend(((b << 16) | a).to_be_bytes());
    let mut output = vec![137, 80, 78, 71, 13, 10, 26, 10];
    let mut header = Vec::new();
    header.extend(size.to_be_bytes());
    header.extend(size.to_be_bytes());
    header.extend([8, 6, 0, 0, 0]);
    chunk(&mut output, b"IHDR", &header);
    chunk(&mut output, b"IDAT", &compressed);
    chunk(&mut output, b"IEND", &[]);
    output
}
fn main() {
    let destination = std::env::args_os()
        .nth(1)
        .expect("usage: render-icons OUTPUT_DIRECTORY");
    let destination = Path::new(&destination);
    fs::create_dir_all(destination).unwrap();
    fs::write(destination.join("tracehound.png"), png(1024)).unwrap();
    let png = png(256);
    let mut ico = vec![0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 1, 0, 32, 0];
    ico.extend((png.len() as u32).to_le_bytes());
    ico.extend(22u32.to_le_bytes());
    ico.extend(png);
    fs::write(destination.join("tracehound.ico"), ico).unwrap();
}
