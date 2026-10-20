use image::codecs::gif::{GifDecoder, GifEncoder, Repeat};
use image::{imageops::FilterType, AnimationDecoder, Frame, ImageFormat, ImageReader};
use std::io::Cursor;
use std::path::PathBuf;

pub const UPLOAD_DIR: &str = "uploads";
pub const MAX_UPLOAD_BYTES: usize = 15 * 1024 * 1024; // pre-decode size on the wire
const MAX_PIXELS: u64 = 40_000_000; // ~40MP cap before we even decode — guards against decompression bombs
const MAX_DIMENSION: u32 = 2500; // downscale-only cap; also blunts sensor-noise/camera fingerprinting
const MAX_FRAMES: usize = 600; // guards against GIF frame-count decompression bombs
const JPEG_QUALITY: u8 = 85;

#[derive(Debug)]
pub enum UploadError {
    TooLarge,
    UnsupportedFormat,
    AnimatedWebpUnsupported,
    DimensionsTooLarge,
    TooManyFrames,
    Decode,
    Io,
}

impl std::fmt::Display for UploadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let msg = match self {
            UploadError::TooLarge => "file too large",
            UploadError::UnsupportedFormat => "unsupported image format (jpeg, png, webp, gif only)",
            UploadError::AnimatedWebpUnsupported => {
                "animated webp is not supported — re-export as animated gif"
            }
            UploadError::DimensionsTooLarge => "image dimensions too large",
            UploadError::TooManyFrames => "too many animation frames",
            UploadError::Decode => "could not decode image",
            UploadError::Io => "could not save image",
        };
        write!(f, "{msg}")
    }
}

/// Sniffs the real format from file bytes (never trusts client-declared
/// content-type), decodes, strips metadata by fully re-encoding from raw
/// pixels (every frame, for animations), downscales oversized images, and
/// writes the result under `UPLOAD_DIR` with a random filename. Returns
/// that filename.
///
/// This is CPU-bound and should be called from `spawn_blocking`.
pub fn process_and_save(bytes: &[u8], random_name: &str) -> Result<String, UploadError> {
    if bytes.len() > MAX_UPLOAD_BYTES {
        return Err(UploadError::TooLarge);
    }

    let format = image::guess_format(bytes).map_err(|_| UploadError::UnsupportedFormat)?;

    let (buf, ext) = match format {
        ImageFormat::Gif => (process_gif(bytes)?, "gif"),
        ImageFormat::Jpeg => (process_static(bytes, format, ImageFormat::Jpeg)?, "jpg"),
        ImageFormat::Png => (process_static(bytes, format, ImageFormat::Png)?, "png"),
        ImageFormat::WebP => {
            if webp_is_animated(bytes) {
                return Err(UploadError::AnimatedWebpUnsupported);
            }
            // WebP re-encoding support in `image` is lossless-only and
            // heavier to depend on; converting static webp to PNG keeps
            // the dependency surface small while still stripping metadata.
            (process_static(bytes, format, ImageFormat::Png)?, "png")
        }
        _ => return Err(UploadError::UnsupportedFormat),
    };

    std::fs::create_dir_all(UPLOAD_DIR).map_err(|_| UploadError::Io)?;
    let filename = format!("{random_name}.{ext}");
    let path: PathBuf = [UPLOAD_DIR, &filename].iter().collect();
    std::fs::write(&path, &buf).map_err(|_| UploadError::Io)?;

    Ok(filename)
}

/// Decode a single-frame image, downscale if oversized, re-encode into
/// `out_format` from raw pixels. The re-encode is what discards EXIF/XMP/
/// ICC-profile-adjacent metadata — nothing is copied from the source file.
fn process_static(bytes: &[u8], in_format: ImageFormat, out_format: ImageFormat) -> Result<Vec<u8>, UploadError> {
    check_header_dimensions(bytes)?;

    let img = image::load_from_memory_with_format(bytes, in_format).map_err(|_| UploadError::Decode)?;
    let img = downscale_if_needed(img);

    let mut buf = Vec::new();
    match out_format {
        ImageFormat::Jpeg => {
            let mut encoder = image::codecs::jpeg::JpegEncoder::new_with_quality(&mut buf, JPEG_QUALITY);
            encoder.encode_image(&img).map_err(|_| UploadError::Decode)?;
        }
        _ => {
            img.write_to(&mut Cursor::new(&mut buf), ImageFormat::Png)
                .map_err(|_| UploadError::Decode)?;
        }
    }
    Ok(buf)
}

/// Decode every frame of an animated GIF and re-encode them into a fresh
/// GIF. Frames are processed one at a time (not collected into memory
/// first), so peak memory is bounded by a single frame, not the whole
/// animation. Re-encoding drops GIF comment/application extensions (the
/// only metadata GIF can carry) along with anything else not representable
/// as plain frame pixels + delay.
fn process_gif(bytes: &[u8]) -> Result<Vec<u8>, UploadError> {
    check_header_dimensions(bytes)?;

    let decoder = GifDecoder::new(Cursor::new(bytes)).map_err(|_| UploadError::Decode)?;
    let frames = decoder.into_frames();

    let mut out_buf = Vec::new();
    let mut frame_count = 0usize;
    {
        let mut encoder = GifEncoder::new(&mut out_buf);
        encoder
            .set_repeat(Repeat::Infinite)
            .map_err(|_| UploadError::Decode)?;

        for frame_result in frames {
            frame_count += 1;
            if frame_count > MAX_FRAMES {
                return Err(UploadError::TooManyFrames);
            }
            let frame = frame_result.map_err(|_| UploadError::Decode)?;
            let delay = frame.delay();
            let buffer = frame.into_buffer();
            let (w, h) = buffer.dimensions();
            if (w as u64) * (h as u64) > MAX_PIXELS {
                return Err(UploadError::DimensionsTooLarge);
            }

            let resized = downscale_if_needed(image::DynamicImage::ImageRgba8(buffer));
            let new_frame = Frame::from_parts(resized.to_rgba8(), 0, 0, delay);
            encoder.encode_frame(new_frame).map_err(|_| UploadError::Decode)?;
        }
    } // encoder dropped here, flushing into out_buf

    if frame_count == 0 {
        return Err(UploadError::Decode);
    }
    Ok(out_buf)
}

fn downscale_if_needed(img: image::DynamicImage) -> image::DynamicImage {
    if img.width() > MAX_DIMENSION || img.height() > MAX_DIMENSION {
        img.resize(MAX_DIMENSION, MAX_DIMENSION, FilterType::Triangle)
    } else {
        img
    }
}

/// Reads just the header to reject absurd pixel counts before allocating a
/// full decode buffer (guards against decompression-bomb-style images).
fn check_header_dimensions(bytes: &[u8]) -> Result<(), UploadError> {
    let (w, h) = ImageReader::new(Cursor::new(bytes))
        .with_guessed_format()
        .map_err(|_| UploadError::Decode)?
        .into_dimensions()
        .map_err(|_| UploadError::Decode)?;
    if (w as u64) * (h as u64) > MAX_PIXELS {
        return Err(UploadError::DimensionsTooLarge);
    }
    Ok(())
}

/// WebP animation support isn't implemented by this version of the `image`
/// crate's decoder, so rather than silently mis-decoding an animated webp
/// (producing a confusing single frame), we detect it via its RIFF `ANIM`
/// chunk and reject it with a clear message.
fn webp_is_animated(bytes: &[u8]) -> bool {
    bytes.windows(4).any(|w| w == b"ANIM")
}

#[derive(serde::Serialize)]
pub struct MediaFile {
    pub name: String,
    pub size_kb: u64,
}

/// Lists uploaded files, newest first. Filenames are always our own
/// generated `<random hex>.<ext>` form (never the client's), so there's
/// nothing here that can carry identifying info from an uploader.
pub fn list_media() -> Vec<MediaFile> {
    let mut entries: Vec<(String, u64, std::time::SystemTime)> = match std::fs::read_dir(UPLOAD_DIR) {
        Ok(rd) => rd
            .filter_map(|e| e.ok())
            .filter_map(|e| {
                let meta = e.metadata().ok()?;
                if !meta.is_file() {
                    return None;
                }
                let name = e.file_name().to_string_lossy().to_string();
                if name == ".gitkeep" {
                    return None;
                }
                let modified = meta.modified().unwrap_or(std::time::SystemTime::UNIX_EPOCH);
                Some((name, meta.len() / 1024, modified))
            })
            .collect(),
        Err(_) => return Vec::new(),
    };
    entries.sort_by(|a, b| b.2.cmp(&a.2));
    entries.into_iter().map(|(name, size_kb, _)| MediaFile { name, size_kb }).collect()
}

/// Deletes an uploaded file by name. Rejects anything that isn't a bare
/// filename (no `/`, no `..`) so a crafted name can't escape `UPLOAD_DIR`.
pub fn delete_media(name: &str) -> Result<(), ()> {
    if name.is_empty() || name.contains('/') || name.contains('\\') || name.contains("..") {
        return Err(());
    }
    let path: PathBuf = [UPLOAD_DIR, name].iter().collect();
    std::fs::remove_file(path).map_err(|_| ())
}
