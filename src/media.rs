use rusqlite::{params, Connection, OptionalExtension};
use serde::Serialize;
use std::path::{Path, PathBuf};

const VIDEO_EXTS: &[&str] = &["mp4", "mkv", "avi", "mov", "webm", "m4v"];

#[derive(Debug, Clone)]
pub struct Movie {
    pub slug: String,
    pub title: String,
    pub year: String,
    pub video_rel: String,
    pub poster_rel: String,
}

/// Parses a Jellyfin-style folder name like "10 Cloverfield Lane (2016)
/// [tmdb-333371]" into (title, year). Falls back to using the whole name as
/// the title if no trailing " (YYYY)" is found.
fn parse_folder_name(name: &str) -> (String, String) {
    let name = match name.find(" [") {
        Some(idx) => &name[..idx],
        None => name,
    };
    if let (Some(open), Some(close)) = (name.rfind('('), name.rfind(')')) {
        if close > open {
            let year = &name[open + 1..close];
            if year.len() == 4 && year.chars().all(|c| c.is_ascii_digit()) {
                return (name[..open].trim().to_string(), year.to_string());
            }
        }
    }
    (name.trim().to_string(), String::new())
}

fn slugify(s: &str) -> String {
    let mut out = String::new();
    let mut prev_dash = false;
    for c in s.chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c.to_ascii_lowercase());
            prev_dash = false;
        } else if !prev_dash {
            out.push('-');
            prev_dash = true;
        }
    }
    out.trim_matches('-').to_string()
}

/// Picks the largest file with a known video extension in `dir` — Jellyfin
/// movie folders also contain subtitles, a `trailers/` folder, and artwork,
/// so "the biggest video-looking file" is a safer heuristic than "any video
/// file in here."
fn find_video(dir: &Path) -> Option<PathBuf> {
    std::fs::read_dir(dir)
        .ok()?
        .filter_map(Result::ok)
        .filter(|e| e.file_type().map(|t| t.is_file()).unwrap_or(false))
        .filter(|e| {
            e.path()
                .extension()
                .and_then(|x| x.to_str())
                .map(|ext| VIDEO_EXTS.contains(&ext.to_ascii_lowercase().as_str()))
                .unwrap_or(false)
        })
        .max_by_key(|e| e.metadata().map(|m| m.len()).unwrap_or(0))
        .map(|e| e.path())
}

fn find_first(dir: &Path, names: &[&str]) -> Option<PathBuf> {
    names.iter().map(|n| dir.join(n)).find(|p| p.is_file())
}

/// Scans a Jellyfin-style `Movies/` library directory (each title in its own
/// subfolder, e.g. `Title (Year) [tmdb-id]/Title.mp4` + `folder.jpg`) and
/// returns one `Movie` per subfolder that contains a recognizable video
/// file. Doesn't touch the database — callers persist the result via
/// `replace_movies`. Pure filesystem reads, no network access.
pub fn scan_movies(movies_dir: &Path) -> Vec<Movie> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(movies_dir) else {
        return out;
    };
    for entry in entries.filter_map(Result::ok) {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let Some(video) = find_video(&path) else {
            continue;
        };
        let folder_name = entry.file_name().to_string_lossy().into_owned();
        let (title, year) = parse_folder_name(&folder_name);
        let slug = if year.is_empty() {
            slugify(&title)
        } else {
            format!("{}-{}", slugify(&title), year)
        };
        let poster = find_first(&path, &["folder.jpg", "poster.jpg", "cover.jpg"]);
        let rel = |p: &Path| -> String {
            p.strip_prefix(movies_dir)
                .unwrap_or(p)
                .to_string_lossy()
                .replace('\\', "/")
        };
        out.push(Movie {
            slug,
            title,
            year,
            video_rel: rel(&video),
            poster_rel: poster.as_deref().map(rel).unwrap_or_default(),
        });
    }
    out.sort_by(|a, b| a.title.cmp(&b.title));
    out
}

/// Percent-encodes a `/`-separated relative path for use in a URL, leaving
/// the separators alone — folder/file names here come straight from
/// Jellyfin's naming convention and routinely contain spaces, parens and
/// apostrophes.
pub fn encode_path(rel: &str) -> String {
    rel.split('/').map(encode_segment).collect::<Vec<_>>().join("/")
}

fn encode_segment(seg: &str) -> String {
    let mut out = String::new();
    for b in seg.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

// ---- DB ----

pub fn init_schema(conn: &Connection) {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS media_movies (
            id         INTEGER PRIMARY KEY,
            slug       TEXT NOT NULL UNIQUE,
            title      TEXT NOT NULL,
            year       TEXT NOT NULL DEFAULT '',
            video_rel  TEXT NOT NULL,
            poster_rel TEXT NOT NULL DEFAULT ''
        );",
    )
    .expect("init media schema");
}

/// Replaces the whole catalog with the result of a fresh scan — simplest
/// correct way to reflect renames/deletions on disk, and cheap enough (a few
/// thousand rows at most) to not need incremental diffing.
pub fn replace_movies(conn: &Connection, movies: &[Movie]) {
    conn.execute("DELETE FROM media_movies", []).expect("clear movies");
    for m in movies {
        conn.execute(
            "INSERT INTO media_movies (slug, title, year, video_rel, poster_rel)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![m.slug, m.title, m.year, m.video_rel, m.poster_rel],
        )
        .expect("insert movie");
    }
}

#[derive(Serialize, Clone)]
pub struct MovieRow {
    pub slug: String,
    pub title: String,
    pub year: String,
    pub poster_url: String,
    pub video_url: String,
}

fn to_row(slug: String, title: String, year: String, poster_rel: String, video_rel: String) -> MovieRow {
    MovieRow {
        poster_url: if poster_rel.is_empty() {
            String::new()
        } else {
            format!("/library/movies/{}", encode_path(&poster_rel))
        },
        video_url: format!("/library/movies/{}", encode_path(&video_rel)),
        slug,
        title,
        year,
    }
}

pub fn list_movies(conn: &Connection) -> Vec<MovieRow> {
    let mut stmt = conn
        .prepare("SELECT slug, title, year, poster_rel, video_rel FROM media_movies ORDER BY title")
        .unwrap();
    stmt.query_map([], |r| Ok(to_row(r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)))
        .unwrap()
        .filter_map(Result::ok)
        .collect()
}

pub fn get_movie(conn: &Connection, slug: &str) -> Option<MovieRow> {
    conn.query_row(
        "SELECT slug, title, year, poster_rel, video_rel FROM media_movies WHERE slug = ?1",
        [slug],
        |r| Ok(to_row(r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
    )
    .optional()
    .expect("query movie")
}

pub fn movie_count(conn: &Connection) -> i64 {
    conn.query_row("SELECT COUNT(*) FROM media_movies", [], |r| r.get(0)).unwrap_or(0)
}
