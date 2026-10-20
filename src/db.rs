use rusqlite::{Connection, OptionalExtension};
use std::sync::Mutex;

pub struct Db(pub Mutex<Connection>);

pub fn open(path: &str) -> Db {
    let conn = Connection::open(path).expect("open sqlite db");
    conn.execute_batch(
        "
        PRAGMA journal_mode = WAL;
        PRAGMA foreign_keys = ON;

        CREATE TABLE IF NOT EXISTS users (
            id            INTEGER PRIMARY KEY,
            username      TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS posts (
            id         INTEGER PRIMARY KEY,
            slug       TEXT NOT NULL UNIQUE,
            title      TEXT NOT NULL,
            body_md    TEXT NOT NULL,
            body_html TEXT NOT NULL,
            published  INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS pages (
            id         INTEGER PRIMARY KEY,
            slug       TEXT NOT NULL UNIQUE,
            title      TEXT NOT NULL,
            body_md    TEXT NOT NULL,
            body_html TEXT NOT NULL,
            published  INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS sessions (
            token      TEXT PRIMARY KEY,
            user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            expires_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS settings (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );

        -- Keyed by username, not IP: every connection to a Tor hidden
        -- service arrives from 127.0.0.1, so per-IP throttling would be a
        -- no-op (and worse, a reason to start logging real client info).
        CREATE TABLE IF NOT EXISTS login_throttle (
            username     TEXT PRIMARY KEY,
            failed_count INTEGER NOT NULL DEFAULT 0,
            locked_until INTEGER NOT NULL DEFAULT 0
        );

        -- Local-only admin-action trail (no client-identifying info, ever —
        -- just what happened and when). Useful forensics if the single
        -- admin account is ever compromised.
        CREATE TABLE IF NOT EXISTS audit_log (
            id         INTEGER PRIMARY KEY,
            action     TEXT NOT NULL,
            detail     TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS post_revisions (
            id         INTEGER PRIMARY KEY,
            post_id    INTEGER NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
            title      TEXT NOT NULL,
            body_md    TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS tags (
            id   INTEGER PRIMARY KEY,
            name TEXT NOT NULL UNIQUE
        );

        CREATE TABLE IF NOT EXISTS post_tags (
            post_id INTEGER NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
            tag_id  INTEGER NOT NULL REFERENCES tags(id) ON DELETE CASCADE,
            PRIMARY KEY (post_id, tag_id)
        );
        ",
    )
    .expect("init schema");
    Db(Mutex::new(conn))
}

pub fn users_exist(conn: &Connection) -> bool {
    conn.query_row("SELECT 1 FROM users LIMIT 1", [], |_| Ok(()))
        .optional()
        .expect("query users")
        .is_some()
}

// ---- audit log ----

pub fn log_action(conn: &Connection, action: &str, detail: &str) {
    conn.execute(
        "INSERT INTO audit_log (action, detail, created_at) VALUES (?1, ?2, datetime('now'))",
        rusqlite::params![action, detail],
    )
    .expect("log action");
}

pub fn recent_audit_log(conn: &Connection, limit: i64) -> Vec<(String, String, String)> {
    let mut stmt = conn
        .prepare("SELECT action, detail, created_at FROM audit_log ORDER BY id DESC LIMIT ?1")
        .unwrap();
    stmt.query_map([limit], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .unwrap()
        .filter_map(Result::ok)
        .collect()
}

// ---- post revisions ----
// A revision is saved from the *pre-update* state right before an edit is
// applied, so the history is "what used to be live", capped at the last 10
// per post to keep the table bounded.

pub fn save_revision(conn: &Connection, post_id: i64, title: &str, body_md: &str) {
    conn.execute(
        "INSERT INTO post_revisions (post_id, title, body_md, created_at) VALUES (?1, ?2, ?3, datetime('now'))",
        rusqlite::params![post_id, title, body_md],
    )
    .expect("insert revision");
    conn.execute(
        "DELETE FROM post_revisions WHERE post_id = ?1 AND id NOT IN (
            SELECT id FROM post_revisions WHERE post_id = ?1 ORDER BY id DESC LIMIT 10
        )",
        [post_id],
    )
    .expect("trim revisions");
}

pub fn list_revisions(conn: &Connection, post_id: i64) -> Vec<(i64, String, String)> {
    let mut stmt = conn
        .prepare("SELECT id, title, created_at FROM post_revisions WHERE post_id = ?1 ORDER BY id DESC")
        .unwrap();
    stmt.query_map([post_id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .unwrap()
        .filter_map(Result::ok)
        .collect()
}

/// Returns `(post_id, title, body_md)` for a given revision id.
pub fn get_revision(conn: &Connection, id: i64) -> Option<(i64, String, String)> {
    conn.query_row(
        "SELECT post_id, title, body_md FROM post_revisions WHERE id = ?1",
        [id],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    )
    .optional()
    .expect("query revision")
}

// ---- tags (posts only — static pages don't need them) ----

pub fn set_post_tags(conn: &Connection, post_id: i64, tag_names: &[String]) {
    conn.execute("DELETE FROM post_tags WHERE post_id = ?1", [post_id])
        .expect("clear tags");
    for raw in tag_names {
        let name = raw.trim();
        if name.is_empty() {
            continue;
        }
        conn.execute(
            "INSERT INTO tags (name) VALUES (?1) ON CONFLICT(name) DO NOTHING",
            [name],
        )
        .expect("upsert tag");
        let tag_id: i64 = conn
            .query_row("SELECT id FROM tags WHERE name = ?1", [name], |r| r.get(0))
            .expect("get tag id");
        conn.execute(
            "INSERT OR IGNORE INTO post_tags (post_id, tag_id) VALUES (?1, ?2)",
            rusqlite::params![post_id, tag_id],
        )
        .expect("link tag");
    }
}

pub fn tags_for_post(conn: &Connection, post_id: i64) -> Vec<String> {
    let mut stmt = conn
        .prepare("SELECT t.name FROM tags t JOIN post_tags pt ON pt.tag_id = t.id WHERE pt.post_id = ?1 ORDER BY t.name")
        .unwrap();
    stmt.query_map([post_id], |r| r.get(0)).unwrap().filter_map(Result::ok).collect()
}

pub fn post_ids_for_tag(conn: &Connection, tag: &str) -> Vec<i64> {
    let mut stmt = conn
        .prepare("SELECT pt.post_id FROM post_tags pt JOIN tags t ON t.id = pt.tag_id WHERE t.name = ?1")
        .unwrap();
    stmt.query_map([tag], |r| r.get(0)).unwrap().filter_map(Result::ok).collect()
}

pub fn get_setting(conn: &Connection, key: &str, default: &str) -> String {
    conn.query_row("SELECT value FROM settings WHERE key = ?1", [key], |r| r.get(0))
        .unwrap_or_else(|_| default.to_string())
}

pub fn set_setting(conn: &Connection, key: &str, value: &str) {
    conn.execute(
        "INSERT INTO settings (key, value) VALUES (?1, ?2)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        rusqlite::params![key, value],
    )
    .expect("set setting");
}
