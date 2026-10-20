use argon2::password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use hmac::{Hmac, Mac};
use rand::RngCore;
use rusqlite::{Connection, OptionalExtension};
use sha2::Sha256;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use time::{Duration, OffsetDateTime};

pub const SESSION_COOKIE: &str = "session";
const SESSION_LIFETIME_HOURS: i64 = 12;

// Per-username (not per-IP) login throttle: every connection to a Tor
// hidden service looks like it comes from 127.0.0.1, so IP-based limits
// are meaningless and would only be a reason to start logging real client
// info, which this app deliberately never does.
const MAX_FAILED_ATTEMPTS: i64 = 5;
const LOCKOUT_SECONDS: i64 = 300;

pub fn hash_password(password: &str) -> String {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .expect("hash password")
        .to_string()
}

pub fn verify_password(password: &str, hash: &str) -> bool {
    let parsed = match PasswordHash::new(hash) {
        Ok(h) => h,
        Err(_) => return false,
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

pub fn new_token() -> String {
    random_hex(32)
}

/// Random hex string of `n_bytes` bytes of entropy (2*n_bytes hex chars).
/// Used for session tokens and for upload filenames — the latter so
/// uploaded filenames never leak the original filename chosen by whoever
/// is posting (which can itself carry identifying information).
pub fn random_hex(n_bytes: usize) -> String {
    let mut bytes = vec![0u8; n_bytes];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

pub fn create_session(conn: &Connection, user_id: i64) -> String {
    let token = new_token();
    let expires = OffsetDateTime::now_utc() + Duration::hours(SESSION_LIFETIME_HOURS);
    conn.execute(
        "INSERT INTO sessions (token, user_id, expires_at) VALUES (?1, ?2, ?3)",
        rusqlite::params![token, user_id, expires.unix_timestamp()],
    )
    .expect("insert session");
    token
}

pub fn user_id_for_session(conn: &Connection, token: &str) -> Option<i64> {
    let now = OffsetDateTime::now_utc().unix_timestamp();
    conn.query_row(
        "SELECT user_id FROM sessions WHERE token = ?1 AND expires_at > ?2",
        rusqlite::params![token, now],
        |row| row.get(0),
    )
    .optional()
    .expect("query session")
}

pub fn destroy_session(conn: &Connection, token: &str) {
    conn.execute("DELETE FROM sessions WHERE token = ?1", [token])
        .expect("delete session");
}

/// Sweeps expired session rows. `user_id_for_session` already refuses
/// expired tokens on its own, so this is just table hygiene — run
/// periodically from a background task, not on the request hot path.
pub fn cleanup_expired_sessions(conn: &Connection) {
    let now = OffsetDateTime::now_utc().unix_timestamp();
    conn.execute("DELETE FROM sessions WHERE expires_at <= ?1", [now])
        .expect("cleanup sessions");
}

pub fn find_user_by_username(conn: &Connection, username: &str) -> Option<(i64, String)> {
    conn.query_row(
        "SELECT id, password_hash FROM users WHERE username = ?1",
        [username],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )
    .optional()
    .expect("query user")
}

pub fn password_hash_for_id(conn: &Connection, user_id: i64) -> Option<String> {
    conn.query_row(
        "SELECT password_hash FROM users WHERE id = ?1",
        [user_id],
        |row| row.get(0),
    )
    .optional()
    .expect("query user")
}

pub fn update_password(conn: &Connection, user_id: i64, new_hash: &str) {
    conn.execute(
        "UPDATE users SET password_hash = ?1 WHERE id = ?2",
        rusqlite::params![new_hash, user_id],
    )
    .expect("update password");
}

// ---- login throttle (per-username) ----

/// Returns `Some(seconds_remaining)` if this username is currently locked out.
pub fn locked_for(conn: &Connection, username: &str) -> Option<i64> {
    let locked_until: Option<i64> = conn
        .query_row(
            "SELECT locked_until FROM login_throttle WHERE username = ?1",
            [username],
            |row| row.get(0),
        )
        .optional()
        .expect("query login_throttle");
    let now = OffsetDateTime::now_utc().unix_timestamp();
    match locked_until {
        Some(until) if until > now => Some(until - now),
        _ => None,
    }
}

pub fn record_failed_login(conn: &Connection, username: &str) {
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let failed_count: i64 = conn
        .query_row(
            "SELECT failed_count FROM login_throttle WHERE username = ?1",
            [username],
            |row| row.get(0),
        )
        .optional()
        .expect("query login_throttle")
        .unwrap_or(0)
        + 1;
    let locked_until = if failed_count >= MAX_FAILED_ATTEMPTS { now + LOCKOUT_SECONDS } else { 0 };
    conn.execute(
        "INSERT INTO login_throttle (username, failed_count, locked_until) VALUES (?1, ?2, ?3)
         ON CONFLICT(username) DO UPDATE SET failed_count = ?2, locked_until = ?3",
        rusqlite::params![username, failed_count, locked_until],
    )
    .expect("upsert login_throttle");
}

pub fn record_successful_login(conn: &Connection, username: &str) {
    conn.execute("DELETE FROM login_throttle WHERE username = ?1", [username])
        .expect("clear login_throttle");
}

// ---- CSRF ----
// Synchronizer-token pattern, but stateless: the token is HMAC(secret,
// session_token) rather than a separate DB column, so it's derivable
// wherever we already have the session cookie and invalidated automatically
// whenever the session is (expiry, logout).

const CSRF_SECRET_FILE: &str = "csrf_secret.key";

pub fn load_or_create_csrf_secret(dir: &str) -> [u8; 32] {
    let path = format!("{}/{}", dir, CSRF_SECRET_FILE);
    if let Ok(bytes) = std::fs::read(&path) {
        if bytes.len() == 32 {
            let mut secret = [0u8; 32];
            secret.copy_from_slice(&bytes);
            return secret;
        }
    }
    let mut secret = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut secret);
    let mut f = std::fs::File::create(&path).expect("create csrf secret file");
    f.write_all(&secret).expect("write csrf secret");
    f.set_permissions(std::fs::Permissions::from_mode(0o600)).ok();
    secret
}

pub fn csrf_token(secret: &[u8; 32], session_token: &str) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("hmac key");
    mac.update(session_token.as_bytes());
    let result = mac.finalize().into_bytes();
    result.iter().map(|b| format!("{:02x}", b)).collect()
}

pub fn constant_time_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.bytes().zip(b.bytes()) {
        diff |= x ^ y;
    }
    diff == 0
}
