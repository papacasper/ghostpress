mod auth;
mod db;
mod uploads;

use axum::{
    extract::{DefaultBodyLimit, Multipart, Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
    Form, Router,
};
use rusqlite::params;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tera::{Context, Tera};
use time::OffsetDateTime;
use tower_cookies::{Cookie, CookieManagerLayer, Cookies};
use tower_http::catch_panic::CatchPanicLayer;
use tower_http::services::ServeDir;

const DEFAULT_SITE_NAME: &str = "ghostpress";
const DB_PATH: &str = "cms.db";
const DEFAULT_BIND_ADDR: &str = "127.0.0.1:8899"; // loopback only — pair with a Tor HiddenServiceDir
const DEFAULT_POSTS_PER_PAGE: i64 = 10;
const DEFAULT_THEME: &str = "default";

/// Lists the `.html` files directly inside `dir` (non-recursive — both
/// `templates/` and each `themes/<name>/` are flat).
fn html_files_in(dir: &str) -> Vec<std::path::PathBuf> {
    std::fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("read directory '{dir}': {e}"))
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|ext| ext == "html"))
        .collect()
}

/// Builds one `Tera` per subdirectory of `themes/` — each theme owns the
/// public-facing templates (base/index/post/page/tag/404) plus the shared
/// admin templates in `templates/` (identical across all themes, so the
/// admin UI never changes when a theme is switched). Everything has to be
/// registered in one `add_template_files` call so Tera can resolve
/// `{% extends "base.html" %}` in the shared templates against the theme's
/// own base.html — building them as two separate `Tera` instances and
/// merging afterwards fails, because the shared templates can't validate
/// their inheritance chain standalone.
fn load_themes() -> std::collections::HashMap<String, Tera> {
    let shared_paths = html_files_in("templates");
    let mut themes = std::collections::HashMap::new();
    let entries = std::fs::read_dir("themes").expect("read themes directory");
    for entry in entries.filter_map(Result::ok) {
        if !entry.path().is_dir() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        let theme_paths = html_files_in(&format!("themes/{name}"));
        let files: Vec<(std::path::PathBuf, Option<String>)> = shared_paths
            .iter()
            .chain(theme_paths.iter())
            .map(|p| {
                let file_name = p.file_name().unwrap().to_string_lossy().into_owned();
                (p.clone(), Some(file_name))
            })
            .collect();
        let mut tera = Tera::default();
        tera.add_template_files(files).unwrap_or_else(|e| panic!("load theme '{name}': {e}"));
        themes.insert(name, tera);
    }
    assert!(
        themes.contains_key(DEFAULT_THEME),
        "themes/{DEFAULT_THEME}/ must exist"
    );
    themes
}

/// Reads an env var and parses it, falling back to `default` if unset or
/// unparseable. Lets a migrated/relocated instance tune a few knobs
/// (bind port, page size) without a rebuild.
fn env_or<T: std::str::FromStr>(key: &str, default: T) -> T {
    std::env::var(key).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

struct AppState {
    db: db::Db,
    themes: std::collections::HashMap<String, Tera>,
    csrf_secret: [u8; 32],
    posts_per_page: i64,
    /// Generated once at startup if no admin account exists yet; required
    /// to submit `/setup`, so reaching the URL first isn't enough to claim
    /// the account — you also need whatever printed this to stdout on boot
    /// (the operator's own console, not a network-reachable channel).
    /// `None` once an account already exists; irrelevant from then on since
    /// `/setup` 404s unconditionally in that case.
    setup_token: Option<String>,
}

#[derive(Serialize, Clone)]
struct PostRow {
    id: i64,
    slug: String,
    title: String,
    body_md: String,
    body_html: String,
    published: bool,
    created_at: String,
}

fn render_markdown(md: &str) -> String {
    let parser = pulldown_cmark::Parser::new(md);
    let mut unsafe_html = String::new();
    pulldown_cmark::html::push_html(&mut unsafe_html, parser);
    ammonia::clean(&unsafe_html)
}

fn current_user(state: &AppState, cookies: &Cookies) -> Option<i64> {
    let token = cookies.get(auth::SESSION_COOKIE)?;
    let conn = state.db.0.lock().unwrap();
    auth::user_id_for_session(&conn, token.value())
}

fn require_auth(state: &AppState, cookies: &Cookies) -> Result<i64, Redirect> {
    current_user(state, cookies).ok_or_else(|| Redirect::to("/admin/login"))
}

/// Picks the `Tera` for the site's currently configured theme (falling back
/// to the default theme if the setting names one that no longer exists on
/// disk, e.g. after a theme folder was removed).
fn active_tera(state: &AppState) -> &Tera {
    let name = {
        let conn = state.db.0.lock().unwrap();
        db::get_setting(&conn, "theme", DEFAULT_THEME)
    };
    state
        .themes
        .get(&name)
        .unwrap_or_else(|| state.themes.get(DEFAULT_THEME).expect("default theme always loaded"))
}

fn render(tera: &Tera, name: &str, ctx: &Context) -> Html<String> {
    match tera.render(name, ctx) {
        Ok(body) => Html(body),
        Err(e) => Html(format!("<pre>template error: {e}</pre>")),
    }
}

fn not_found(state: &AppState, cookies: &Cookies) -> Response {
    let logged_in = current_user(state, cookies).is_some();
    let ctx = base_ctx(state, cookies, logged_in);
    (StatusCode::NOT_FOUND, render(active_tera(&state), "404.html", &ctx)).into_response()
}

/// Builds the context every page needs: the (runtime-configurable) site
/// name, login state, and — for logged-in requests — a CSRF token derived
/// from the session cookie (see `auth::csrf_token`). Locks the DB briefly
/// to read the site name; callers must not already hold the DB lock when
/// calling this (std::sync::Mutex is not reentrant).
fn base_ctx(state: &AppState, cookies: &Cookies, logged_in: bool) -> Context {
    let mut ctx = Context::new();
    let (name, custom_css, header_html, body_html, footer_html) = {
        let conn = state.db.0.lock().unwrap();
        (
            db::get_setting(&conn, "site_name", DEFAULT_SITE_NAME),
            db::get_setting(&conn, "custom_css", ""),
            db::get_setting(&conn, "custom_header_html", ""),
            db::get_setting(&conn, "custom_body_html", ""),
            db::get_setting(&conn, "custom_footer_html", ""),
        )
    };
    ctx.insert("site_name", &name);
    ctx.insert("custom_css", &custom_css);
    // Sanitized at save time (see settings_submit) with the same ammonia
    // pass used on post/page markdown, so this is safe to render raw here
    // even though it's admin-supplied HTML — it still can't carry <script>
    // or event-handler attributes, preserving the zero-JS guarantee.
    ctx.insert("custom_header_html", &header_html);
    ctx.insert("custom_body_html", &body_html);
    ctx.insert("custom_footer_html", &footer_html);
    ctx.insert("logged_in", &logged_in);
    if logged_in {
        if let Some(cookie) = cookies.get(auth::SESSION_COOKIE) {
            ctx.insert("csrf_token", &auth::csrf_token(&state.csrf_secret, cookie.value()));
        }
    }
    ctx
}

/// Verifies a submitted CSRF token against the one derived from the
/// caller's session cookie. Used on every state-changing admin POST.
fn verify_csrf(state: &AppState, cookies: &Cookies, submitted: &str) -> bool {
    match cookies.get(auth::SESSION_COOKIE) {
        Some(cookie) => {
            let expected = auth::csrf_token(&state.csrf_secret, cookie.value());
            auth::constant_time_eq(&expected, submitted)
        }
        None => false,
    }
}

#[derive(Deserialize)]
struct CsrfOnly {
    csrf_token: String,
}

// ---- public routes ----

#[derive(Deserialize)]
struct PageQuery {
    page: Option<i64>,
}

async fn index(State(state): State<Arc<AppState>>, cookies: Cookies, Query(q): Query<PageQuery>) -> Html<String> {
    let per_page = state.posts_per_page;
    let page = q.page.unwrap_or(1).max(1);
    let offset = (page - 1) * per_page;
    // Fetch one extra row to know whether a next page exists, without a
    // separate COUNT(*) query.
    let mut posts: Vec<PostRow> = {
        let conn = state.db.0.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT id, slug, title, body_md, body_html, published, created_at FROM posts WHERE published = 1 ORDER BY created_at DESC LIMIT ?1 OFFSET ?2")
            .unwrap();
        stmt.query_map(params![per_page + 1, offset], row_to_post)
            .unwrap()
            .filter_map(Result::ok)
            .collect()
    };
    let has_next = posts.len() as i64 > per_page;
    posts.truncate(per_page as usize);

    let logged_in = current_user(&state, &cookies).is_some();
    let mut ctx = base_ctx(&state, &cookies, logged_in);
    ctx.insert("posts", &posts);
    ctx.insert("page", &page);
    ctx.insert("has_next", &has_next);
    ctx.insert("has_prev", &(page > 1));
    render(active_tera(&state), "index.html", &ctx)
}

fn row_to_post(row: &rusqlite::Row) -> rusqlite::Result<PostRow> {
    Ok(PostRow {
        id: row.get(0)?,
        slug: row.get(1)?,
        title: row.get(2)?,
        body_md: row.get(3)?,
        body_html: row.get(4)?,
        published: row.get::<_, i64>(5)? != 0,
        created_at: row.get(6)?,
    })
}

async fn show_post(
    State(state): State<Arc<AppState>>,
    cookies: Cookies,
    Path(slug): Path<String>,
) -> Response {
    let (post, tags): (Option<PostRow>, Vec<String>) = {
        let conn = state.db.0.lock().unwrap();
        let post: Option<PostRow> = conn
            .query_row(
                "SELECT id, slug, title, body_md, body_html, published, created_at FROM posts WHERE slug = ?1",
                [&slug],
                row_to_post,
            )
            .ok();
        let tags = post.as_ref().map(|p| db::tags_for_post(&conn, p.id)).unwrap_or_default();
        (post, tags)
    };
    let logged_in = current_user(&state, &cookies).is_some();
    match post {
        Some(p) if p.published || logged_in => {
            let mut ctx = base_ctx(&state, &cookies, logged_in);
            ctx.insert("post", &p);
            ctx.insert("tags", &tags);
            render(active_tera(&state), "post.html", &ctx).into_response()
        }
        _ => not_found(&state, &cookies),
    }
}

async fn show_page(
    State(state): State<Arc<AppState>>,
    cookies: Cookies,
    Path(slug): Path<String>,
) -> Response {
    // `pages` has the same shape as `posts` (static content vs. dated
    // posts), so PostRow/row_to_post are reused as-is.
    let page: Option<PostRow> = {
        let conn = state.db.0.lock().unwrap();
        conn.query_row(
            "SELECT id, slug, title, body_md, body_html, published, created_at FROM pages WHERE slug = ?1",
            [&slug],
            row_to_post,
        )
        .ok()
    };
    let logged_in = current_user(&state, &cookies).is_some();
    match page {
        Some(p) if p.published || logged_in => {
            let mut ctx = base_ctx(&state, &cookies, logged_in);
            ctx.insert("page", &p);
            render(active_tera(&state), "page.html", &ctx).into_response()
        }
        _ => not_found(&state, &cookies),
    }
}

async fn show_tag(
    State(state): State<Arc<AppState>>,
    cookies: Cookies,
    Path(tag): Path<String>,
) -> Response {
    let logged_in = current_user(&state, &cookies).is_some();
    let posts: Vec<PostRow> = {
        let conn = state.db.0.lock().unwrap();
        let ids = db::post_ids_for_tag(&conn, &tag);
        ids.into_iter()
            .filter_map(|id| {
                conn.query_row(
                    "SELECT id, slug, title, body_md, body_html, published, created_at FROM posts WHERE id = ?1",
                    [id],
                    row_to_post,
                )
                .ok()
            })
            .filter(|p: &PostRow| p.published || logged_in)
            .collect()
    };
    let mut ctx = base_ctx(&state, &cookies, logged_in);
    ctx.insert("tag", &tag);
    ctx.insert("posts", &posts);
    render(active_tera(&state), "tag.html", &ctx).into_response()
}

async fn feed_xml(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let (posts, site_name, site_url_setting): (Vec<PostRow>, String, String) = {
        let conn = state.db.0.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT id, slug, title, body_md, body_html, published, created_at FROM posts WHERE published = 1 ORDER BY created_at DESC LIMIT 20")
            .unwrap();
        let posts = stmt.query_map([], row_to_post).unwrap().filter_map(Result::ok).collect();
        let name = db::get_setting(&conn, "site_name", DEFAULT_SITE_NAME);
        let url = db::get_setting(&conn, "site_url", "");
        (posts, name, url)
    };

    // Prefer the explicit `site_url` setting; otherwise fall back to this
    // request's Host header. Under a Tor hidden service, Host is the
    // server's own .onion address (public by design, not client info), so
    // this never touches anything client-identifying.
    let base = if !site_url_setting.is_empty() {
        site_url_setting.trim_end_matches('/').to_string()
    } else {
        let host = headers.get("host").and_then(|h| h.to_str().ok()).unwrap_or("");
        format!("http://{host}")
    };

    let mut items = String::new();
    for p in &posts {
        items.push_str(&format!(
            "<item><title>{}</title><link>{base}/post/{}</link><guid>{base}/post/{}</guid><pubDate>{}</pubDate><description>{}</description></item>",
            xml_escape(&p.title),
            xml_escape(&p.slug),
            xml_escape(&p.slug),
            xml_escape(&p.created_at),
            xml_escape(&p.body_html),
        ));
    }
    let body = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><rss version=\"2.0\"><channel><title>{}</title><link>{base}</link><description>{}</description>{items}</channel></rss>",
        xml_escape(&site_name),
        xml_escape(&site_name),
    );
    (
        [("content-type", "application/rss+xml; charset=utf-8")],
        body,
    )
        .into_response()
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

async fn healthz(State(state): State<Arc<AppState>>) -> Response {
    let ok = {
        let conn = state.db.0.lock().unwrap();
        conn.query_row("SELECT 1", [], |_| Ok(())).is_ok()
    };
    if ok {
        (StatusCode::OK, "ok").into_response()
    } else {
        (StatusCode::INTERNAL_SERVER_ERROR, "db unavailable").into_response()
    }
}

// ---- first-run setup (replaces needing CLI/SSH access to create the
// admin account — useful when the blog is moved to a fresh machine: copy
// the binary + templates, start it, and create the account from a browser
// instead of needing shell access on the new host) ----
//
// Only reachable while the `users` table is empty; the moment an account
// exists this 404s like any other unknown route, same as /admin does. This
// is the common "first visitor claims the admin account" pattern — create
// the account immediately after first boot, before the service is
// reachable from outside (e.g. before starting the Tor hidden service),
// since whoever reaches /setup first gets the account.

#[derive(Deserialize)]
struct SetupQuery {
    token: Option<String>,
}

async fn setup_page(
    State(state): State<Arc<AppState>>,
    cookies: Cookies,
    Query(q): Query<SetupQuery>,
) -> Response {
    let exists = {
        let conn = state.db.0.lock().unwrap();
        db::users_exist(&conn)
    };
    if exists {
        return not_found(&state, &cookies);
    }
    let mut ctx = base_ctx(&state, &cookies, false);
    // Convenience prefill only — the real check is on submit.
    ctx.insert("token_value", &q.token.unwrap_or_default());
    render(active_tera(&state), "setup.html", &ctx).into_response()
}

#[derive(Deserialize)]
struct SetupForm {
    username: String,
    password: String,
    confirm_password: String,
    token: String,
}

async fn setup_submit(
    State(state): State<Arc<AppState>>,
    cookies: Cookies,
    Form(form): Form<SetupForm>,
) -> Response {
    let conn = state.db.0.lock().unwrap();
    if db::users_exist(&conn) {
        drop(conn);
        return not_found(&state, &cookies);
    }
    let username = form.username.trim();
    let token_ok = state
        .setup_token
        .as_deref()
        .is_some_and(|expected| auth::constant_time_eq(expected, form.token.trim()));
    let error = if !token_ok {
        Some("invalid or missing setup token (check the server's stdout/logs at startup)")
    } else if username.is_empty() {
        Some("username is required")
    } else if form.password.len() < 8 {
        Some("password must be at least 8 characters")
    } else if form.password != form.confirm_password {
        Some("passwords do not match")
    } else {
        None
    };
    if let Some(e) = error {
        drop(conn);
        let mut ctx = base_ctx(&state, &cookies, false);
        ctx.insert("error", e);
        ctx.insert("token_value", &form.token);
        return render(active_tera(&state), "setup.html", &ctx).into_response();
    }
    let hash = auth::hash_password(&form.password);
    conn.execute(
        "INSERT INTO users (username, password_hash) VALUES (?1, ?2)",
        params![username, hash],
    )
    .expect("insert user");
    db::log_action(&conn, "setup", "initial admin account created");
    Redirect::to("/admin/login").into_response()
}

// ---- auth routes ----

#[derive(Deserialize)]
struct LoginForm {
    username: String,
    password: String,
}

async fn login_page(State(state): State<Arc<AppState>>, cookies: Cookies) -> Response {
    let exists = {
        let conn = state.db.0.lock().unwrap();
        db::users_exist(&conn)
    };
    if !exists {
        return Redirect::to("/setup").into_response();
    }
    let ctx = base_ctx(&state, &cookies, false);
    render(active_tera(&state), "login.html", &ctx).into_response()
}

async fn login_submit(
    State(state): State<Arc<AppState>>,
    cookies: Cookies,
    Form(form): Form<LoginForm>,
) -> Response {
    let conn = state.db.0.lock().unwrap();

    // Per-username throttle — see auth::locked_for for why this isn't per-IP.
    if let Some(remaining) = auth::locked_for(&conn, &form.username) {
        drop(conn);
        let mut ctx = base_ctx(&state, &cookies, false);
        ctx.insert("error", &format!("too many failed attempts — try again in {remaining} seconds"));
        return render(active_tera(&state), "login.html", &ctx).into_response();
    }

    let user = auth::find_user_by_username(&conn, &form.username);
    let ok = match &user {
        Some((_, hash)) => auth::verify_password(&form.password, hash),
        None => {
            // run a dummy hash to keep timing roughly constant whether or not the user exists
            let _ = auth::verify_password(&form.password, "$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHQ$aGFzaA");
            false
        }
    };
    if let (true, Some((uid, _))) = (ok, user) {
        auth::record_successful_login(&conn, &form.username);
        auth::cleanup_expired_sessions(&conn);
        db::log_action(&conn, "login", &format!("user '{}'", form.username));
        let token = auth::create_session(&conn, uid);
        let mut cookie = Cookie::new(auth::SESSION_COOKIE, token);
        cookie.set_path("/");
        cookie.set_http_only(true);
        cookie.set_same_site(tower_cookies::cookie::SameSite::Strict);
        cookies.add(cookie);
        Redirect::to("/admin").into_response()
    } else {
        auth::record_failed_login(&conn, &form.username);
        db::log_action(&conn, "login_failed", &format!("user '{}'", form.username));
        drop(conn);
        let mut ctx = base_ctx(&state, &cookies, false);
        ctx.insert("error", "invalid username or password");
        render(active_tera(&state), "login.html", &ctx).into_response()
    }
}

async fn logout(State(state): State<Arc<AppState>>, cookies: Cookies, Form(form): Form<CsrfOnly>) -> Response {
    if !verify_csrf(&state, &cookies, &form.csrf_token) {
        return (StatusCode::FORBIDDEN, "bad csrf token").into_response();
    }
    if let Some(cookie) = cookies.get(auth::SESSION_COOKIE) {
        let conn = state.db.0.lock().unwrap();
        auth::destroy_session(&conn, cookie.value());
        db::log_action(&conn, "logout", "");
    }
    cookies.remove(Cookie::new(auth::SESSION_COOKIE, ""));
    Redirect::to("/").into_response()
}

// ---- admin routes ----

async fn admin_dashboard(State(state): State<Arc<AppState>>, cookies: Cookies) -> Response {
    if require_auth(&state, &cookies).is_err() {
        return Redirect::to("/admin/login").into_response();
    }
    let (posts, pages): (Vec<PostRow>, Vec<PostRow>) = {
        let conn = state.db.0.lock().unwrap();
        let mut post_stmt = conn
            .prepare("SELECT id, slug, title, body_md, body_html, published, created_at FROM posts ORDER BY created_at DESC")
            .unwrap();
        let posts = post_stmt.query_map([], row_to_post).unwrap().filter_map(Result::ok).collect();
        let mut page_stmt = conn
            .prepare("SELECT id, slug, title, body_md, body_html, published, created_at FROM pages ORDER BY created_at DESC")
            .unwrap();
        let pages = page_stmt.query_map([], row_to_post).unwrap().filter_map(Result::ok).collect();
        (posts, pages)
    };
    let mut ctx = base_ctx(&state, &cookies, true);
    ctx.insert("posts", &posts);
    ctx.insert("pages", &pages);
    render(active_tera(&state), "admin_dashboard.html", &ctx).into_response()
}

async fn new_post_page(State(state): State<Arc<AppState>>, cookies: Cookies) -> Response {
    if require_auth(&state, &cookies).is_err() {
        return Redirect::to("/admin/login").into_response();
    }
    let mut ctx = base_ctx(&state, &cookies, true);
    ctx.insert("form_action", "/admin/new");
    render(active_tera(&state), "admin_edit.html", &ctx).into_response()
}

#[derive(Deserialize)]
struct PostForm {
    title: String,
    slug: String,
    body_md: String,
    published: Option<String>,
    tags: Option<String>,
    csrf_token: String,
    /// "preview" renders without saving; anything else (including absent,
    /// for pages which don't have a preview button) saves as before.
    action: Option<String>,
}

fn parse_tags(raw: &str) -> Vec<String> {
    raw.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect()
}

/// Builds the context for a preview render: same shape the edit template
/// expects from a real `post`/`page` row, but holding unsaved submitted
/// values plus freshly rendered markdown — nothing touches the DB.
fn preview_ctx(id: i64, form: &PostForm, created_at: &str) -> PostRow {
    PostRow {
        id,
        slug: form.slug.clone(),
        title: form.title.clone(),
        body_md: form.body_md.clone(),
        body_html: render_markdown(&form.body_md),
        published: form.published.is_some(),
        created_at: created_at.to_string(),
    }
}

async fn create_post(
    State(state): State<Arc<AppState>>,
    cookies: Cookies,
    Form(form): Form<PostForm>,
) -> Response {
    if require_auth(&state, &cookies).is_err() {
        return Redirect::to("/admin/login").into_response();
    }
    if !verify_csrf(&state, &cookies, &form.csrf_token) {
        return (StatusCode::FORBIDDEN, "bad csrf token").into_response();
    }

    if form.action.as_deref() == Some("preview") {
        let preview = preview_ctx(0, &form, "");
        let mut ctx = base_ctx(&state, &cookies, true);
        ctx.insert("form_action", "/admin/new");
        ctx.insert("post", &preview);
        ctx.insert("tags_value", &form.tags.clone().unwrap_or_default());
        ctx.insert("preview", &true);
        return render(active_tera(&state), "admin_edit.html", &ctx).into_response();
    }

    let body_html = render_markdown(&form.body_md);
    let now = OffsetDateTime::now_utc();
    let created_at = format!("{}-{:02}-{:02}", now.year(), u8::from(now.month()), now.day());
    let conn = state.db.0.lock().unwrap();
    let res = conn.execute(
        "INSERT INTO posts (slug, title, body_md, body_html, published, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![form.slug, form.title, form.body_md, body_html, form.published.is_some() as i64, created_at],
    );
    match res {
        Ok(_) => {
            let post_id = conn.last_insert_rowid();
            db::set_post_tags(&conn, post_id, &parse_tags(&form.tags.unwrap_or_default()));
            db::log_action(&conn, "post_created", &format!("'{}'", form.title));
            Redirect::to("/admin").into_response()
        }
        Err(_) => {
            let mut ctx = base_ctx(&state, &cookies, true);
            ctx.insert("form_action", "/admin/new");
            ctx.insert("error", "could not save post (slug already taken?)");
            render(active_tera(&state), "admin_edit.html", &ctx).into_response()
        }
    }
}

async fn edit_post_page(
    State(state): State<Arc<AppState>>,
    cookies: Cookies,
    Path(id): Path<i64>,
) -> Response {
    if require_auth(&state, &cookies).is_err() {
        return Redirect::to("/admin/login").into_response();
    }
    let post: Option<PostRow> = {
        let conn = state.db.0.lock().unwrap();
        conn.query_row(
            "SELECT id, slug, title, body_md, body_html, published, created_at FROM posts WHERE id = ?1",
            [id],
            row_to_post,
        )
        .ok()
    };
    match post {
        Some(p) => {
            let tags_value = {
                let conn = state.db.0.lock().unwrap();
                db::tags_for_post(&conn, p.id).join(", ")
            };
            let mut ctx = base_ctx(&state, &cookies, true);
            ctx.insert("form_action", &format!("/admin/edit/{id}"));
            ctx.insert("post", &p);
            ctx.insert("tags_value", &tags_value);
            render(active_tera(&state), "admin_edit.html", &ctx).into_response()
        }
        None => not_found(&state, &cookies),
    }
}

async fn update_post(
    State(state): State<Arc<AppState>>,
    cookies: Cookies,
    Path(id): Path<i64>,
    Form(form): Form<PostForm>,
) -> Response {
    if require_auth(&state, &cookies).is_err() {
        return Redirect::to("/admin/login").into_response();
    }
    if !verify_csrf(&state, &cookies, &form.csrf_token) {
        return (StatusCode::FORBIDDEN, "bad csrf token").into_response();
    }

    if form.action.as_deref() == Some("preview") {
        let preview = preview_ctx(id, &form, "");
        let mut ctx = base_ctx(&state, &cookies, true);
        ctx.insert("form_action", &format!("/admin/edit/{id}"));
        ctx.insert("post", &preview);
        ctx.insert("tags_value", &form.tags.clone().unwrap_or_default());
        ctx.insert("preview", &true);
        return render(active_tera(&state), "admin_edit.html", &ctx).into_response();
    }

    let body_html = render_markdown(&form.body_md);
    let conn = state.db.0.lock().unwrap();
    // Save the pre-update state as a revision before overwriting it.
    if let Ok((old_title, old_body)) = conn.query_row(
        "SELECT title, body_md FROM posts WHERE id = ?1",
        [id],
        |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
    ) {
        db::save_revision(&conn, id, &old_title, &old_body);
    }
    let res = conn.execute(
        "UPDATE posts SET slug = ?1, title = ?2, body_md = ?3, body_html = ?4, published = ?5 WHERE id = ?6",
        params![form.slug, form.title, form.body_md, body_html, form.published.is_some() as i64, id],
    );
    match res {
        Ok(_) => {
            db::set_post_tags(&conn, id, &parse_tags(&form.tags.unwrap_or_default()));
            db::log_action(&conn, "post_updated", &format!("'{}'", form.title));
            Redirect::to("/admin").into_response()
        }
        Err(_) => (StatusCode::BAD_REQUEST, "could not update post").into_response(),
    }
}

async fn delete_post(
    State(state): State<Arc<AppState>>,
    cookies: Cookies,
    Path(id): Path<i64>,
    Form(form): Form<CsrfOnly>,
) -> Response {
    if require_auth(&state, &cookies).is_err() {
        return Redirect::to("/admin/login").into_response();
    }
    if !verify_csrf(&state, &cookies, &form.csrf_token) {
        return (StatusCode::FORBIDDEN, "bad csrf token").into_response();
    }
    let conn = state.db.0.lock().unwrap();
    let _ = conn.execute("DELETE FROM posts WHERE id = ?1", [id]);
    db::log_action(&conn, "post_deleted", &format!("id {id}"));
    Redirect::to("/admin").into_response()
}

// ---- admin: post revision history ----

async fn revisions_page(
    State(state): State<Arc<AppState>>,
    cookies: Cookies,
    Path(post_id): Path<i64>,
) -> Response {
    if require_auth(&state, &cookies).is_err() {
        return Redirect::to("/admin/login").into_response();
    }
    let conn = state.db.0.lock().unwrap();
    let post: Option<PostRow> = conn
        .query_row(
            "SELECT id, slug, title, body_md, body_html, published, created_at FROM posts WHERE id = ?1",
            [post_id],
            row_to_post,
        )
        .ok();
    let Some(post) = post else {
        drop(conn);
        return not_found(&state, &cookies);
    };
    let revisions = db::list_revisions(&conn, post_id);
    drop(conn);
    let mut ctx = base_ctx(&state, &cookies, true);
    ctx.insert("post", &post);
    ctx.insert("revisions", &revisions);
    render(active_tera(&state), "admin_revisions.html", &ctx).into_response()
}

#[derive(Deserialize)]
struct RestoreRevisionForm {
    csrf_token: String,
}

async fn restore_revision(
    State(state): State<Arc<AppState>>,
    cookies: Cookies,
    Path(revision_id): Path<i64>,
    Form(form): Form<RestoreRevisionForm>,
) -> Response {
    if require_auth(&state, &cookies).is_err() {
        return Redirect::to("/admin/login").into_response();
    }
    if !verify_csrf(&state, &cookies, &form.csrf_token) {
        return (StatusCode::FORBIDDEN, "bad csrf token").into_response();
    }
    let conn = state.db.0.lock().unwrap();
    let Some((post_id, title, body_md)) = db::get_revision(&conn, revision_id) else {
        drop(conn);
        return not_found(&state, &cookies);
    };
    // Save current state as a revision too, so restoring is itself undoable.
    if let Ok((cur_title, cur_body)) = conn.query_row(
        "SELECT title, body_md FROM posts WHERE id = ?1",
        [post_id],
        |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
    ) {
        db::save_revision(&conn, post_id, &cur_title, &cur_body);
    }
    let body_html = render_markdown(&body_md);
    let _ = conn.execute(
        "UPDATE posts SET title = ?1, body_md = ?2, body_html = ?3 WHERE id = ?4",
        params![title, body_md, body_html, post_id],
    );
    db::log_action(&conn, "post_revision_restored", &format!("post id {post_id}"));
    Redirect::to(&format!("/admin/edit/{post_id}")).into_response()
}

// ---- admin: pages ----
// `pages` is for static content (About, Contact) vs. dated/listed `posts`.
// Table shape, form shape, and markdown handling are identical to posts,
// so PostForm/PostRow/row_to_post are reused — only the SQL table name and
// template names differ.

async fn new_page_page(State(state): State<Arc<AppState>>, cookies: Cookies) -> Response {
    if require_auth(&state, &cookies).is_err() {
        return Redirect::to("/admin/login").into_response();
    }
    let mut ctx = base_ctx(&state, &cookies, true);
    ctx.insert("form_action", "/admin/pages/new");
    render(active_tera(&state), "admin_page_edit.html", &ctx).into_response()
}

async fn create_page(
    State(state): State<Arc<AppState>>,
    cookies: Cookies,
    Form(form): Form<PostForm>,
) -> Response {
    if require_auth(&state, &cookies).is_err() {
        return Redirect::to("/admin/login").into_response();
    }
    if !verify_csrf(&state, &cookies, &form.csrf_token) {
        return (StatusCode::FORBIDDEN, "bad csrf token").into_response();
    }
    if form.action.as_deref() == Some("preview") {
        let preview = preview_ctx(0, &form, "");
        let mut ctx = base_ctx(&state, &cookies, true);
        ctx.insert("form_action", "/admin/pages/new");
        ctx.insert("page", &preview);
        ctx.insert("preview", &true);
        return render(active_tera(&state), "admin_page_edit.html", &ctx).into_response();
    }
    let body_html = render_markdown(&form.body_md);
    let now = OffsetDateTime::now_utc();
    let created_at = format!("{}-{:02}-{:02}", now.year(), u8::from(now.month()), now.day());
    let conn = state.db.0.lock().unwrap();
    let res = conn.execute(
        "INSERT INTO pages (slug, title, body_md, body_html, published, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![form.slug, form.title, form.body_md, body_html, form.published.is_some() as i64, created_at],
    );
    match res {
        Ok(_) => {
            db::log_action(&conn, "page_created", &format!("'{}'", form.title));
            Redirect::to("/admin").into_response()
        }
        Err(_) => {
            let mut ctx = base_ctx(&state, &cookies, true);
            ctx.insert("error", "could not save page (slug already taken?)");
            render(active_tera(&state), "admin_page_edit.html", &ctx).into_response()
        }
    }
}

async fn edit_page_page(
    State(state): State<Arc<AppState>>,
    cookies: Cookies,
    Path(id): Path<i64>,
) -> Response {
    if require_auth(&state, &cookies).is_err() {
        return Redirect::to("/admin/login").into_response();
    }
    let page: Option<PostRow> = {
        let conn = state.db.0.lock().unwrap();
        conn.query_row(
            "SELECT id, slug, title, body_md, body_html, published, created_at FROM pages WHERE id = ?1",
            [id],
            row_to_post,
        )
        .ok()
    };
    match page {
        Some(p) => {
            let mut ctx = base_ctx(&state, &cookies, true);
            ctx.insert("form_action", &format!("/admin/pages/edit/{id}"));
            ctx.insert("page", &p);
            render(active_tera(&state), "admin_page_edit.html", &ctx).into_response()
        }
        None => not_found(&state, &cookies),
    }
}

async fn update_page(
    State(state): State<Arc<AppState>>,
    cookies: Cookies,
    Path(id): Path<i64>,
    Form(form): Form<PostForm>,
) -> Response {
    if require_auth(&state, &cookies).is_err() {
        return Redirect::to("/admin/login").into_response();
    }
    if !verify_csrf(&state, &cookies, &form.csrf_token) {
        return (StatusCode::FORBIDDEN, "bad csrf token").into_response();
    }
    if form.action.as_deref() == Some("preview") {
        let preview = preview_ctx(id, &form, "");
        let mut ctx = base_ctx(&state, &cookies, true);
        ctx.insert("form_action", &format!("/admin/pages/edit/{id}"));
        ctx.insert("page", &preview);
        ctx.insert("preview", &true);
        return render(active_tera(&state), "admin_page_edit.html", &ctx).into_response();
    }
    let body_html = render_markdown(&form.body_md);
    let conn = state.db.0.lock().unwrap();
    let res = conn.execute(
        "UPDATE pages SET slug = ?1, title = ?2, body_md = ?3, body_html = ?4, published = ?5 WHERE id = ?6",
        params![form.slug, form.title, form.body_md, body_html, form.published.is_some() as i64, id],
    );
    match res {
        Ok(_) => {
            db::log_action(&conn, "page_updated", &format!("'{}'", form.title));
            Redirect::to("/admin").into_response()
        }
        Err(_) => (StatusCode::BAD_REQUEST, "could not update page").into_response(),
    }
}

async fn delete_page(
    State(state): State<Arc<AppState>>,
    cookies: Cookies,
    Path(id): Path<i64>,
    Form(form): Form<CsrfOnly>,
) -> Response {
    if require_auth(&state, &cookies).is_err() {
        return Redirect::to("/admin/login").into_response();
    }
    if !verify_csrf(&state, &cookies, &form.csrf_token) {
        return (StatusCode::FORBIDDEN, "bad csrf token").into_response();
    }
    let conn = state.db.0.lock().unwrap();
    let _ = conn.execute("DELETE FROM pages WHERE id = ?1", [id]);
    db::log_action(&conn, "page_deleted", &format!("id {id}"));
    Redirect::to("/admin").into_response()
}

// ---- uploads ----

async fn upload_page(State(state): State<Arc<AppState>>, cookies: Cookies) -> Response {
    if require_auth(&state, &cookies).is_err() {
        return Redirect::to("/admin/login").into_response();
    }
    let ctx = base_ctx(&state, &cookies, true);
    render(active_tera(&state), "admin_upload.html", &ctx).into_response()
}

async fn upload_submit(
    State(state): State<Arc<AppState>>,
    cookies: Cookies,
    mut multipart: Multipart,
) -> Response {
    if require_auth(&state, &cookies).is_err() {
        return Redirect::to("/admin/login").into_response();
    }

    let mut field_bytes: Option<Vec<u8>> = None;
    let mut csrf_token: Option<String> = None;
    loop {
        let next = multipart.next_field().await;
        let field = match next {
            Ok(Some(f)) => f,
            Ok(None) => break,
            Err(_) => return upload_error_page(&state, &cookies, "upload too large or malformed"),
        };
        match field.name() {
            Some("file") => match field.bytes().await {
                Ok(bytes) => field_bytes = Some(bytes.to_vec()),
                Err(_) => return upload_error_page(&state, &cookies, "upload too large or malformed"),
            },
            Some("csrf_token") => match field.text().await {
                Ok(t) => csrf_token = Some(t),
                Err(_) => return upload_error_page(&state, &cookies, "upload too large or malformed"),
            },
            _ => {}
        }
    }

    if !csrf_token.is_some_and(|t| verify_csrf(&state, &cookies, &t)) {
        return (StatusCode::FORBIDDEN, "bad csrf token").into_response();
    }

    let Some(bytes) = field_bytes else {
        return upload_error_page(&state, &cookies, "no file provided");
    };

    let random_name = auth::random_hex(16);
    let result = tokio::task::spawn_blocking(move || uploads::process_and_save(&bytes, &random_name))
        .await
        .expect("upload task panicked");

    match result {
        Ok(filename) => {
            let mut ctx = base_ctx(&state, &cookies, true);
            ctx.insert("markdown_snippet", &format!("![](/uploads/{filename})"));
            ctx.insert("uploaded_path", &format!("/uploads/{filename}"));
            render(active_tera(&state), "admin_upload.html", &ctx).into_response()
        }
        Err(e) => upload_error_page(&state, &cookies, &e.to_string()),
    }
}

fn upload_error_page(state: &AppState, cookies: &Cookies, msg: &str) -> Response {
    let mut ctx = base_ctx(state, cookies, true);
    ctx.insert("error", msg);
    render(active_tera(&state), "admin_upload.html", &ctx).into_response()
}

// ---- admin: media library ----

async fn media_library(State(state): State<Arc<AppState>>, cookies: Cookies) -> Response {
    if require_auth(&state, &cookies).is_err() {
        return Redirect::to("/admin/login").into_response();
    }
    let files = uploads::list_media();
    let mut ctx = base_ctx(&state, &cookies, true);
    ctx.insert("files", &files);
    render(active_tera(&state), "admin_media.html", &ctx).into_response()
}

#[derive(Deserialize)]
struct DeleteMediaForm {
    name: String,
    csrf_token: String,
}

async fn delete_media_route(
    State(state): State<Arc<AppState>>,
    cookies: Cookies,
    Form(form): Form<DeleteMediaForm>,
) -> Response {
    if require_auth(&state, &cookies).is_err() {
        return Redirect::to("/admin/login").into_response();
    }
    if !verify_csrf(&state, &cookies, &form.csrf_token) {
        return (StatusCode::FORBIDDEN, "bad csrf token").into_response();
    }
    let deleted = uploads::delete_media(&form.name).is_ok();
    if deleted {
        let conn = state.db.0.lock().unwrap();
        db::log_action(&conn, "media_deleted", &form.name);
    }
    Redirect::to("/admin/media").into_response()
}

// ---- admin: account / settings ----

async fn password_page(State(state): State<Arc<AppState>>, cookies: Cookies) -> Response {
    if require_auth(&state, &cookies).is_err() {
        return Redirect::to("/admin/login").into_response();
    }
    let ctx = base_ctx(&state, &cookies, true);
    render(active_tera(&state), "admin_password.html", &ctx).into_response()
}

#[derive(Deserialize)]
struct PasswordForm {
    current_password: String,
    new_password: String,
    confirm_password: String,
    csrf_token: String,
}

async fn password_submit(
    State(state): State<Arc<AppState>>,
    cookies: Cookies,
    Form(form): Form<PasswordForm>,
) -> Response {
    let Ok(uid) = require_auth(&state, &cookies) else {
        return Redirect::to("/admin/login").into_response();
    };
    if !verify_csrf(&state, &cookies, &form.csrf_token) {
        return (StatusCode::FORBIDDEN, "bad csrf token").into_response();
    }

    let error = {
        let conn = state.db.0.lock().unwrap();
        let current_hash = auth::password_hash_for_id(&conn, uid);
        match current_hash {
            Some(hash) if !auth::verify_password(&form.current_password, &hash) => {
                Some("current password is incorrect")
            }
            None => Some("current password is incorrect"),
            _ if form.new_password.len() < 8 => Some("new password must be at least 8 characters"),
            _ if form.new_password != form.confirm_password => Some("new passwords do not match"),
            _ => {
                let new_hash = auth::hash_password(&form.new_password);
                auth::update_password(&conn, uid, &new_hash);
                db::log_action(&conn, "password_changed", "");
                None
            }
        }
    };

    let mut ctx = base_ctx(&state, &cookies, true);
    match error {
        None => ctx.insert("success", "password updated"),
        Some(e) => ctx.insert("error", e),
    }
    render(active_tera(&state), "admin_password.html", &ctx).into_response()
}

#[derive(Deserialize)]
struct SettingsForm {
    site_name: String,
    site_url: Option<String>,
    theme: Option<String>,
    custom_css: Option<String>,
    custom_header_html: Option<String>,
    custom_body_html: Option<String>,
    custom_footer_html: Option<String>,
    csrf_token: String,
}

async fn settings_page(State(state): State<Arc<AppState>>, cookies: Cookies) -> Response {
    if require_auth(&state, &cookies).is_err() {
        return Redirect::to("/admin/login").into_response();
    }
    let (site_url, theme) = {
        let conn = state.db.0.lock().unwrap();
        (db::get_setting(&conn, "site_url", ""), db::get_setting(&conn, "theme", DEFAULT_THEME))
    };
    let mut available_themes: Vec<&String> = state.themes.keys().collect();
    available_themes.sort();
    let mut ctx = base_ctx(&state, &cookies, true);
    ctx.insert("site_url", &site_url);
    ctx.insert("theme", &theme);
    ctx.insert("available_themes", &available_themes);
    render(active_tera(&state), "admin_settings.html", &ctx).into_response()
}

async fn settings_submit(
    State(state): State<Arc<AppState>>,
    cookies: Cookies,
    Form(form): Form<SettingsForm>,
) -> Response {
    if require_auth(&state, &cookies).is_err() {
        return Redirect::to("/admin/login").into_response();
    }
    if !verify_csrf(&state, &cookies, &form.csrf_token) {
        return (StatusCode::FORBIDDEN, "bad csrf token").into_response();
    }
    let name = form.site_name.trim();
    let name = if name.is_empty() { DEFAULT_SITE_NAME } else { name };
    let site_url = form.site_url.unwrap_or_default().trim().to_string();
    // Falls back to whatever's already saved if the field is omitted or
    // doesn't match any loaded theme folder (e.g. a stale option from a
    // since-removed theme), rather than silently resetting it to default.
    let theme = {
        let conn = state.db.0.lock().unwrap();
        let current = db::get_setting(&conn, "theme", DEFAULT_THEME);
        match form.theme.as_deref().map(str::trim) {
            Some(t) if state.themes.contains_key(t) => t.to_string(),
            _ => current,
        }
    };
    let custom_css = form.custom_css.unwrap_or_default();
    // Sanitized the same way post/page bodies are, so admin-supplied markup
    // can never reintroduce <script> or inline event handlers — the no-JS
    // guarantee has to hold even against a careless admin paste, since it's
    // the whole reason this CMS is safe to run as a Tor hidden service.
    let header_html = ammonia::clean(&form.custom_header_html.unwrap_or_default());
    let body_html = ammonia::clean(&form.custom_body_html.unwrap_or_default());
    let footer_html = ammonia::clean(&form.custom_footer_html.unwrap_or_default());
    {
        let conn = state.db.0.lock().unwrap();
        db::set_setting(&conn, "site_name", name);
        db::set_setting(&conn, "site_url", &site_url);
        db::set_setting(&conn, "theme", &theme);
        db::set_setting(&conn, "custom_css", &custom_css);
        db::set_setting(&conn, "custom_header_html", &header_html);
        db::set_setting(&conn, "custom_body_html", &body_html);
        db::set_setting(&conn, "custom_footer_html", &footer_html);
        db::log_action(&conn, "settings_changed", "");
    }
    // base_ctx re-reads everything from the DB, so the saved values are
    // reflected immediately without a second insert here.
    let mut available_themes: Vec<&String> = state.themes.keys().collect();
    available_themes.sort();
    let mut ctx = base_ctx(&state, &cookies, true);
    ctx.insert("success", "settings saved");
    ctx.insert("site_url", &site_url);
    ctx.insert("theme", &theme);
    ctx.insert("available_themes", &available_themes);
    render(active_tera(&state), "admin_settings.html", &ctx).into_response()
}

// ---- admin: audit log ----

async fn audit_log_page(State(state): State<Arc<AppState>>, cookies: Cookies) -> Response {
    if require_auth(&state, &cookies).is_err() {
        return Redirect::to("/admin/login").into_response();
    }
    let entries = {
        let conn = state.db.0.lock().unwrap();
        db::recent_audit_log(&conn, 200)
    };
    let mut ctx = base_ctx(&state, &cookies, true);
    ctx.insert("entries", &entries);
    render(active_tera(&state), "admin_audit.html", &ctx).into_response()
}

// ---- server hardening ----

/// Strip response headers that leak the framework/runtime.
async fn strip_server_header(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let mut res = next.run(req).await;
    res.headers_mut().remove("server");
    res
}

fn add_security_headers(headers: &mut HeaderMap) {
    headers.insert("x-content-type-options", "nosniff".parse().unwrap());
    headers.insert("x-frame-options", "DENY".parse().unwrap());
    headers.insert(
        "content-security-policy",
        "default-src 'self'; style-src 'unsafe-inline'; img-src 'self'; script-src 'none'"
            .parse()
            .unwrap(),
    );
    headers.insert("referrer-policy", "no-referrer".parse().unwrap());
}

async fn security_headers_mw(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let mut res = next.run(req).await;
    add_security_headers(res.headers_mut());
    res
}

/// Converts a panicking handler into a generic 500 instead of a dropped
/// connection. Deliberately does not include the panic payload in the
/// response: it can contain local file paths or internal state, which is
/// host-fingerprinting information with no business reaching a client.
fn handle_panic(_err: Box<dyn std::any::Any + Send + 'static>) -> Response {
    let mut res = (StatusCode::INTERNAL_SERVER_ERROR, Html("<!doctype html><title>error</title><body>something went wrong</body>")).into_response();
    add_security_headers(res.headers_mut());
    res
}

async fn fallback_404(State(state): State<Arc<AppState>>, cookies: Cookies) -> Response {
    not_found(&state, &cookies)
}

/// Live SQLite backup (safe to run against a database that's currently
/// being written to, unlike `cp`) via sqlite's own backup API.
fn backup(dest: &str) {
    let db = db::open(DB_PATH);
    let conn = db.0.lock().unwrap();
    let mut dst = rusqlite::Connection::open(dest).expect("open backup destination");
    {
        let bk = rusqlite::backup::Backup::new(&conn, &mut dst).expect("init backup");
        bk.run_to_completion(5, std::time::Duration::from_millis(250), None)
            .expect("run backup");
    }
    println!("ok: backed up '{DB_PATH}' to '{dest}'");
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() == 3 && args[1] == "backup" {
        backup(&args[2]);
        return;
    }

    let themes = load_themes();
    let db = db::open(DB_PATH);
    let setup_token = {
        let conn = db.0.lock().unwrap();
        if db::users_exist(&conn) {
            None
        } else {
            let token = auth::random_hex(16);
            println!("no admin account yet — visit /setup?token={token} to create one");
            println!("(this token is only printed here, to this console, never logged or served)");
            Some(token)
        }
    };
    let state = Arc::new(AppState {
        db,
        themes,
        csrf_secret: auth::load_or_create_csrf_secret("."),
        posts_per_page: env_or("TORCMS_POSTS_PER_PAGE", DEFAULT_POSTS_PER_PAGE),
        setup_token,
    });

    std::fs::create_dir_all(uploads::UPLOAD_DIR).expect("create uploads dir");

    // Periodic hygiene sweep — session cleanup also happens opportunistically
    // on every successful login, this just catches sessions from users who
    // never come back.
    {
        let state = state.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600));
            loop {
                interval.tick().await;
                let conn = state.db.0.lock().unwrap();
                auth::cleanup_expired_sessions(&conn);
            }
        });
    }

    const FORM_BODY_LIMIT: usize = 512 * 1024; // posts/login — text only

    let upload_routes = Router::new()
        .route("/admin/upload", get(upload_page).post(upload_submit))
        .layer(DefaultBodyLimit::max(uploads::MAX_UPLOAD_BYTES))
        .with_state(state.clone());

    let app = Router::new()
        .route("/", get(index))
        .route("/post/:slug", get(show_post))
        .route("/p/:slug", get(show_page))
        .route("/tag/:name", get(show_tag))
        .route("/feed.xml", get(feed_xml))
        .route("/healthz", get(healthz))
        .route("/setup", get(setup_page).post(setup_submit))
        .route("/admin/login", get(login_page).post(login_submit))
        .route("/admin/logout", post(logout))
        .route("/admin", get(admin_dashboard))
        .route("/admin/new", get(new_post_page).post(create_post))
        .route("/admin/edit/:id", get(edit_post_page).post(update_post))
        .route("/admin/delete/:id", post(delete_post))
        .route("/admin/revisions/:post_id", get(revisions_page))
        .route("/admin/revisions/restore/:id", post(restore_revision))
        .route("/admin/pages/new", get(new_page_page).post(create_page))
        .route("/admin/pages/edit/:id", get(edit_page_page).post(update_page))
        .route("/admin/pages/delete/:id", post(delete_page))
        .route("/admin/media", get(media_library))
        .route("/admin/media/delete", post(delete_media_route))
        .route("/admin/password", get(password_page).post(password_submit))
        .route("/admin/settings", get(settings_page).post(settings_submit))
        .route("/admin/audit", get(audit_log_page))
        .fallback(fallback_404)
        .layer(DefaultBodyLimit::max(FORM_BODY_LIMIT))
        .with_state(state.clone())
        .merge(upload_routes)
        .nest_service("/uploads", ServeDir::new(uploads::UPLOAD_DIR))
        .layer(axum::middleware::from_fn(security_headers_mw))
        .layer(axum::middleware::from_fn(strip_server_header))
        .layer(CatchPanicLayer::custom(handle_panic))
        .layer(CookieManagerLayer::new());

    let bind_addr: String = std::env::var("TORCMS_BIND_ADDR").unwrap_or_else(|_| DEFAULT_BIND_ADDR.to_string());
    let listener = tokio::net::TcpListener::bind(&bind_addr).await.expect("bind");
    println!("listening on {bind_addr} (loopback only)");
    axum::serve(listener, app).await.expect("serve");
}
