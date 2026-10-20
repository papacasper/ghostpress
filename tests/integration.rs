//! Black-box integration tests: each test spawns the real compiled binary
//! against an isolated temp directory (own `cms.db`, own port) and drives it
//! over plain HTTP, the same way the manual curl-based testing during
//! development did. Dev-only `ureq` dependency, never linked into the
//! shipped binary (see Cargo.toml).

use std::io::{BufRead, BufReader};
use std::net::TcpListener;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

struct TestServer {
    child: Child,
    base: String,
    stdout_lines: mpsc::Receiver<String>,
    _dir: tempfile::TempDir,
}

/// An agent configured not to follow redirects, so a 303 response can be
/// asserted on directly instead of transparently chasing it.
fn no_redirect_agent() -> ureq::Agent {
    ureq::AgentBuilder::new().redirects(0).build()
}

fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    listener.local_addr().unwrap().port()
}

impl TestServer {
    /// Starts a fresh instance with no admin account yet, in its own temp
    /// dir and on its own port, and waits for it to answer `/healthz`.
    fn start() -> Self {
        Self::start_with_env(&[])
    }

    fn start_with_env(extra_env: &[(&str, &str)]) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        // The binary loads templates via a cwd-relative glob ("templates/**/*.html"),
        // so give the isolated test directory a symlink to the real one.
        let templates_src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("templates");
        std::os::unix::fs::symlink(&templates_src, dir.path().join("templates"))
            .expect("symlink templates dir");
        let port = free_port();
        let bind = format!("127.0.0.1:{port}");
        let bin = env!("CARGO_BIN_EXE_tor-cms");

        let mut cmd = Command::new(bin);
        cmd.current_dir(dir.path())
            .env("TORCMS_BIND_ADDR", &bind)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for (k, v) in extra_env {
            cmd.env(k, v);
        }
        let mut child = cmd.spawn().expect("spawn tor-cms binary");

        let stdout = child.stdout.take().expect("capture stdout");
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                let _ = tx.send(line);
            }
        });

        let base = format!("http://{bind}");
        let srv = TestServer { child, base, stdout_lines: rx, _dir: dir };
        srv.wait_healthy();
        srv
    }

    fn wait_healthy(&self) {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Ok(resp) = ureq::get(&format!("{}/healthz", self.base)).call() {
                if resp.status() == 200 {
                    return;
                }
            }
            if Instant::now() > deadline {
                panic!("server did not become healthy in time");
            }
            thread::sleep(Duration::from_millis(50));
        }
    }

    /// Reads stdout lines (with a timeout) until one contains `token=`,
    /// returning the token value. Startup always prints this when no
    /// admin account exists yet.
    fn setup_token(&self) -> String {
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if let Ok(line) = self.stdout_lines.recv_timeout(Duration::from_millis(200)) {
                if let Some(idx) = line.find("token=") {
                    let rest = &line[idx + "token=".len()..];
                    let value = rest.split_whitespace().next().unwrap_or("");
                    return value.to_string();
                }
            }
        }
        panic!("setup token never appeared on stdout");
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Pulls `value="..."` out of `<input ... name="{field}" ... value="...">`.
/// Good enough for our own templates' fixed attribute order; not a general
/// HTML parser.
fn extract_input_value(html: &str, field: &str) -> String {
    let marker = format!("name=\"{field}\"");
    let start = html.find(&marker).unwrap_or_else(|| panic!("field '{field}' not found in html"));
    let after = &html[start..];
    let value_marker = "value=\"";
    let vstart = after.find(value_marker).expect("value attr") + value_marker.len();
    let vend = after[vstart..].find('"').expect("closing quote");
    after[vstart..vstart + vend].to_string()
}

/// ureq treats any 4xx/5xx as `Err`; this unwraps either variant into the
/// underlying `Response` so callers can assert on `.status()` directly.
fn any_status(result: Result<ureq::Response, ureq::Error>) -> ureq::Response {
    match result {
        Ok(r) => r,
        Err(ureq::Error::Status(_, r)) => r,
        Err(e) => panic!("transport error: {e}"),
    }
}

fn extract_session_cookie(resp: &ureq::Response) -> String {
    for h in resp.headers_names() {
        if h.eq_ignore_ascii_case("set-cookie") {
            for v in resp.all("Set-Cookie") {
                if let Some(rest) = v.strip_prefix("session=") {
                    let value = rest.split(';').next().unwrap();
                    return format!("session={value}");
                }
            }
        }
    }
    panic!("no session cookie in response");
}

/// Creates the admin account via `/setup` and returns (base_url, session_cookie).
fn setup_and_login(srv: &TestServer, username: &str, password: &str) -> String {
    let token = srv.setup_token();
    let agent = no_redirect_agent();
    let resp = agent
        .post(&format!("{}/setup", srv.base))
        .send_form(&[
            ("token", token.as_str()),
            ("username", username),
            ("password", password),
            ("confirm_password", password),
        ])
        .expect("setup request");
    assert_eq!(resp.status(), 303, "setup should redirect on success");

    let resp = agent
        .post(&format!("{}/admin/login", srv.base))
        .send_form(&[("username", username), ("password", password)])
        .expect("login request");
    assert_eq!(resp.status(), 303, "login should redirect on success");
    extract_session_cookie(&resp)
}

fn get_csrf_token(srv: &TestServer, cookie: &str, path: &str) -> String {
    let body = ureq::get(&format!("{}{}", srv.base, path))
        .set("Cookie", cookie)
        .call()
        .expect("authenticated GET")
        .into_string()
        .unwrap();
    extract_input_value(&body, "csrf_token")
}

#[test]
fn healthz_ok() {
    let srv = TestServer::start();
    let resp = ureq::get(&format!("{}/healthz", srv.base)).call().unwrap();
    assert_eq!(resp.status(), 200);
}

#[test]
fn login_redirects_to_setup_when_no_admin_exists() {
    let srv = TestServer::start();
    let resp = no_redirect_agent()
        .get(&format!("{}/admin/login", srv.base))
        .call()
        .unwrap();
    assert_eq!(resp.status(), 303);
    assert_eq!(resp.header("Location").unwrap(), "/setup");
}

#[test]
fn setup_requires_the_correct_token() {
    let srv = TestServer::start();
    let token = srv.setup_token();

    // Missing token is rejected.
    let resp = ureq::post(&format!("{}/setup", srv.base))
        .send_form(&[
            ("token", ""),
            ("username", "admin"),
            ("password", "supersecret1"),
            ("confirm_password", "supersecret1"),
        ])
        .unwrap();
    assert!(resp.into_string().unwrap().contains("invalid or missing setup token"));

    // Wrong token is rejected.
    let resp = ureq::post(&format!("{}/setup", srv.base))
        .send_form(&[
            ("token", "not-the-real-token"),
            ("username", "admin"),
            ("password", "supersecret1"),
            ("confirm_password", "supersecret1"),
        ])
        .unwrap();
    assert!(resp.into_string().unwrap().contains("invalid or missing setup token"));

    // Correct token succeeds.
    let resp = no_redirect_agent()
        .post(&format!("{}/setup", srv.base))
        .send_form(&[
            ("token", token.as_str()),
            ("username", "admin"),
            ("password", "supersecret1"),
            ("confirm_password", "supersecret1"),
        ])
        .unwrap();
    assert_eq!(resp.status(), 303);

    // And the route is permanently closed afterward, token or not.
    let status = ureq::get(&format!("{}/setup?token={token}", srv.base))
        .call()
        .map(|r| r.status())
        .unwrap_or_else(|e| e.into_response().unwrap().status());
    assert_eq!(status, 404);
}

#[test]
fn csrf_is_enforced_on_state_changing_requests() {
    let srv = TestServer::start();
    let cookie = setup_and_login(&srv, "admin", "supersecret1");
    let real_csrf = get_csrf_token(&srv, &cookie, "/admin/settings");

    // Missing/garbage CSRF token -> rejected.
    let resp = any_status(
        ureq::post(&format!("{}/admin/settings", srv.base))
            .set("Cookie", &cookie)
            .send_form(&[("site_name", "hacked"), ("site_url", ""), ("csrf_token", "garbage")]),
    );
    assert_eq!(resp.status(), 403);

    // Correct CSRF token -> accepted.
    let resp = ureq::post(&format!("{}/admin/settings", srv.base))
        .set("Cookie", &cookie)
        .send_form(&[("site_name", "My Blog"), ("site_url", ""), ("csrf_token", &real_csrf)])
        .unwrap();
    assert_eq!(resp.status(), 200);
}

#[test]
fn login_lockout_is_per_username_not_per_ip() {
    let srv = TestServer::start();
    let _cookie = setup_and_login(&srv, "admin", "supersecret1");

    for _ in 0..5 {
        ureq::post(&format!("{}/admin/login", srv.base))
            .send_form(&[("username", "admin"), ("password", "wrong-password")])
            .ok();
    }

    // Even the correct password is now rejected while locked out.
    let resp = no_redirect_agent()
        .post(&format!("{}/admin/login", srv.base))
        .send_form(&[("username", "admin"), ("password", "supersecret1")])
        .unwrap();
    assert_ne!(resp.status(), 303, "login should not succeed while locked out");
}

#[test]
fn post_lifecycle_tags_preview_and_revisions() {
    let srv = TestServer::start();
    let agent = no_redirect_agent();
    let cookie = setup_and_login(&srv, "admin", "supersecret1");
    let csrf = get_csrf_token(&srv, &cookie, "/admin/new");

    // Create a published, tagged post.
    let resp = agent
        .post(&format!("{}/admin/new", srv.base))
        .set("Cookie", &cookie)
        .send_form(&[
            ("csrf_token", csrf.as_str()),
            ("title", "Hello World"),
            ("slug", "hello-world"),
            ("body_md", "first version"),
            ("tags", "foo, bar"),
            ("published", "1"),
            ("action", "save"),
        ])
        .unwrap();
    assert_eq!(resp.status(), 303);

    // It's live and tagged.
    let body = ureq::get(&format!("{}/post/hello-world", srv.base)).call().unwrap().into_string().unwrap();
    assert!(body.contains("Hello World"));
    assert!(body.contains("/tag/foo"));

    let tag_body = ureq::get(&format!("{}/tag/foo", srv.base)).call().unwrap().into_string().unwrap();
    assert!(tag_body.contains("hello-world"));

    // Preview renders but must not persist.
    let edit_body = ureq::get(&format!("{}/admin/edit/1", srv.base)).set("Cookie", &cookie).call().unwrap().into_string().unwrap();
    let edit_csrf = extract_input_value(&edit_body, "csrf_token");
    let preview_resp = ureq::post(&format!("{}/admin/edit/1", srv.base))
        .set("Cookie", &cookie)
        .send_form(&[
            ("csrf_token", edit_csrf.as_str()),
            ("title", "SHOULD NOT PERSIST"),
            ("slug", "hello-world"),
            ("body_md", "preview-only body"),
            ("tags", "foo"),
            ("action", "preview"),
        ])
        .unwrap()
        .into_string()
        .unwrap();
    assert!(preview_resp.contains("preview-only body") || preview_resp.contains("preview"));
    let live = ureq::get(&format!("{}/post/hello-world", srv.base)).call().unwrap().into_string().unwrap();
    assert!(live.contains("Hello World") && !live.contains("SHOULD NOT PERSIST"));

    // A real update saves a revision of the pre-update state.
    let resp = agent
        .post(&format!("{}/admin/edit/1", srv.base))
        .set("Cookie", &cookie)
        .send_form(&[
            ("csrf_token", edit_csrf.as_str()),
            ("title", "Hello World v2"),
            ("slug", "hello-world"),
            ("body_md", "second version"),
            ("tags", "foo, bar, baz"),
            ("published", "1"),
            ("action", "save"),
        ])
        .unwrap();
    assert_eq!(resp.status(), 303);

    let revisions_body = ureq::get(&format!("{}/admin/revisions/1", srv.base)).set("Cookie", &cookie).call().unwrap().into_string().unwrap();
    assert!(revisions_body.contains("Hello World")); // the old title, now in history
    assert!(revisions_body.contains("/admin/revisions/restore/1"));

    // Restore it, and confirm the live post reverts.
    let resp = agent
        .post(&format!("{}/admin/revisions/restore/1", srv.base))
        .set("Cookie", &cookie)
        .send_form(&[("csrf_token", edit_csrf.as_str())])
        .unwrap();
    assert_eq!(resp.status(), 303);
    let restored = ureq::get(&format!("{}/post/hello-world", srv.base)).call().unwrap().into_string().unwrap();
    assert!(restored.contains("<title>Hello World —"));
}

#[test]
fn media_delete_rejects_path_traversal() {
    let srv = TestServer::start();
    let cookie = setup_and_login(&srv, "admin", "supersecret1");
    let csrf = get_csrf_token(&srv, &cookie, "/admin/media");

    // Plant a canary file outside the uploads dir and confirm a traversal
    // delete request can't reach it.
    let canary = srv._dir.path().join("canary.txt");
    std::fs::write(&canary, "do not delete me").unwrap();

    let resp = ureq::post(&format!("{}/admin/media/delete", srv.base))
        .set("Cookie", &cookie)
        .send_form(&[("csrf_token", csrf.as_str()), ("name", "../canary.txt")])
        .unwrap();
    // Whatever status it returns, the file must survive untouched.
    let _ = resp.status();
    assert!(canary.exists(), "path traversal must not delete files outside uploads/");
    assert_eq!(std::fs::read_to_string(&canary).unwrap(), "do not delete me");
}

#[test]
fn pagination_and_rss_and_audit_log() {
    let srv = TestServer::start_with_env(&[("TORCMS_POSTS_PER_PAGE", "2")]);
    let cookie = setup_and_login(&srv, "admin", "supersecret1");

    for i in 1..=3 {
        let csrf = get_csrf_token(&srv, &cookie, "/admin/new");
        ureq::post(&format!("{}/admin/new", srv.base))
            .set("Cookie", &cookie)
            .send_form(&[
                ("csrf_token", csrf.as_str()),
                ("title", &format!("Post {i}")),
                ("slug", &format!("post-{i}")),
                ("body_md", "body"),
                ("published", "1"),
                ("action", "save"),
            ])
            .unwrap();
    }

    let page1 = ureq::get(&format!("{}/", srv.base)).call().unwrap().into_string().unwrap();
    assert!(page1.contains("older"), "page 1 of 3 posts at 2/page should have an older link");
    assert!(!page1.contains("newer"));

    let page2 = ureq::get(&format!("{}/?page=2", srv.base)).call().unwrap().into_string().unwrap();
    assert!(page2.contains("newer"));

    // RSS feed exists, is XML, and lists the posts.
    let resp = ureq::get(&format!("{}/feed.xml", srv.base)).call().unwrap();
    assert!(resp.header("Content-Type").unwrap().contains("rss"));
    let xml = resp.into_string().unwrap();
    assert_eq!(xml.matches("<item>").count(), 3);

    // Audit log recorded the account creation, login, and all three posts —
    // and never anything that looks like client info.
    let audit = ureq::get(&format!("{}/admin/audit", srv.base)).set("Cookie", &cookie).call().unwrap().into_string().unwrap();
    assert!(audit.contains("setup"));
    assert!(audit.contains("login"));
    assert_eq!(audit.matches("post_created").count(), 3);
    assert!(!audit.contains("127.0.0.1"), "audit log must never contain client-identifying info");
}

#[test]
fn unknown_route_renders_themed_404() {
    let srv = TestServer::start();
    let resp = ureq::get(&format!("{}/this-does-not-exist", srv.base))
        .call()
        .unwrap_err();
    let resp = resp.into_response().unwrap();
    assert_eq!(resp.status(), 404);
    let body = resp.into_string().unwrap();
    assert!(body.to_lowercase().contains("not found") || body.contains("404"));
}
