# ghostpress

Minimal CMS in Rust (Axum + SQLite), built to run as a Tor hidden service
without leaking the host's real IP.

## Design choices that matter for IP hiding

- Binds only to `127.0.0.1:8899` by default (overridable via
  `TORCMS_BIND_ADDR`, still loopback-only by convention) — never `0.0.0.0`.
  Tor's `HiddenServiceDir` reverse-proxies to this loopback port; there is no
  other listener.
- No HTTP client dependency at all (no `reqwest`, no outbound calls anywhere
  in the dependency tree) — the binary cannot "phone home" even by accident.
- No telemetry, analytics, remote fonts/avatars/CDNs. All CSS is inlined in
  the templates; zero JavaScript is served, so the app works identically
  under Tor Browser's "Safest" security level.
- `server` response header is stripped and a restrictive CSP/security header
  set is applied to every response (`src/main.rs::security_headers_mw`).
- Markdown-rendered post bodies are sanitized with `ammonia` before being
  marked safe for the template, so a compromised/malicious admin session
  can't inject `<script>`.
- Sessions are random 256-bit tokens in a server-side table (no JWT, nothing
  client-decodable); cookies are `HttpOnly` + `SameSite=Strict`, no `Secure`
  flag (the tor↔app hop is loopback, not TLS, by design).
- Login timing is padded with a dummy hash verification on unknown usernames
  to reduce username-enumeration via response timing.
- Login attempts are throttled **per username, not per IP** — every
  connection to a Tor hidden service arrives from `127.0.0.1`, so an IP-based
  limiter would be a no-op and a reason to start logging real client info,
  which this app never does. 5 failed attempts locks that username for 5
  minutes (`src/auth.rs::locked_for`/`record_failed_login`).
- Every state-changing admin request (post/page CRUD, upload, media delete,
  password/settings change, logout) requires a CSRF token derived via
  HMAC-SHA256 from the session cookie (`src/auth.rs::csrf_token`) — stateless
  (no extra DB column), automatically invalidated with the session, and
  compared in constant time.
- A panic in a request handler is caught (`tower_http::catch_panic`) and
  turned into a generic 500 page rather than a dropped connection or a
  leaked panic message — panic payloads can contain local file paths, which
  is host-fingerprinting info with no reason to reach a client.

None of this hides the IP by itself — that's entirely Tor's job. The code's
job is to not undermine it (no stray outbound connections, no IP-bearing
headers trusted, no client-side code that could fingerprint or dial out).

## Build

```sh
cargo build --release
```

## First run — create the admin account

The admin account is created entirely through the browser, no CLI/SSH
needed: start the server (writes into `cms.db` — SQLite, created next to the
binary; run from the directory you want data to live in, or set
`WorkingDirectory` in the systemd unit) and it prints a one-time setup token
to stdout:

```
no admin account yet — visit /setup?token=<token> to create one
(this token is only printed here, to this console, never logged or served)
```

Visit that URL (or `/setup` and paste the token into the form) to create the
account. The token is required to submit the form — reaching `/setup` alone
isn't enough, which closes the "whoever gets there first wins" race from
earlier versions of this app. The route 404s permanently once an account
exists, same as any other unknown route, and a fresh token is generated
each time the server starts with no account yet (so a stale token from a
previous boot won't work).

This is also the path for **migrating the blog to a new machine**: copy
`cms.db`/`uploads/` or start fresh, boot the binary on the new box, read the
token from its console output, and claim the account from a browser instead
of needing shell access there.

There is no CLI account-creation/reset path. A locked-out admin must clear
the `users` table in `cms.db` directly (e.g. `sqlite3 cms.db "DELETE FROM
users;"`) to re-open `/setup`.

## Run

```sh
./target/release/ghostpress
```

Visit `http://127.0.0.1:8899` locally to confirm it works before wiring up
Tor.

## Deploy as a Tor hidden service

1. Copy `deploy/torrc.snippet` into your Tor config and restart Tor — see
   that file for details and the security notes.
2. Install the binary + `templates/` directory somewhere like
   `/opt/ghostpress/` and adapt/install `deploy/ghostpress.service` with
   `systemctl enable --now ghostpress`.
3. Get the onion address: `sudo cat /var/lib/tor/ghostpress/hostname`.

## Static pages vs. posts

Alongside dated/listed blog `posts` (`/post/<slug>`, shown on `/`), there's
a separate `pages` table for static content like an About or Contact page,
served at `/p/<slug>` and never listed on the homepage. Managed from the
same admin dashboard ("pages" section) with the same draft/published and
markdown-sanitization behavior as posts.

## Image uploads (`/admin/upload`, admin-only)

- Accepts jpeg, png, static webp, and static/animated gif, sniffed from
  file bytes via magic numbers (`image::guess_format`) — the client's
  declared `content-type` and original filename are never trusted or
  stored.
- Every frame is fully decoded and re-encoded from raw pixels
  (`src/uploads.rs`), which inherently discards all EXIF/metadata: GPS,
  camera make/model, timestamps, embedded thumbnails, and (for gif) comment
  and application extensions. Verified in testing against a JPEG with
  planted GPS/camera/comment EXIF tags and an animated GIF with a planted
  comment extension — all gone after re-encode, confirmed byte-for-byte,
  with frame count/timing/loop behavior preserved for the GIF.
- Animated webp is explicitly rejected (this version of the `image` crate
  can't decode its animation) rather than silently mis-decoded to a single
  frame; the error message points the user at re-exporting as gif instead.
- Header dimensions are checked *before* full decode and capped at 40MP
  per frame, to avoid a decompression-bomb-style small-file/huge-pixel-
  buffer DoS; animated gifs are additionally capped at 600 frames and
  processed one frame at a time so peak memory is bounded by a single
  frame, not the whole animation.
- Oversized images/frames are downscaled (never upscaled) to a 2500px
  longest side — also blunts sensor-noise camera fingerprinting on photos.
- Saved under a random 128-bit hex filename, never the name the uploader's
  browser sent (which can itself leak identifying info).
- Served back out via a plain static file server at `/uploads/` — no
  script execution path, directory listing disabled by default.
- Upload body limit is 15MB, enforced separately from the 512KB limit on
  all other (text) form routes.

## Media library (`/admin/media`)

Lists every file under `uploads/`, newest first, with a one-click copyable
markdown snippet and a delete button per file. Deletion takes a bare
filename only (rejects anything containing `/`, `\`, or `..`) so it can't be
used to escape `UPLOAD_DIR`.

## Account & site settings

- `/admin/password` — change the admin password in-app (no SSH/CLI needed
  after first setup); requires the current password, enforces an 8-char
  minimum on the new one.
- `/admin/settings` — change the site name shown in the nav/title at
  runtime, stored in a `settings` key-value table instead of hardcoded.

## Pagination

The post index (`/`) paginates at `TORCMS_POSTS_PER_PAGE` posts/page
(default 10) via `?page=N`, with newer/older links. Pages (`/p/<slug>`) and
posts themselves are unpaginated (single items).

## Error pages

Unmatched routes and explicit "not found" cases render a themed `404.html`
instead of plain text. A panicking handler is caught and returns a generic
themed 500 instead of a dropped connection.

## Tags (posts only)

Comma-separated tags can be set on a post from the edit form. Each tag links
to `/tag/<name>`, listing every published post with that tag (unpaginated).
Scoped to posts, not pages — static pages don't need categorization the way
dated posts do.

## Revision history (posts only)

Every time a post is updated, its pre-update title/body is saved to
`post_revisions`, capped at the last 10 per post. View history at
`/admin/revisions/<post_id>` and restore any prior version with one click
(CSRF-protected POST) — restoring itself saves the current state as a new
revision first, so a restore is undoable too. Scoped to posts, not pages,
for the same reason as tags.

## Markdown preview

The post edit form has a "preview" button alongside "save" — it renders the
submitted markdown and re-shows the form with your values intact, without
writing anything to the database.

## RSS feed (`/feed.xml`)

Hand-built RSS 2.0 XML (no extra dependency) of the latest 20 published
posts. The feed's absolute URL base comes from the `site_url` setting
(`/admin/settings`) if set, else falls back to the request's `Host` header —
safe under the "never leak client info" rule because under a Tor hidden
service `Host` reflects the server's own public `.onion` address, not
anything about the requesting client.

## Health check (`/healthz`)

Unauthenticated `GET /healthz` runs a trivial query against the DB and
returns 200 `ok` or 500 `db unavailable`. No logging, no client info.

## Audit log (`/admin/audit`, admin-only)

Local-only record of admin actions (login/login_failed/logout, setup,
password/settings changes, post/page create/update/delete, media delete,
revision restore) — action name, a non-client-identifying detail string, and
a timestamp. Never records anything about who/where a request came from;
useful forensics if the single admin account is ever compromised.

## Runtime configuration (env vars)

Two knobs can be tuned without a rebuild, read at startup:

- `TORCMS_BIND_ADDR` (default `127.0.0.1:8899`)
- `TORCMS_POSTS_PER_PAGE` (default `10`)

## Backups

```sh
./target/release/ghostpress backup /path/to/backup.db
```

Uses SQLite's own online-backup API (`rusqlite::backup`), safe to run
against a database that's currently being written to — unlike a raw `cp` of
a live SQLite file, which can copy a torn/inconsistent snapshot. `uploads/`
still needs a normal file copy alongside it.

## Session cleanup

Expired session rows are deleted opportunistically on every successful
login, plus a background sweep every hour (`tokio::spawn` loop in `main()`)
to catch sessions from users who never log in again. `user_id_for_session`
already refuses expired tokens on its own either way — this is just table
hygiene.

## What this does NOT do

- No animated webp support (decode-side limitation of the `image` crate) —
  re-export as gif instead. Static webp is re-encoded to PNG rather than
  re-encoded as webp, to avoid pulling in a webp encoder dependency.
- No multi-user/multi-author support — a single `users` table, created via
  `/setup`, in-app for password changes.
- No full-text search, comments, or client-side code of any kind — all of
  that either needs JavaScript (breaks the zero-JS/Tor-Browser-Safest design
  goal) or is irrelevant to a single-author Tor-only blog.
