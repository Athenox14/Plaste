//! Human-readable landing page for a public share link, at `GET /s/{share_token}` (plus
//! `POST /s/{share_token}` for the password form).
//!
//! `/public/shares/{token}` (sharing.rs) is JSON-only, meant for programmatic clients; this
//! module renders the same data as an HTML page for a person who clicked a link in a message.
//! It never talks to the DB itself for validation — it always goes through
//! `sharing::load_valid_share`, so revocation/expiry/password/rate-limit behave identically on
//! both the JSON and HTML paths and can't drift apart.
//!
//! No template engine, no JS: the password field is a plain HTML `<form method="post">`. It must
//! be a POST — a GET form would put the password in the query string, i.e. into the proxy access
//! log, the browser history and every outbound `Referer`. For the same reason the download link
//! this page renders carries a short-lived signed ticket (`?t=`), never the password: a `GET`
//! the browser performs can't carry a header, and a ticket in a log is worthless once expired.

use axum::{
    extract::{Form, Path, State},
    http::{header, StatusCode},
    response::{Html, IntoResponse},
    Router,
};
use serde::Deserialize;

use crate::{sharing, AppState};

pub fn router() -> Router<AppState> {
    Router::new().route(
        "/s/{share_token}",
        axum::routing::get(show_share_page).post(submit_share_password),
    )
}

#[derive(Deserialize)]
struct PasswordForm {
    password: String,
}

/// Escapes the five HTML-significant characters. Every piece of request- or DB-derived text
/// (filename, folder name, share token) goes through this before it is concatenated into the
/// page — the filename in particular is chosen by whoever uploaded the file, so it is
/// attacker-controlled as far as this page is concerned. The password is never echoed back.
fn escape_html(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

/// Formats a byte count as a human-readable size (`1.5 MB`, `842 B`, ...). Binary (1024) units,
/// since that's what every OS file browser shows.
fn format_size(bytes: i64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    if bytes < 1024 {
        return format!("{bytes} B");
    }
    let mut size = bytes as f64;
    let mut unit = 0;
    while size >= 1024.0 && unit < UNITS.len() - 1 {
        size /= 1024.0;
        unit += 1;
    }
    format!("{size:.1} {}", UNITS[unit])
}

const CSP: &str = "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'self'";

fn page_response(status: StatusCode, body: String) -> impl IntoResponse {
    (
        status,
        [
            (header::CONTENT_SECURITY_POLICY, CSP),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
            // The page can carry a download ticket; keep it out of proxy caches and out of the
            // `Referer` of the download navigation.
            (header::CACHE_CONTROL, "no-store"),
            (header::REFERRER_POLICY, "no-referrer"),
        ],
        Html(body),
    )
}

/// Shared HTML skeleton (title + minimal CSS), so every state below only supplies the body.
fn layout(inner: &str) -> String {
    format!(
        r#"<!doctype html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Partage Plaste</title>
<style>
  body {{ font-family: system-ui, sans-serif; max-width: 28rem; margin: 3rem auto; padding: 0 1rem;
         color: #222; background: #fafafa; }}
  .card {{ background: #fff; border: 1px solid #ddd; border-radius: 8px; padding: 1.5rem; }}
  h1 {{ font-size: 1.1rem; word-break: break-word; margin-top: 0; }}
  .meta {{ color: #666; font-size: 0.9rem; margin-bottom: 1.2rem; }}
  .btn {{ display: inline-block; background: #2563eb; color: #fff; text-decoration: none;
         padding: 0.6rem 1.2rem; border-radius: 6px; font-weight: 600; border: 0;
         font-size: 1rem; cursor: pointer; }}
  .btn:hover {{ background: #1d4ed8; }}
  input[type=password] {{ width: 100%; box-sizing: border-box; padding: 0.5rem; margin: 0.5rem 0;
                          border: 1px solid #ccc; border-radius: 6px; font-size: 1rem; }}
  .error {{ color: #b91c1c; margin-bottom: 0.8rem; }}
  .notice {{ color: #444; }}
</style>
</head>
<body><div class="card">{inner}</div></body>
</html>"#
    )
}

fn notice_page(status: StatusCode, message: &str) -> impl IntoResponse {
    page_response(status, layout(&format!(r#"<p class="notice">{}</p>"#, escape_html(message))))
}

/// Renders the password prompt. `wrong` distinguishes "first visit" (no message) from "you just
/// submitted a bad password" (shown as an error) — both cases still return 401, since the
/// underlying route does too and this page must not imply the link is otherwise valid data.
///
/// `method="post"`: the browser then puts the password in the request body, not the URL.
fn password_form(share_token: &str, wrong: bool) -> String {
    let error = if wrong {
        r#"<p class="error">Mot de passe incorrect.</p>"#
    } else {
        ""
    };
    format!(
        r#"<h1>Lien protégé par mot de passe</h1>
{error}
<form method="post" action="/s/{token}">
  <input type="password" name="password" placeholder="Mot de passe" autocomplete="current-password" autofocus required>
  <button class="btn" type="submit">Continuer</button>
</form>"#,
        token = escape_html(share_token),
    )
}

async fn show_share_page(
    State(state): State<AppState>,
    Path(share_token): Path<String>,
) -> impl IntoResponse {
    render_share(&state, &share_token, None).await
}

async fn submit_share_password(
    State(state): State<AppState>,
    Path(share_token): Path<String>,
    Form(form): Form<PasswordForm>,
) -> impl IntoResponse {
    render_share(&state, &share_token, Some(form.password)).await
}

/// The whole page, for both methods. `password` is `Some` only on the POST path.
///
/// Note the rate limit lives inside `load_valid_share` and is keyed on the share token, not on
/// the HTTP method or the client address — so submitting the form by POST consumes exactly the
/// same brute-force budget the old query-string GET did, and can't be used to escape it.
async fn render_share(
    state: &AppState,
    share_token: &str,
    password: Option<String>,
) -> axum::response::Response {
    let share = match sharing::load_valid_share(state, share_token, password.as_deref()).await {
        Ok(share) => share,
        Err((StatusCode::NOT_FOUND, _)) => {
            // Same message for "never existed" and "revoked" — see sharing.rs's own comment on
            // load_valid_share: distinguishing the two would confirm to a prober that a given
            // token was once valid.
            return notice_page(StatusCode::NOT_FOUND, "Ce lien n'existe pas ou n'est plus valide.")
                .into_response();
        }
        Err((StatusCode::GONE, _)) => {
            return notice_page(StatusCode::GONE, "Ce lien a expiré.").into_response();
        }
        Err((StatusCode::TOO_MANY_REQUESTS, _)) => {
            return notice_page(
                StatusCode::TOO_MANY_REQUESTS,
                "Trop de tentatives, réessayez plus tard.",
            )
            .into_response();
        }
        Err((StatusCode::UNAUTHORIZED, _)) => {
            // wrong=true only once a password was actually submitted and rejected; a bare first
            // visit to a protected link just gets the empty form, not an "incorrect" message.
            let wrong = password.is_some();
            return page_response(StatusCode::UNAUTHORIZED, layout(&password_form(share_token, wrong)))
                .into_response();
        }
        Err(_) => {
            return notice_page(StatusCode::INTERNAL_SERVER_ERROR, "Une erreur est survenue.")
                .into_response();
        }
    };

    if share.resource_type != "file" {
        // Folder shares resolve fine over the JSON route but the download route 400s on them
        // (files only) — no point building a folder browser here for a route this page doesn't
        // support downloading from.
        return notice_page(
            StatusCode::OK,
            "Ce lien partage un dossier ; utilisez un client compatible pour y accéder.",
        )
        .into_response();
    }

    struct FileInfoRow {
        name: String,
        size: i64,
    }
    impl From<&mut hiqlite::Row<'_>> for FileInfoRow {
        fn from(row: &mut hiqlite::Row<'_>) -> Self {
            Self { name: row.get("name"), size: row.get("size") }
        }
    }
    let info: Option<FileInfoRow> = state
        .db
        .query_map_optional(
            "SELECT f.name AS name, COALESCE(v.size, 0) AS size FROM files f \
             LEFT JOIN file_versions v ON v.id = f.current_version_id \
             WHERE f.id = $1 AND f.deleted_at IS NULL",
            hiqlite::params!(share.resource_id),
        )
        .await
        .ok()
        .flatten();
    let Some(info) = info else {
        // The share row is valid but the file it points to is gone (deleted since) — same
        // "not found" wording as an unknown token, for the same non-disclosure reason.
        return notice_page(StatusCode::NOT_FOUND, "Ce lien n'existe pas ou n'est plus valide.")
            .into_response();
    };

    // A password was accepted => the share is protected => the download route needs proof. Mint
    // a ticket rather than re-sending the password: it expires in ~2 minutes and is bound to
    // this share token. `download_ticket` returns base64url only, so no escaping is needed.
    let download_href = match password {
        Some(_) => format!(
            "/public/shares/{}/download?t={}",
            escape_html(share_token),
            sharing::download_ticket(state, share_token)
        ),
        None => format!("/public/shares/{}/download", escape_html(share_token)),
    };

    let body = format!(
        r#"<h1>{name}</h1>
<p class="meta">{size}</p>
<a class="btn" href="{href}">Télécharger</a>"#,
        name = escape_html(&info.name),
        size = escape_html(&format_size(info.size)),
        href = download_href,
    );
    page_response(StatusCode::OK, layout(&body)).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn html_escape_neutralizes_script_tags() {
        let escaped = escape_html(r#"<script>alert(1)</script>"#);
        assert!(!escaped.contains("<script>"));
        assert!(!escaped.contains("</script>"));
        assert_eq!(escaped, "&lt;script&gt;alert(1)&lt;/script&gt;");
    }

    #[test]
    fn html_escape_covers_all_five_significant_characters() {
        assert_eq!(escape_html("&<>\"'"), "&amp;&lt;&gt;&quot;&#39;");
        assert_eq!(escape_html("plain name.txt"), "plain name.txt");
    }

    #[test]
    fn format_size_is_human_readable() {
        assert_eq!(format_size(0), "0 B");
        assert_eq!(format_size(500), "500 B");
        assert_eq!(format_size(1024), "1.0 KB");
        assert_eq!(format_size(1536), "1.5 KB");
        assert_eq!(format_size(1024 * 1024), "1.0 MB");
        assert_eq!(format_size(3 * 1024 * 1024 * 1024), "3.0 GB");
    }

    /// The password must never travel in a URL: the form posts it, so no `?password=` can be
    /// produced by this page, and the field is not echoed back into the re-rendered form.
    #[test]
    fn password_form_posts_and_never_puts_the_password_in_a_url() {
        for wrong in [false, true] {
            let html = password_form("tok-123", wrong);
            assert!(html.contains(r#"method="post""#), "must not be a GET form: {html}");
            assert!(!html.contains("method=\"get\""));
            assert!(!html.contains("password="), "no password in any URL: {html}");
            assert!(!html.contains("value="), "the password must not be echoed back: {html}");
        }
        assert!(password_form("tok-123", true).contains("incorrect"));
        assert!(!password_form("tok-123", false).contains("incorrect"));
    }
}
