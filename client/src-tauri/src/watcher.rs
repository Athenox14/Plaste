// Filesystem watcher: watches a local sync folder and emits change events to the frontend.
// Foundation for future sync logic only — does not talk to the Plaste server.

use notify::RecursiveMode;
use notify_debouncer_full::{new_debouncer, DebouncedEvent};
use serde::Serialize;
use std::time::Duration;
use tauri::{AppHandle, Emitter};

#[derive(Serialize, Clone)]
pub struct FsChangeEvent {
    kind: String, // "create" | "modify" | "delete" | "rename" | "other"
    paths: Vec<String>,
}

fn classify(event: &notify::Event) -> &'static str {
    use notify::EventKind::*;
    match event.kind {
        Create(_) => "create",
        Modify(kind) => match kind {
            notify::event::ModifyKind::Name(_) => "rename",
            _ => "modify",
        },
        Remove(_) => "delete",
        _ => "other",
    }
}

/// Starts watching `path` recursively. Runs the debouncer on a dedicated thread
/// for the lifetime of the app (ponytail: no stop_watching command yet, add when
/// multiple concurrent/changeable watch roots are needed).
#[tauri::command]
pub fn start_watching(app: AppHandle, path: String) -> Result<(), String> {
    std::thread::spawn(move || {
        let app_for_events = app.clone();
        let mut debouncer = match new_debouncer(
            Duration::from_millis(500),
            None,
            move |result: Result<Vec<DebouncedEvent>, Vec<notify::Error>>| match result {
                Ok(events) => {
                    for debounced in events {
                        let kind = classify(&debounced.event);
                        let paths = debounced
                            .event
                            .paths
                            .iter()
                            .map(|p| p.display().to_string())
                            .collect();
                        let payload = FsChangeEvent {
                            kind: kind.to_string(),
                            paths,
                        };
                        println!("[watcher] {} {:?}", payload.kind, payload.paths);
                        let _ = app_for_events.emit("sync-folder://fs-change", payload);
                    }
                }
                Err(errors) => {
                    for e in errors {
                        eprintln!("[watcher] watch error: {e:?}");
                    }
                }
            },
        ) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("[watcher] failed to create debouncer: {e}");
                return;
            }
        };

        if let Err(e) = debouncer.watch(std::path::Path::new(&path), RecursiveMode::Recursive) {
            eprintln!("[watcher] failed to watch {path}: {e}");
            return;
        }

        // Keep the debouncer (and its watcher thread) alive for the process lifetime.
        std::mem::forget(debouncer);
    });

    Ok(())
}
