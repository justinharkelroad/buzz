use super::*;
use buzz_terminal::damage::{CursorFrame, RowFrame, Span};

fn publication(spans: Vec<Span>) -> Publication {
    Publication {
        subscription_id: SubscriptionId::new(),
        sequence: 7,
        frame: buzz_terminal::damage::Frame {
            rows: vec![RowFrame { line: 3, spans }],
            cursor: CursorFrame {
                line: 1,
                column: 2,
                visible: true,
            },
            cursor_changed: true,
            full: true,
            viewport: Viewport {
                generation: 4,
                columns: 80,
                screen_lines: 24,
            },
        },
    }
}

fn style() -> Style {
    Style {
        fg: 1,
        bg: 2,
        flags: 3,
    }
}

fn marker_frame(marker: usize, full: bool) -> Frame {
    Frame {
        rows: vec![RowFrame {
            line: marker,
            spans: Vec::new(),
        }],
        cursor: CursorFrame {
            line: 0,
            column: 0,
            visible: true,
        },
        cursor_changed: true,
        full,
        viewport: Viewport {
            generation: 0,
            columns: 80,
            screen_lines: 24,
        },
    }
}

fn assert_post_snapshot_capture_survives_attach(mut publisher: FramePublisher) {
    assert!(!publisher.requires_snapshot());
    let bootstrap = marker_frame(1, true);
    let post_snapshot_incremental = marker_frame(42, false);
    let subscription = SubscriptionId::new();
    publisher.attach(subscription, bootstrap).unwrap();
    let publisher = Mutex::new(publisher);

    assert_eq!(
        offer_capture(&publisher, post_snapshot_incremental, || marker_frame(
            42, true
        )),
        None
    );

    let successor = publisher
        .lock()
        .unwrap()
        .acknowledge(subscription, 1)
        .expect("post-snapshot PTY output was lost");
    assert_eq!(successor.frame.rows[0].line, 42);
    assert!(successor.frame.full);
}

#[test]
fn reader_pumps_a_deferred_tail_without_an_external_event() {
    let (terminal, _actions) = Terminal::new(Size::default(), Fences::ALL);
    let terminal = SharedTerminal::new(terminal);
    let payload = "\u{1b}c".repeat(2_102_714);

    assert!(
        feed_and_drain(&terminal, payload.as_bytes()),
        "fixture must defer parser work before the runtime pumps it"
    );

    let terminal = terminal.lock();
    assert_eq!(terminal.pending_bytes(), 0);
    assert_eq!(terminal.stats().completed_units, 2_102_714);
}

#[test]
fn initial_attach_retains_output_captured_after_its_bootstrap_snapshot() {
    let viewport = marker_frame(0, true).viewport;
    let publisher = FramePublisher::new(viewport);
    assert_post_snapshot_capture_survives_attach(publisher);
}

#[test]
fn reattach_retains_output_captured_after_its_bootstrap_snapshot() {
    let viewport = marker_frame(0, true).viewport;
    let mut publisher = FramePublisher::new(viewport);
    let old = SubscriptionId::new();
    publisher.attach(old, marker_frame(0, true)).unwrap();
    assert!(publisher.acknowledge(old, 1).is_none());
    assert_post_snapshot_capture_survives_attach(publisher);
}

#[test]
fn mapper_expands_ascii_runs_without_unicode_classification() {
    let message = wire_publication(publication(vec![Span {
        column: 4,
        text: "abc".into(),
        width: 1,
        cluster_count: 3,
        style: style(),
    }]))
    .unwrap();
    let clusters = &message.rows[0].spans[0].clusters;
    assert_eq!(
        clusters
            .iter()
            .map(|cluster| (cluster.column, cluster.text.as_str()))
            .collect::<Vec<_>>(),
        vec![(4, "a"), (5, "b"), (6, "c")]
    );
}

#[test]
fn mapper_keeps_a_multi_char_cluster_atomic() {
    let message = wire_publication(publication(vec![Span {
        column: 9,
        text: "1\u{fe0f}\u{20e3}".into(),
        width: 2,
        cluster_count: 1,
        style: style(),
    }]))
    .unwrap();
    let clusters = &message.rows[0].spans[0].clusters;
    assert_eq!(clusters.len(), 1);
    assert_eq!(clusters[0].column, 9);
    assert_eq!(clusters[0].text, "1\u{fe0f}\u{20e3}");
    assert_eq!(clusters[0].width, 2);
}

#[test]
fn mapper_rejects_an_inconsistent_engine_span() {
    let result = wire_publication(publication(vec![Span {
        column: 0,
        text: "ab".into(),
        width: 1,
        cluster_count: 3,
        style: style(),
    }]));
    assert!(result.is_err());
}

#[test]
fn terminal_commands_accept_only_the_trusted_main_window() {
    assert!(require_main_window_label("main").is_ok());
    for label in ["huddle-1", "huddle-main", "main-preview", ""] {
        assert!(
            require_main_window_label(label).is_err(),
            "untrusted window {label:?} crossed the terminal command boundary"
        );
    }
}

#[test]
fn every_terminal_tauri_command_applies_the_main_window_guard() {
    let source = include_str!("../terminal_runtime.rs");
    let command_marker = concat!("#[", "tauri::command", "]");
    let guard_call = concat!("require_main_window", "(&window)?;");
    let commands = source.matches(command_marker).count();
    let guards = source.matches(guard_call).count();

    assert_eq!(commands, 9, "update this gate when commands are added");
    assert_eq!(
        guards, commands,
        "every terminal Tauri command must reject non-main callers"
    );
}

#[test]
fn reader_join_has_a_deadline_when_the_pty_never_reports_eof() {
    let (terminal, _actions) = Terminal::new(
        Size {
            columns: 1,
            screen_lines: 1,
            scrollback: 0,
        },
        Fences::ALL,
    );
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let handle = std::thread::spawn(move || {
        let _ = release_rx.recv_timeout(Duration::from_secs(2));
    });
    let stopping = Arc::new(AtomicBool::new(false));
    let reader: Box<dyn buzz_terminal::lifecycle::DrainingReader> = Box::new(ReaderThread {
        handle: Some(handle),
        terminal: Arc::new(SharedTerminal::new(terminal)),
        stopping: Arc::clone(&stopping),
    });

    reader.stop();
    assert!(stopping.load(Ordering::Acquire));
    let started = Instant::now();
    reader.join();
    let elapsed = started.elapsed();
    let _ = release_tx.send(());

    assert!(
        elapsed < Duration::from_secs(1),
        "reader join exceeded its deadline: {elapsed:?}"
    );
}

#[test]
fn dimensions_reject_zero_and_upper_bound_violations() {
    assert!(size(0, 24).is_err());
    assert!(size(80, 0).is_err());
    assert!(size(MAX_TERMINAL_COLUMNS + 1, 24).is_err());
    assert!(size(80, MAX_TERMINAL_ROWS + 1).is_err());
}

#[test]
fn ordinary_dimensions_preserve_the_default_scrollback() {
    let size = size(100, 40).unwrap();
    assert_eq!(
        (size.columns, size.screen_lines, size.scrollback),
        (100, 40, 10_000)
    );
}

#[test]
fn maximum_dimensions_bound_viewport_plus_scrollback_cells() {
    let size = size(MAX_TERMINAL_COLUMNS, MAX_TERMINAL_ROWS).unwrap();
    let retained_cells = size.columns * (size.screen_lines + size.scrollback);

    assert_eq!(size.columns, usize::from(MAX_TERMINAL_COLUMNS));
    assert_eq!(size.screen_lines, usize::from(MAX_TERMINAL_ROWS));
    assert_eq!(retained_cells, MAX_TERMINAL_GRID_CELLS);
    assert!(size.scrollback < Size::default().scrollback);
}
