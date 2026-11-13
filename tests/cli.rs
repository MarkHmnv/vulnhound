use std::process::Command;

/// Scans this machine: `cargo test -- --ignored live_scan`.
#[test]
#[ignore = "scans this machine: needs Fedora (rpm, dnf) or Windows, and network access"]
fn live_scan_prints_summary_and_writes_report() {
    let path = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("live-report.md");
    let _ = std::fs::remove_file(&path);
    let out = Command::new(env!("CARGO_BIN_EXE_vulnhound"))
        .arg("-o")
        .arg(&path)
        .output()
        .unwrap();
    let code = out.status.code().unwrap();
    assert!(code == 0 || code == 1, "{}", String::from_utf8_lossy(&out.stderr));

    let summary = String::from_utf8_lossy(&out.stdout);
    assert!(summary.contains(&format!("Full report: {}", path.display())));
    // Not a terminal: no color, no progress.
    assert!(!summary.contains('\x1b'));
    assert!(out.stderr.is_empty());

    let report = std::fs::read_to_string(&path).unwrap();
    assert!(report.starts_with("# vulnhound report\n"));
}
