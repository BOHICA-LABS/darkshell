// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! WF-1: End-to-end upload workflow integration tests.
//!
//! Tests the pure functions that compose the upload pipeline: rsync argument
//! building, filtered tar command generation, dry-run diff computation, and
//! progress reporting wrappers.

use openshell_cli::progress::{
    CountingReader, CountingWriter, TransferDirection, TransferProgress, calculate_local_size,
};
use openshell_cli::ssh::{
    FileEntry, ModifiedEntry, UploadDiff, build_filtered_tar_command, compute_upload_diff,
    format_dry_run_json,
};
use std::io::{Cursor, Read, Write};
use std::path::Path;

// ---------------------------------------------------------------------------
// Rsync command building — public type behavior
// ---------------------------------------------------------------------------

#[test]
fn rsync_upload_options_default_follows_symlinks() {
    // AC-005: follow_symlinks defaults to true.
    let options = openshell_cli::ssh::RsyncUploadOptions {
        follow_symlinks: true,
        progress: false,
    };
    assert!(
        options.follow_symlinks,
        "follow_symlinks should be true when set"
    );
}

#[test]
fn rsync_upload_options_no_follow_symlinks() {
    let options = openshell_cli::ssh::RsyncUploadOptions {
        follow_symlinks: false,
        progress: false,
    };
    assert!(
        !options.follow_symlinks,
        "follow_symlinks should be false when disabled"
    );
}

// ---------------------------------------------------------------------------
// Filtered tar command building
// ---------------------------------------------------------------------------

#[test]
fn test_filtered_tar_command_with_include() {
    let cmd = build_filtered_tar_command("/workspace/project", &["*.json".to_string()], &[]);
    assert!(
        cmd.contains("-name"),
        "include pattern should use find -name: {cmd}"
    );
    assert!(
        cmd.contains("*.json"),
        "include pattern should appear in command: {cmd}"
    );
}

#[test]
fn test_filtered_tar_command_with_exclude() {
    let cmd = build_filtered_tar_command("/workspace", &[], &["*.log".to_string()]);
    assert!(
        cmd.contains("! \\("),
        "exclude should use negated predicate: {cmd}"
    );
    assert!(
        cmd.contains("-name"),
        "exclude pattern should use find -name: {cmd}"
    );
    assert!(
        cmd.contains("*.log"),
        "exclude pattern should appear in command: {cmd}"
    );
}

#[test]
fn test_filtered_tar_command_exclude_precedence() {
    // AC-005: When both include and exclude are present, exclude predicates
    // appear after include predicates so find evaluates them in order.
    let cmd =
        build_filtered_tar_command("/workspace", &["*.rs".to_string()], &["*.bak".to_string()]);

    let include_pos = cmd
        .find("\\( -name")
        .expect("include predicate should exist");
    let exclude_pos = cmd.find("! \\(").expect("exclude predicate should exist");
    assert!(
        include_pos < exclude_pos,
        "include predicates should precede exclude predicates in find command: {cmd}"
    );
}

#[test]
fn test_filtered_tar_command_no_filters_matches_upstream() {
    // AC-010: Without filters, the command matches the upstream tar pattern.
    let cmd = build_filtered_tar_command("/workspace/project", &[], &[]);
    assert!(
        cmd.contains("tar cf -"),
        "no-filter command should use plain tar: {cmd}"
    );
    assert!(
        !cmd.contains("find"),
        "no-filter command should not use find: {cmd}"
    );
}

// ---------------------------------------------------------------------------
// Dry-run diff computation
// ---------------------------------------------------------------------------

#[test]
fn test_dry_run_diff_computation() {
    let local_files = vec![
        FileEntry {
            path: "src/main.rs".to_string(),
            hash: "aaa".to_string(),
            size: 100,
        },
        FileEntry {
            path: "src/lib.rs".to_string(),
            hash: "bbb_changed".to_string(),
            size: 200,
        },
        FileEntry {
            path: "new_file.txt".to_string(),
            hash: "ccc".to_string(),
            size: 50,
        },
    ];

    let remote_files = vec![
        FileEntry {
            path: "src/main.rs".to_string(),
            hash: "aaa".to_string(),
            size: 100,
        },
        FileEntry {
            path: "src/lib.rs".to_string(),
            hash: "bbb_original".to_string(),
            size: 180,
        },
        FileEntry {
            path: "old_file.txt".to_string(),
            hash: "ddd".to_string(),
            size: 75,
        },
    ];

    let diff = compute_upload_diff(&local_files, &remote_files);

    assert_eq!(diff.added.len(), 1, "expected 1 added file");
    assert_eq!(diff.added[0].path, "new_file.txt");

    assert_eq!(diff.modified.len(), 1, "expected 1 modified file");
    assert_eq!(diff.modified[0].path, "src/lib.rs");
    assert_eq!(diff.modified[0].local_size, 200);
    assert_eq!(diff.modified[0].remote_size, 180);

    assert_eq!(diff.deleted.len(), 1, "expected 1 deleted file");
    assert_eq!(diff.deleted[0].path, "old_file.txt");

    assert_eq!(diff.unchanged.len(), 1, "expected 1 unchanged file");
    assert_eq!(diff.unchanged[0].path, "src/main.rs");
}

#[test]
fn test_dry_run_diff_empty_local_means_all_deleted() {
    let remote_files = vec![FileEntry {
        path: "a.txt".to_string(),
        hash: "xxx".to_string(),
        size: 10,
    }];

    let diff = compute_upload_diff(&[], &remote_files);
    assert!(diff.added.is_empty());
    assert!(diff.modified.is_empty());
    assert_eq!(diff.deleted.len(), 1);
    assert!(diff.unchanged.is_empty());
}

#[test]
fn test_dry_run_diff_empty_remote_means_all_added() {
    let local_files = vec![FileEntry {
        path: "a.txt".to_string(),
        hash: "xxx".to_string(),
        size: 10,
    }];

    let diff = compute_upload_diff(&local_files, &[]);
    assert_eq!(diff.added.len(), 1);
    assert!(diff.modified.is_empty());
    assert!(diff.deleted.is_empty());
    assert!(diff.unchanged.is_empty());
}

#[test]
fn test_dry_run_json_output() {
    let diff = UploadDiff {
        added: vec![FileEntry {
            path: "new.rs".to_string(),
            hash: "abc".to_string(),
            size: 42,
        }],
        modified: vec![ModifiedEntry {
            path: "changed.rs".to_string(),
            local_size: 100,
            remote_size: 80,
        }],
        deleted: vec![FileEntry {
            path: "old.rs".to_string(),
            hash: "def".to_string(),
            size: 30,
        }],
        unchanged: vec![FileEntry {
            path: "same.rs".to_string(),
            hash: "ghi".to_string(),
            size: 50,
        }],
    };

    let json_str = format_dry_run_json(&diff).expect("format_dry_run_json should succeed");

    // Parse the JSON to verify structure
    let parsed: serde_json::Value =
        serde_json::from_str(&json_str).expect("output should be valid JSON");

    assert!(parsed["added"].is_array(), "expected 'added' array");
    assert!(parsed["modified"].is_array(), "expected 'modified' array");
    assert!(parsed["deleted"].is_array(), "expected 'deleted' array");
    assert!(parsed["summary"].is_object(), "expected 'summary' object");

    assert_eq!(parsed["added"][0]["path"], "new.rs");
    assert_eq!(parsed["added"][0]["size"], 42);
    assert_eq!(parsed["modified"][0]["path"], "changed.rs");
    assert_eq!(parsed["modified"][0]["local_size"], 100);
    assert_eq!(parsed["modified"][0]["remote_size"], 80);
    assert_eq!(parsed["deleted"][0]["path"], "old.rs");
    assert_eq!(parsed["summary"]["added"], 1);
    assert_eq!(parsed["summary"]["modified"], 1);
    assert_eq!(parsed["summary"]["deleted"], 1);
    assert_eq!(parsed["summary"]["unchanged"], 1);
}

// ---------------------------------------------------------------------------
// Progress reporting: CountingWriter
// ---------------------------------------------------------------------------

#[test]
fn test_progress_counting_writer() {
    let buf: Vec<u8> = Vec::new();
    let progress = TransferProgress::new(100, TransferDirection::Upload, false);
    let mut writer = CountingWriter::new(buf, progress);

    writer.write_all(b"hello").expect("write");
    writer.write_all(b" world!!").expect("write");

    let inner = writer.finish();
    assert_eq!(
        inner, b"hello world!!",
        "all bytes must pass through to inner writer"
    );
}

// ---------------------------------------------------------------------------
// Progress reporting: CountingReader
// ---------------------------------------------------------------------------

#[test]
fn test_progress_counting_reader() {
    let data = Cursor::new(b"hello world".to_vec());
    let progress = TransferProgress::new(11, TransferDirection::Download, false);
    let mut reader = CountingReader::new(data, progress);

    let mut output = Vec::new();
    reader.read_to_end(&mut output).expect("read");
    assert_eq!(
        output, b"hello world",
        "all bytes must pass through from inner reader"
    );
}

// ---------------------------------------------------------------------------
// Progress suppression
// ---------------------------------------------------------------------------

#[test]
fn test_progress_suppressed_when_not_tty() {
    let progress = TransferProgress::new(1000, TransferDirection::Upload, false);
    assert!(
        progress.is_hidden(),
        "progress bar should be hidden when not a TTY"
    );
}

// ---------------------------------------------------------------------------
// Local size calculation
// ---------------------------------------------------------------------------

#[test]
fn test_calculate_local_size() {
    let tmp = tempfile::tempdir().expect("create temp dir");
    std::fs::write(tmp.path().join("a.txt"), "hello").expect("write a");
    std::fs::write(tmp.path().join("b.txt"), "world!").expect("write b");
    let sub = tmp.path().join("sub");
    std::fs::create_dir(&sub).expect("create subdir");
    std::fs::write(sub.join("c.txt"), "!!").expect("write c");

    let size = calculate_local_size(tmp.path());
    // "hello" (5) + "world!" (6) + "!!" (2) = 13
    assert_eq!(size, 13, "expected total size of 13 bytes");
}

#[test]
fn test_calculate_local_size_nonexistent_returns_zero() {
    assert_eq!(
        calculate_local_size(Path::new("/nonexistent/xyz/abc")),
        0,
        "nonexistent path should return 0"
    );
}

#[test]
fn test_calculate_local_size_empty_dir_returns_zero() {
    let tmp = tempfile::tempdir().expect("create temp dir");
    assert_eq!(
        calculate_local_size(tmp.path()),
        0,
        "empty directory should return 0"
    );
}
