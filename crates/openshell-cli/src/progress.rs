// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Progress reporting for upload and download transfers.
//!
//! Provides [`TransferProgress`] which wraps `indicatif::ProgressBar` to show
//! bytes transferred, rate, and ETA on stderr. When stderr is not a TTY the
//! progress bar is suppressed entirely (hidden draw target) so programmatic
//! consumers like DarkClaw are never polluted with ANSI escape codes.

use indicatif::{HumanBytes, ProgressBar, ProgressDrawTarget, ProgressStyle};
use std::io::{self, IsTerminal, Read, Write};
use std::path::Path;
use std::time::Duration;

// ---------------------------------------------------------------------------
// Pure helpers
// ---------------------------------------------------------------------------

/// Calculate total byte size of a local path (file or directory, recursive).
///
/// Returns 0 for empty directories, non-existent paths, or paths where all
/// entries are unreadable.
pub fn calculate_local_size(path: &Path) -> u64 {
    if path.is_file() {
        return path.metadata().map(|m| m.len()).unwrap_or(0);
    }
    if path.is_dir() {
        return sum_dir_size(path);
    }
    0
}

/// Calculate total byte size for a list of files relative to `base_dir`.
pub fn calculate_files_size(base_dir: &Path, files: &[String]) -> u64 {
    files
        .iter()
        .map(|f| {
            let full = base_dir.join(f);
            calculate_local_size(&full)
        })
        .sum()
}

fn sum_dir_size(dir: &Path) -> u64 {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return 0;
    };
    entries
        .filter_map(|e| e.ok())
        .map(|e| {
            let path = e.path();
            if path.is_file() {
                path.metadata().map(|m| m.len()).unwrap_or(0)
            } else if path.is_dir() {
                sum_dir_size(&path)
            } else {
                0
            }
        })
        .sum()
}

/// Format a byte count for display using `indicatif::HumanBytes`.
pub fn format_bytes(bytes: u64) -> String {
    format!("{}", HumanBytes(bytes))
}

// ---------------------------------------------------------------------------
// TransferProgress
// ---------------------------------------------------------------------------

/// Direction of the transfer, used for the progress bar prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferDirection {
    Upload,
    Download,
}

impl TransferDirection {
    fn label(self) -> &'static str {
        match self {
            Self::Upload => "Uploading",
            Self::Download => "Downloading",
        }
    }
}

/// Progress reporter wrapping an `indicatif::ProgressBar`.
///
/// Create via [`TransferProgress::new`] (known total) or
/// [`TransferProgress::new_unknown`] (unknown total / spinner mode).
pub struct TransferProgress {
    bar: ProgressBar,
}

impl TransferProgress {
    /// Create a progress bar with a known total byte count.
    ///
    /// When `is_tty` is false the bar uses a hidden draw target so no output
    /// is emitted. When `total` is 0 the bar is finished immediately.
    pub fn new(total: u64, direction: TransferDirection, is_tty: bool) -> Self {
        let bar = if is_tty {
            let pb = ProgressBar::with_draw_target(
                Some(total),
                ProgressDrawTarget::stderr_with_hz(10),
            );
            let style = ProgressStyle::with_template(
                "{prefix} [{wide_bar:.cyan/blue}] {bytes}/{total_bytes} {binary_bytes_per_sec} ETA {eta}",
            )
            .expect("valid progress bar template")
            .progress_chars("=>-");
            pb.set_style(style);
            pb.set_prefix(direction.label().to_string());
            pb.enable_steady_tick(Duration::from_millis(100));
            pb
        } else {
            let pb = ProgressBar::hidden();
            pb.set_length(total);
            pb
        };

        let this = Self { bar };

        // Zero-byte transfer: complete immediately.
        if total == 0 {
            this.bar
                .finish_with_message(format!("{} 0 B", direction.label()));
        }

        this
    }

    /// Create a progress bar for a transfer with unknown total (spinner mode).
    pub fn new_unknown(direction: TransferDirection, is_tty: bool) -> Self {
        let bar = if is_tty {
            let pb = ProgressBar::with_draw_target(
                None,
                ProgressDrawTarget::stderr_with_hz(10),
            );
            let style = ProgressStyle::with_template(
                "{prefix} {spinner:.green} {bytes} {binary_bytes_per_sec}",
            )
            .expect("valid spinner template");
            pb.set_style(style);
            pb.set_prefix(direction.label().to_string());
            pb.enable_steady_tick(Duration::from_millis(100));
            pb
        } else {
            ProgressBar::hidden()
        };

        Self { bar }
    }

    /// Report that `n` additional bytes have been transferred.
    pub fn inc(&self, n: u64) {
        self.bar.inc(n);
    }

    /// Mark the transfer as complete.
    pub fn finish(&self) {
        self.bar.finish_and_clear();
    }

    /// Abandon the progress bar (e.g. on error).
    #[allow(dead_code)]
    pub fn abandon(&self) {
        self.bar.abandon();
    }

    /// Returns whether this progress bar is hidden (non-TTY).
    pub fn is_hidden(&self) -> bool {
        self.bar.is_hidden()
    }

    /// Access the inner `ProgressBar` (for testing).
    #[cfg(test)]
    fn inner(&self) -> &ProgressBar {
        &self.bar
    }
}

// ---------------------------------------------------------------------------
// CountingWriter — wraps a Write, counts bytes, updates progress
// ---------------------------------------------------------------------------

/// A writer that counts bytes written through it and updates a progress bar.
///
/// The underlying writer receives all bytes unmodified.
pub struct CountingWriter<W: Write> {
    inner: W,
    progress: TransferProgress,
}

impl<W: Write> CountingWriter<W> {
    pub fn new(inner: W, progress: TransferProgress) -> Self {
        Self { inner, progress }
    }

    /// Consume the wrapper, finish the progress bar, and return the inner writer.
    pub fn finish(self) -> W {
        self.progress.finish();
        self.inner
    }
}

impl<W: Write> Write for CountingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.progress.inc(n as u64);
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

// ---------------------------------------------------------------------------
// CountingReader — wraps a Read, counts bytes, updates progress
// ---------------------------------------------------------------------------

/// A reader that counts bytes read through it and updates a progress bar.
///
/// The underlying reader's bytes pass through unmodified.
pub struct CountingReader<R: Read> {
    inner: R,
    progress: TransferProgress,
}

impl<R: Read> CountingReader<R> {
    pub fn new(inner: R, progress: TransferProgress) -> Self {
        Self { inner, progress }
    }

    /// Consume the wrapper, finish the progress bar, and return the inner reader.
    #[allow(dead_code)]
    pub fn finish(self) -> R {
        self.progress.finish();
        self.inner
    }
}

impl<R: Read> Read for CountingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.progress.inc(n as u64);
        Ok(n)
    }
}

// ---------------------------------------------------------------------------
// Convenience: detect TTY
// ---------------------------------------------------------------------------

/// Returns true if stderr is connected to a terminal.
pub fn stderr_is_tty() -> bool {
    io::stderr().is_terminal()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    // -- TTY detection / suppression --

    #[test]
    fn test_progress_suppressed_when_not_tty() {
        // When is_tty=false, the progress bar must be hidden.
        let progress = TransferProgress::new(1000, TransferDirection::Upload, false);
        assert!(progress.is_hidden());
    }

    #[test]
    fn test_progress_configured_when_tty() {
        // When is_tty=true, the progress bar is configured with the correct length.
        // Note: in test environments stderr may not be a real TTY, so indicatif may
        // still report is_hidden()=true. We verify our configuration intent instead.
        let progress = TransferProgress::new(1000, TransferDirection::Upload, true);
        assert_eq!(progress.inner().length(), Some(1000));
    }

    #[test]
    fn test_unknown_progress_suppressed_when_not_tty() {
        let progress = TransferProgress::new_unknown(TransferDirection::Download, false);
        assert!(progress.is_hidden());
    }

    // -- Zero-byte handling (EC-004) --

    #[test]
    fn test_zero_byte_transfer_completes() {
        // 0-byte upload must not panic (no division by zero) and finishes immediately.
        let progress = TransferProgress::new(0, TransferDirection::Upload, true);
        assert!(progress.inner().is_finished());
    }

    #[test]
    fn test_zero_byte_transfer_hidden() {
        let progress = TransferProgress::new(0, TransferDirection::Download, false);
        assert!(progress.is_hidden());
        assert!(progress.inner().is_finished());
    }

    // -- Size calculation --

    #[test]
    fn test_calculate_local_size_empty_dir() {
        let tmp = tempfile::tempdir().expect("create temp dir");
        assert_eq!(calculate_local_size(tmp.path()), 0);
    }

    #[test]
    fn test_calculate_local_size_file() {
        let tmp = tempfile::tempdir().expect("create temp dir");
        let file_path = tmp.path().join("hello.txt");
        std::fs::write(&file_path, "hello world").expect("write file");
        assert_eq!(calculate_local_size(&file_path), 11);
    }

    #[test]
    fn test_calculate_local_size_nested_dir() {
        let tmp = tempfile::tempdir().expect("create temp dir");
        let sub = tmp.path().join("sub");
        std::fs::create_dir(&sub).expect("create subdir");
        std::fs::write(tmp.path().join("a.txt"), "aaa").expect("write a");
        std::fs::write(sub.join("b.txt"), "bbbbb").expect("write b");
        assert_eq!(calculate_local_size(tmp.path()), 8); // 3 + 5
    }

    #[test]
    fn test_calculate_local_size_nonexistent() {
        assert_eq!(calculate_local_size(Path::new("/nonexistent/path/xyz")), 0);
    }

    #[test]
    fn test_calculate_files_size() {
        let tmp = tempfile::tempdir().expect("create temp dir");
        std::fs::write(tmp.path().join("a.txt"), "aaa").expect("write a");
        std::fs::write(tmp.path().join("b.txt"), "bbbbb").expect("write b");
        let files = vec!["a.txt".to_string(), "b.txt".to_string()];
        assert_eq!(calculate_files_size(tmp.path(), &files), 8);
    }

    #[test]
    fn test_calculate_files_size_empty_list() {
        let tmp = tempfile::tempdir().expect("create temp dir");
        assert_eq!(calculate_files_size(tmp.path(), &[]), 0);
    }

    // -- Format --

    #[test]
    fn test_format_bytes_zero() {
        assert_eq!(format_bytes(0), "0 B");
    }

    #[test]
    fn test_format_bytes_large() {
        let formatted = format_bytes(1_073_741_824); // 1 GiB
        assert!(formatted.contains("GiB"), "expected GiB in '{formatted}'");
    }

    // -- CountingWriter --

    #[test]
    fn test_counting_writer_passes_bytes_through() {
        let buf: Vec<u8> = Vec::new();
        let progress = TransferProgress::new(100, TransferDirection::Upload, false);
        let mut writer = CountingWriter::new(buf, progress);

        writer.write_all(b"hello").expect("write");
        writer.write_all(b" world").expect("write");

        let inner = writer.finish();
        assert_eq!(inner, b"hello world");
    }

    #[test]
    fn test_counting_writer_counts_bytes() {
        let buf: Vec<u8> = Vec::new();
        let progress = TransferProgress::new(100, TransferDirection::Upload, false);
        // Clone the bar handle to check position after wrapping.
        let bar_clone = progress.bar.clone();
        let mut writer = CountingWriter::new(buf, progress);

        writer.write_all(b"12345").expect("write");
        assert_eq!(bar_clone.position(), 5);

        writer.write_all(b"678").expect("write");
        assert_eq!(bar_clone.position(), 8);
    }

    // -- CountingReader --

    #[test]
    fn test_counting_reader_passes_bytes_through() {
        let data = Cursor::new(b"hello world".to_vec());
        let progress = TransferProgress::new(11, TransferDirection::Download, false);
        let mut reader = CountingReader::new(data, progress);

        let mut output = Vec::new();
        reader.read_to_end(&mut output).expect("read");
        assert_eq!(output, b"hello world");
    }

    #[test]
    fn test_counting_reader_counts_bytes() {
        let data = Cursor::new(b"hello world".to_vec());
        let progress = TransferProgress::new(11, TransferDirection::Download, false);
        let bar_clone = progress.bar.clone();
        let mut reader = CountingReader::new(data, progress);

        let mut buf = [0u8; 5];
        let n = reader.read(&mut buf).expect("read");
        assert_eq!(n, 5);
        assert_eq!(bar_clone.position(), 5);

        let mut rest = Vec::new();
        reader.read_to_end(&mut rest).expect("read rest");
        assert_eq!(bar_clone.position(), 11);
    }

    // -- Direction labels --

    #[test]
    fn test_direction_labels() {
        assert_eq!(TransferDirection::Upload.label(), "Uploading");
        assert_eq!(TransferDirection::Download.label(), "Downloading");
    }
}
