import unittest
import hashlib
import os
import shutil
import tempfile
import io
import sys
import threading
import time
from collections import deque
from pathlib import Path
from contextlib import redirect_stdout, redirect_stderr
from unittest.mock import mock_open, patch, MagicMock

# Ensure shasum.py is in the same directory
import shasum

class TestShasum(unittest.TestCase):
    def setUp(self):
        # Create a fresh playground for each test
        self.test_dir = Path(tempfile.mkdtemp())
        self.old_cwd = os.getcwd()
        os.chdir(self.test_dir)

    def tearDown(self):
        os.chdir(self.old_cwd)
        shutil.rmtree(self.test_dir)

    def create_file(self, name, content=b"content"):
        p = self.test_dir / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(content)
        return p

    def run_verify(self, line_data, is_tag, label, algo):
        """Helper to run verification while capturing output for inspection."""
        out, err = io.StringIO(), io.StringIO()
        exit_code = 0
        with redirect_stdout(out), redirect_stderr(err):
            try:
                shasum.verify_checksums(line_data, is_tag, label, algo)
            except SystemExit as e:
                exit_code = e.code
        return exit_code, out.getvalue(), err.getvalue()

    # --- FORMAT DETECTION & CONSENSUS TESTS ---

    def test_standard_format_with_nightmare_filename(self):
        """Standard format: Filename contains ' ( ' and ' = ' (Fake Tag Lookalike)"""
        name = "Report (Draft) = Final.txt"
        data = b"secret_data"
        self.create_file(name, data)
        h = hashlib.sha256(data).hexdigest()

        sums_file = self.create_file("sums.txt", f"{h}  {name}\n".encode())
        line_data, is_tag, label = shasum.get_input_and_format(str(sums_file))

        self.assertFalse(is_tag, "Consensus engine should reject fake tag format")
        code, out, _ = self.run_verify(line_data, is_tag, label, "sha256")
        self.assertEqual(code, 0)
        self.assertIn(f"{name}: OK", out)

    def test_consensus_engine_noise_filtering(self):
        """Consensus: Random junk lines shouldn't hijack the detected format"""
        h = "a" * 64
        content = [
            f"{h}  valid1.txt\n",
            "TOTALLY INVALID DATA LINE\n",
            f"{h}  valid2.txt\n",
            "SHA256 (fake) = aaaa\n", # One tag-lookalike in a standard file
            f"{h}  valid3.txt\n"
        ]
        sums_file = self.create_file("noisy.txt", "".join(content).encode())
        _, is_tag, _ = shasum.get_input_and_format(str(sums_file))
        self.assertFalse(is_tag, "Majority (3 vs 1) should remain Standard format")

    # --- PATH & UNICODE TORTURE ---

    def test_unicode_and_emoji_filenames(self):
        """Path Torture: UTF-8 emojis and symbols in filenames"""
        name = "🔥 file_π_test.txt"
        data = b"unicode_content"
        self.create_file(name, data)
        h = hashlib.sha256(data).hexdigest()

        # Test using BSD Tag format
        sums_file = self.create_file("unicode.txt", f"SHA256 ({name}) = {h}\n".encode('utf-8'))
        line_data, is_tag, label = shasum.get_input_and_format(str(sums_file))

        code, out, _ = self.run_verify(line_data, is_tag, label, "sha256")
        self.assertEqual(code, 0)
        self.assertIn(f"{name}: OK", out)

    def test_windows_style_paths(self):
        """Path Torture: Backslashes (common in Windows-generated sums files)"""
        name = "logs\\2024\\app.log"
        data = b"log_contents"
        self.create_file(name, data)
        h = hashlib.sha256(data).hexdigest()

        sums_file = self.create_file("win.txt", f"{h} *{name}\n".encode())
        line_data, is_tag, label = shasum.get_input_and_format(str(sums_file))

        code, out, _ = self.run_verify(line_data, is_tag, label, "sha256")
        self.assertEqual(code, 0)
        self.assertIn("OK", out)

    # --- ALGORITHM & DATA INTEGRITY ---

    def test_shake_dynamic_length_deduction(self):
        """SHAKE: Verify digest length is deduced from hex string length"""
        name = "variable_length.bin"
        data = b"shake_data"
        self.create_file(name, data)

        # Create a long 128-char hex (64-byte) SHAKE128 hash
        h = hashlib.shake_128(data).hexdigest(64)
        sums_file = self.create_file("sums.txt", f"{h}  {name}\n".encode())

        line_data, is_tag, label = shasum.get_input_and_format(str(sums_file))
        code, out, _ = self.run_verify(line_data, is_tag, label, "shake128")
        self.assertEqual(code, 0)
        self.assertIn("OK", out)

    def test_failed_checksum_reporting(self):
        """Integrity: Ensure FAILED status and correct warning on corruption"""
        name = "bad_data.txt"
        self.create_file(name, b"genuine_content")
        h = "f" * 64 # Wrong hash

        sums_file = self.create_file("fail.txt", f"{h}  {name}\n".encode())
        line_data, is_tag, label = shasum.get_input_and_format(str(sums_file))

        code, out, err = self.run_verify(line_data, is_tag, label, "sha256")
        self.assertEqual(code, 1)
        self.assertIn(f"{name}: FAILED", out)
        self.assertIn("1 computed checksum did NOT match", err)

    # --- SYSTEM & I/O EDGE CASES ---

    def oldtest_piped_stdin_input(self):
        """I/O: Simulate 'cat sums.txt | python3 shasum.py'"""
        name = "stdin_test.txt"
        data = b"piped_content"
        self.create_file(name, data)
        h = hashlib.sha256(data).hexdigest()

        stdin_content = f"{h}  {name}\n"
        old_stdin = sys.stdin
        sys.stdin = io.StringIO(stdin_content)

        try:
            line_data, is_tag, label = shasum.get_input_and_format("-")
            code, out, _ = self.run_verify(line_data, is_tag, label, "sha256")
            self.assertEqual(code, 0)
            self.assertIn("OK", out)
            self.assertEqual(label, "stdin")
        finally:
            sys.stdin = old_stdin

    def test_piped_stdin_input_mocked(self):
        """I/O: Simulate 'cat sums.txt | python3 shasum.py'"""
        # The content we want to simulate
        content = b"5d41402abc4b2a76b9719d911017c592  file.txt\n"

        # We must mock the buffer specifically
        mock_stdin = MagicMock()
        mock_stdin.buffer.read.return_value = content

        with patch('sys.stdin', mock_stdin):
            line_data, is_tag, label = shasum.get_input_and_format("-")

        self.assertEqual(label, "stdin")
        self.assertIn(0, line_data)
        self.assertEqual(line_data[0]['value'], "5d41402abc4b2a76b9719d911017c592  file.txt")

    def test_massive_file_hashing(self):
        """I/O: Ensure chunking/file_digest handles files larger than buffer"""
        name = "big_file.dat"
        # 1MB of data (Buffer is 32KB)
        data = b"ABCDEFGH" * 128 * 1024
        self.create_file(name, data)
        h = hashlib.sha256(data).hexdigest()

        sums_file = self.create_file("big.txt", f"{h}  {name}\n".encode())
        line_data, is_tag, label = shasum.get_input_and_format(str(sums_file))

        code, out, _ = self.run_verify(line_data, is_tag, label, "sha256")
        self.assertEqual(code, 0)
        self.assertIn("OK", out)

    def test_missing_files_skipped(self):
        """Resilience: Missing files should be skipped per requirements"""
        sums_file = self.create_file("missing.txt", b"a"*64 + b"  ghost.file\n")
        line_data, is_tag, label = shasum.get_input_and_format(str(sums_file))

        # Should exit 1 because 0 files were verified
        code, out, err = self.run_verify(line_data, is_tag, label, "sha256")
        self.assertEqual(code, 1)
        self.assertIn("no file was verified", err)
        self.assertNotIn("FAILED", out)

    def test_file_modified_mocked(self):
        """Safety: Use mocking to simulate a file change during hashing."""
        from itertools import cycle
        # 1. SETUP PHASE (Uses real filesystem)
        name = "mock_test.bin"
        data = b"A" * 1024
        self.create_file(name, data)
        h = hashlib.sha256(data).hexdigest()
        sums_file = self.create_file("mock.txt", f"{h}  {name}\n".encode())

        # 2. DEFINE MOCKS (33188 = Regular File)
        stat_scan = MagicMock(st_size=1024, st_mtime=1000.0, st_mode=33188, st_ino=1)
        stat_worker = MagicMock(st_size=2048, st_mtime=2000.0, st_mode=33188, st_ino=1)

        # 3. EXECUTION PHASE (Scoped Patch)
        # We only patch while calling the script's functions
        with patch('shasum.Path.stat') as mock_stat:
            # Provide enough values for: exists(), stat() in scan, and worker checks
            mock_stat.side_effect = [stat_scan, stat_scan, stat_scan, stat_worker, stat_worker]
            mock_stat.side_effect = cycle([stat_scan, stat_worker])

            line_data, is_tag, label = shasum.get_input_and_format(str(sums_file))
            code, out, err = self.run_verify(line_data, is_tag, label, "sha256")

        # 4. ASSERTIONS
        self.assertEqual(code, 1)
        self.assertIn("File modified since scan", out)

    def test_consensus_split_tie_breaker(self):
        """Consensus: Ensure a 50/50 mix defaults to Standard format."""
        # Setup: 1 Standard line, 1 Tag line
        self.create_file("file1.txt", b"data1")
        self.create_file("file2.txt", b"data2")

        # Standard: hash  file
        # Tag: ALGO (file) = hash
        lines = [
            f"{hashlib.sha256(b'data1').hexdigest()}  file1.txt",
            f"SHA256 (file2.txt) = {hashlib.sha256(b'data2').hexdigest()}"
        ]

        # Mocking the input processing logic from get_input_and_format
        # In a real run, this would be passed to verify_checksums
        content = {
            0: {'value': lines[0], 'skipped': False, 'format': 'standard'},
            1: {'value': lines[1], 'skipped': False, 'format': 'tag'},
            'counts': {'standard': 1, 'tag': 1}
        }

        # is_tag should be False because 1 is NOT > 1
        is_tag = content['counts'].get('tag', 0) > content['counts'].get('standard', 0)
        self.assertFalse(is_tag)

        exit_code, out, err = self.run_verify(content, is_tag, "mixed.txt", "sha256")

        # Should verify file1.txt (Standard), but warn about file2.txt (Tag line is invalid in Standard mode)
        self.assertIn("file1.txt: OK", out)
        self.assertIn("WARNING: improperly formatted line", err)

    def test_hash_length_mismatch_protection(self):
        """Integrity: Flag lines where hash length doesn't match algorithm expectation."""
        self.create_file("target.txt", b"some data")
        short_hash = "a" * 32 # MD5 length

        # Line is valid 'standard' format (hex + space + name),
        # but 'short_hash' is wrong for SHA256.
        content = {
            0: {'value': f"{short_hash}  target.txt", 'skipped': False, 'format': 'standard'},
            'counts': {'standard': 1}
        }

        # verify_checksums regex for sha256 expects 64 chars
        exit_code, out, err = self.run_verify(content, False, "short.txt", "sha256")

        self.assertEqual(exit_code, 1)
        self.assertIn("FAILED", out) # Digest mismatch

    def test_unreadable_file_reporting(self):
        """Resilience: Ensure permission denied or locked files report as FAILED (Error)."""
        p = self.create_file("locked.txt")
        p.chmod(0o000) # Remove all permissions

        h = hashlib.sha256(b"content").hexdigest()
        content = {
            0: {'value': f"{h}  locked.txt", 'skipped': False, 'format': 'standard'},
            'counts': {'standard': 1}
        }

        try:
            exit_code, out, err = self.run_verify(content, False, "test.txt", "sha256")
            self.assertIn("locked.txt: FAILED (Error: [Errno 13] Permission denied", out)
            self.assertEqual(exit_code, 1)
        finally:
            p.chmod(0o644) # Cleanup for tearDown

    def test_manifest_with_bom(self):
        """Format: Ensure UTF-8 BOM is stripped and doesn't corrupt the first hash."""
        h = hashlib.sha256(b"data").hexdigest()
        # Prepend the UTF-8 BOM (EF BB BF)
        content = b'\xef\xbb\xbf' + f"{h}  file.txt\n".encode('utf-8')

        manifest = self.create_file("sums.txt", content)
        self.create_file("file.txt", b"data")

        # This will trigger get_input_and_format -> p.read_text(encoding='utf-8-sig')
        line_data, is_tag, label = shasum.get_input_and_format(str(manifest))

        # Verify the first line doesn't contain the BOM character
        self.assertNotIn('\ufeff', line_data[0]['value'])

        exit_code, out, err = self.run_verify(line_data, is_tag, label, "sha256")
        self.assertEqual(exit_code, 0)
        self.assertIn("file.txt: OK", out)

    def test_mixed_line_endings_in_manifest(self):
        """Format: Handle manifests with mixed \r\n and \n line endings."""
        h1 = hashlib.sha256(b"1").hexdigest()
        h2 = hashlib.sha256(b"2").hexdigest()
        # Mix of Windows and Unix endings
        raw_content = f"{h1}  f1.txt\r\n{h2}  f2.txt\n".encode('utf-8')

        manifest = self.create_file("mixed_endings.txt", raw_content)
        self.create_file("f1.txt", b"1")
        self.create_file("f2.txt", b"2")

        line_data, is_tag, label = shasum.get_input_and_format(str(manifest))
        exit_code, out, err = self.run_verify(line_data, is_tag, label, "sha256")

        self.assertEqual(exit_code, 0)
        self.assertIn("f1.txt: OK", out)
        self.assertIn("f2.txt: OK", out)

    def test_stdin_bom_rejection(self):
        """I/O: Ensure stdin rejects manifests starting with a UTF-8 BOM."""
        bom_content = b'\xef\xbb\xbfhash  file.txt\n'

        # Mock sys.stdin.buffer.read to simulate the piped BOM input
        with patch('sys.stdin.buffer.read', return_value=bom_content):
            with self.assertRaises(SystemExit) as cm:
                with redirect_stderr(io.StringIO()) as err:
                    shasum.get_input_and_format("-")

            self.assertEqual(cm.exception.code, 1)
            self.assertIn("UTF-8 BOM detected", err.getvalue())

    def test_utf16le_file_rejection(self):
        """Format: Explicitly reject UTF-16 Little Endian manifest files."""
        # \xff\xfe is the UTF-16 LE BOM
        content = b'\xff\xfe' + "hash  file.txt".encode('utf-16le')
        manifest = self.create_file("utf16le.txt", content)

        with self.assertRaises(SystemExit) as cm:
            with redirect_stderr(io.StringIO()) as err:
                shasum.get_input_and_format(str(manifest))

        self.assertEqual(cm.exception.code, 1)
        self.assertIn("UTF-16 manifest detected", err.getvalue())

    def test_utf16be_stdin_rejection(self):
        """I/O: Explicitly reject UTF-16 Big Endian manifests from stdin."""
        # \xfe\xff is the UTF-16 BE BOM
        bom_content = b'\xfe\xff' + "hash  file.txt".encode('utf-16be')

        mock_stdin = MagicMock()
        mock_stdin.buffer.read.return_value = bom_content

        with patch('sys.stdin', mock_stdin):
            with self.assertRaises(SystemExit) as cm:
                with redirect_stderr(io.StringIO()) as err:
                    shasum.get_input_and_format("-")

            self.assertEqual(cm.exception.code, 1)
            self.assertIn("UTF-16 BOM detected", err.getvalue())

    def test_symlink_to_directory_skipped(self):
        """Safety: Ensure symlinks pointing to directories are skipped, not opened as files."""
        # Create a directory and a link to it
        target_dir = self.test_dir / "real_dir"
        target_dir.mkdir()
        link_path = self.test_dir / "link_to_dir"

        # os.symlink is available on Unix and Windows (with proper perms)
        try:
            os.symlink(target_dir, link_path)
        except OSError:
            self.skipTest("Symlinks not supported in this environment")

        h = hashlib.sha256(b"").hexdigest()
        content = {
            0: {'value': f"{h}  link_to_dir", 'skipped': False, 'format': 'standard'},
            'counts': {'standard': 1}
        }

        exit_code, out, err = self.run_verify(content, False, "test.txt", "sha256")

        # Should skip because is_file() is False for a directory symlink
        self.assertIn("no file was verified", err)

    def test_strict_line_termination_with_warning(self):
        """Security: Ensure trailing noise is treated as filename and triggers a warning."""
        h = hashlib.sha256(b"data").hexdigest()
        self.create_file("target.txt", b"data")

        # Manifest line with noise
        malicious_line = f"{h}  target.txt  # extra noise"

        content = {
            0: {'value': malicious_line, 'skipped': False, 'format': 'standard'},
            'counts': {'standard': 1}
        }

        exit_code, out, err = self.run_verify(content, False, "dirty.txt", "sha256")

        # 1. Should warn about the '#' in the filename
        self.assertIn("contained a '#' character", err)
        # 2. Should eventually report no files verified (since 'target.txt #...' doesn't exist)
        self.assertIn("no file was verified", err)
        self.assertEqual(exit_code, 1)

    def test_path_traversal_manifest(self):
        """Security: Ensure manifest cannot trick the tool into hashing outside the target directory."""
        # Create a sensitive file 'outside' our test dir (simulated by a sibling dir)
        outside_dir = self.test_dir.parent / "outside_scope"
        outside_dir.mkdir(exist_ok=True)
        secret_file = outside_dir / "secret.txt"
        secret_file.write_bytes(b"sensitive data")

        h = hashlib.sha256(b"sensitive data").hexdigest()
        # Manifest attempts to escape via traversal
        traversal_path = "../outside_scope/secret.txt"
        content = {
            0: {'value': f"{h}  {traversal_path}", 'skipped': False, 'format': 'standard'},
            'counts': {'standard': 1}
        }

        exit_code, out, err = self.run_verify(content, False, "evil.txt", "sha256")

        # Even if the file exists, the tool should report no files verified
        # because the traversal makes the relative path lookup fail or skip.
        self.assertIn("no file was verified", err)
        self.assertNotIn("OK", out)

    def test_zero_byte_and_buffer_edge(self):
        """I/O: Verify 0-byte files and files exactly at buffer size limits."""
        buf_size = 1024 * 1024 # 1 MiB matching your script's pool size

        # 0-byte file
        self.create_file("zero.txt", b"")
        h_zero = hashlib.sha256(b"").hexdigest()

        # File exactly at buffer size
        exact_data = b"A" * buf_size
        self.create_file("exact.txt", exact_data)
        h_exact = hashlib.sha256(exact_data).hexdigest()

        content = {
            0: {'value': f"{h_zero}  zero.txt", 'skipped': False, 'format': 'standard'},
            1: {'value': f"{h_exact}  exact.txt", 'skipped': False, 'format': 'standard'},
            'counts': {'standard': 2}
        }

        exit_code, out, err = self.run_verify(content, False, "edge.txt", "sha256")

        self.assertEqual(exit_code, 0)
        self.assertIn("zero.txt: OK", out)
        self.assertIn("exact.txt: OK", out)

    def test_path_resolve_symlink_loop(self):
        """Security: Ensure the tool handles infinite symlink loops gracefully."""
        # Create an infinite loop: link_a -> link_b -> link_a
        link_a = self.test_dir / "loop_a"
        link_b = self.test_dir / "loop_b"

        # We use os.symlink to bypass pathlib's safety checks during setup
        os.symlink(link_b, link_a)
        os.symlink(link_a, link_b)

        # Manifest entry pointing to the loop
        h = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        content = {0: {'value': f"{h}  loop_a", 'skipped': False, 'format': 'standard'}, 'counts': {'standard': 1}}

        exit_code, out, err = self.run_verify(content, False, "loop.txt", "sha256")

        # Should catch the RuntimeError and print your "could not be resolved" warning
        self.assertIn("skipping path that could not be resolved", err)
        self.assertEqual(exit_code, 1)

    def test_path_resolve_oserror_mock(self):
        """Resilience: Verify the catch-all for OSError during path resolution."""
        self.create_file("test.txt")

        # We want Path().resolve() to work for abs_cwd, but fail for target_path
        original_resolve = Path.resolve
        def side_effect(self_obj, *args, **kwargs):
            # If resolving 'test.txt', throw the error
            if "test.txt" in str(self_obj):
                raise OSError("Device not ready")
            return original_resolve(self_obj, *args, **kwargs)

        with patch.object(Path, 'resolve', autospec=True, side_effect=side_effect):
            content = {
                0: {'value': f"{'a'*64}  test.txt", 'skipped': False, 'format': 'standard'},
                'counts': {'standard': 1}
            }
            exit_code, out, err = self.run_verify(content, False, "err.txt", "sha256")
            self.assertIn("could not be resolved: Device not ready", err)

    def test_broken_pipe_exit_code(self):
        """I/O: Ensure stdout handles BrokenPipeError by exiting with 141."""
        with patch('sys.stdout.write', side_effect=BrokenPipeError):
            with self.assertRaises(SystemExit) as cm:
                shasum.stdout("test")
            self.assertEqual(cm.exception.code, 141)

    def test_concurrency_state_stress(self):
        """Safety: Stress the STATE_LOCK and IO_LOCK with a high-volume task storm."""
        file_count = 500
        manifest_lines = []
        for i in range(file_count):
            name = f"stress_{i}.bin"
            data = b"constant data"
            self.create_file(name, data)
            h = hashlib.sha256(data).hexdigest()
            manifest_lines.append(f"{h}  {name}\n")

        sums_file = self.create_file("stress_test.txt", "".join(manifest_lines).encode())
        line_data, is_tag, label = shasum.get_input_and_format(str(sums_file))

        code, out, err = self.run_verify(line_data, is_tag, label, "sha256")
        output_lines = [l for l in out.splitlines() if "OK" in l]
        self.assertEqual(len(output_lines), file_count)
        self.assertEqual(code, 0)

    def test_file_deleted_before_hashing(self):
        """Resilience: Handle a file deleted after manifest parsing."""
        name = "gone.bin"
        self.create_file(name, b"data")
        manifest = f"{hashlib.sha256(b'data').hexdigest()}  {name}\n"
        sums_file = self.create_file("del_test.txt", manifest.encode())
        line_data, is_tag, label = shasum.get_input_and_format(str(sums_file))

        os.remove(name)
        code, out, err = self.run_verify(line_data, is_tag, label, "sha256")

        # Combine streams to catch the failure message reliably
        self.assertIn(": WARNING: ", err)
        self.assertIn("/del_test.txt: no file was verified", err)
        self.assertEqual(code, 1)

    def test_interleaved_scheduling_priority(self):
        """Priority: Ensure a stalled 'large' digest doesn't block smaller files."""
        sizes = [2 * 1024 * 1024, 512 * 1024, 1024, 512, 128]
        filenames = []
        for i, size in enumerate(sizes):
            name = f"file_{size}_{i}.bin"
            data = os.urandom(size)
            self.create_file(name, data)
            filenames.append((hashlib.sha256(data).hexdigest(), name, data))

        manifest = "".join([f"{h}  {n}\n" for h, n, d in filenames])
        line_data, _, label = shasum.get_input_and_format(self.create_file("test.txt", manifest.encode()))

        class HashProxy:
            def __init__(self, real_hasher):
                self.real = real_hasher
            def update(self, data):
                if len(data) >= 1024 * 1024:
                    time.sleep(0.4)
                return self.real.update(data)
            def hexdigest(self, *args):
                return self.real.hexdigest(*args)

        # Capture the original before the patch starts
        original_new = hashlib.new

        def stalled_new(algo, *args, **kwargs):
            # Use the captured original_new to avoid recursion
            return HashProxy(original_new(algo, *args, **kwargs))

        with patch('hashlib.new', side_effect=stalled_new):
            code, out, err = self.run_verify(line_data, False, label, "sha256")

        output_lines = [l for l in out.splitlines() if "OK" in l]
        self.assertTrue(output_lines, f"No output lines captured. Full output:\n{out}\nError:\n{err}")
        self.assertIn("file_2097152_0.bin", output_lines[-1], "Largest file did not finish last.")
        self.assertEqual(code, 0)

    def test_large_file_slot_serialization(self):
        """Scheduling: Prove the 'in-flight' large file count never exceeds 1 under heavy cloud-scale load."""
        # 1. Setup: 2 Large files (2MB, 1.5MB) and 512 filler files (8k - 1 bytes)
        # 512 files ensures saturation even on the largest 128+ vCPU instances.
        filler_count = 512
        filler_size = (8 * 1024) - 1
        sizes = [2 * 1024 * 1024, 1536 * 1024] + ([filler_size] * filler_count)
        filenames = []
        for i, s in enumerate(sizes):
            name = f"task_{s}_{i}.bin"
            data = os.urandom(s)
            self.create_file(name, data)
            filenames.append((hashlib.sha256(data).hexdigest(), name, data))

        manifest = "".join([f"{h}  {n}\n" for h, n, d in filenames])
        line_data, _, label = shasum.get_input_and_format(self.create_file("test_slot.txt", manifest.encode()))

        # 2. Tracking State
        in_flight_large = 0
        max_observed_large = 0
        counter_lock = threading.Lock()
        original_new = hashlib.new

        class HashProxy:
            def __init__(self, real):
                self.real = real
                self.total_seen = 0
                self.is_large_file = False

            def update(self, data):
                nonlocal in_flight_large, max_observed_large
                self.total_seen += len(data)

                # Case A: Heavy task (> 1MiB cumulative)
                if not self.is_large_file and self.total_seen > 1024 * 1024:
                    self.is_large_file = True
                    with counter_lock:
                        in_flight_large += 1
                        max_observed_large = max(max_observed_large, in_flight_large)

                    # Hold the heavy slot to test for overlapping execution
                    time.sleep(0.2)

                # Case B: Filler task (single 8k chunk)
                elif not self.is_large_file:
                    # Slight sleep to keep 128+ threads busy with 512 files
                    time.sleep(0.01)

                return self.real.update(data)

            def hexdigest(self, *args):
                nonlocal in_flight_large
                if self.is_large_file:
                    with counter_lock:
                        in_flight_large -= 1
                return self.real.hexdigest(*args)

        # 3. Execution with recursive-safe patch
        with patch('hashlib.new', side_effect=lambda a, *args, **kwargs: HashProxy(original_new(a, *args, **kwargs))):
            code, out, err = self.run_verify(line_data, False, label, "sha256")

        # 4. Final Validation
        self.assertTrue(out, f"No output captured. Full output:\n{out}")
        # If the logic failed on ANY core count, this will be > 1.
        self.assertEqual(max_observed_large, 1, f"Serialization Failed: {max_observed_large} large files ran together.")
        self.assertEqual(code, 0)

    def test_concurrency_during_io_stall(self):
        """Verify that a slow-reading file does not block other worker threads."""
        # 1. Setup: 1 'Slow' file (2MB - bypasses fill_buffer) and 256 'Fast' fillers (8k-1)
        slow_name = "slow_disk_lat.bin"
        self.create_file(slow_name, b"L" * 2 * 1024 * 1024)
        l_hash = hashlib.sha256(b"L" * 2 * 1024 * 1024).hexdigest()

        manifest = [f"{l_hash}  {slow_name}\n"]
        for i in range(256):
            name = f"fast_{i}.bin"
            data = b"f" * 8191
            self.create_file(name, data)
            manifest.append(f"{hashlib.sha256(data).hexdigest()}  {name}\n")

        line_data, _, label = shasum.get_input_and_format(self.create_file("test_lat.txt", "".join(manifest).encode()))

        # PRE-PATCH CAPTURE
        real_std_base = shasum._std_base
        real_path_open = Path.open
        main_thread_id = threading.get_ident() # Capture main thread ID

        first_fast_time = None
        slow_finish_time = None
        start_time = time.perf_counter()

        def timed_std_base(*args, **kwargs):
            nonlocal first_fast_time, slow_finish_time
            output_str = str(args) if args else ""
            if "fast_" in output_str and first_fast_time is None:
                first_fast_time = time.perf_counter() - start_time
            elif slow_name in output_str:
                slow_finish_time = time.perf_counter() - start_time
            return real_std_base(*args, **kwargs)

        def slow_open_proxy(path_obj, *args, **kwargs):
            # PROTECT MAIN THREAD: Only sleep if it's a worker thread
            if path_obj.name == slow_name and threading.get_ident() != main_thread_id:
                time.sleep(0.5)
            return real_path_open(path_obj, *args, **kwargs)

        # 3. Execution
        with patch('shasum._std_base', side_effect=timed_std_base):
            with patch.object(Path, 'open', side_effect=slow_open_proxy, autospec=True):
                code, out, err = self.run_verify(line_data, False, label, "sha256")

        # 4. Validation
        self.assertIsNotNone(first_fast_time, f"Fast files blocked. Output: {out}")
        print(f"   [Metric] TTFR (First Fast): {first_fast_time:.4f}s")
        print(f"   [Metric] Slow File Finish: {slow_finish_time:.4f}s")

        self.assertLess(first_fast_time, 0.2, f"TTFR too high: {first_fast_time:.4f}s")
        self.assertGreater(slow_finish_time, 0.45, f"Slow file finished too early: {slow_finish_time:.4f}s")
        self.assertEqual(code, 0)

    def test_ttfr_responsiveness(self):
        """Metric: Measure TTFR by capturing the timestamp of the first atomic print."""
        # 1. Setup: 1 Large blocker (2MB) and 256 filler files (8k-1)
        filler_count = 256
        filler_size = (8 * 1024) - 1
        self.create_file("blocker.bin", b"B" * 2 * 1024 * 1024)

        manifest = f"{hashlib.sha256(b'B'*2*1024*1024).hexdigest()}  blocker.bin\n"
        for i in range(filler_count):
            name = f"tiny_{i}.bin"
            data = b"t" * filler_size
            self.create_file(name, data)
            manifest += f"{hashlib.sha256(data).hexdigest()}  {name}\n"

        line_data, _, label = shasum.get_input_and_format(self.create_file("test_ttfr.txt", manifest.encode()))

        first_result_time = None
        start_time = time.perf_counter()

        # We wrap the original stdout helper to catch the exact moment of the first print
        original_std_base = shasum._std_base
        def timed_std_base(*args, **kwargs):
            nonlocal first_result_time
            if first_result_time is None:
                first_result_time = time.perf_counter()
            return original_std_base(*args, **kwargs)

        # Proxy to stall the large hash
        original_new = hashlib.new
        class TTFRProxy:
            def __init__(self, real):
                self.real, self.seen, self.stalled = real, 0, False
            def update(self, data):
                self.seen += len(data)
                if not self.stalled and self.seen > 1024 * 1024:
                    self.stalled = True
                    time.sleep(0.4)
                return self.real.update(data)
            def hexdigest(self, *args): return self.real.hexdigest(*args)

        # 2. Execution
        with patch('shasum._std_base', side_effect=timed_std_base):
            with patch('hashlib.new', side_effect=lambda a, *args, **kwargs: TTFRProxy(original_new(a, *args, **kwargs))):
                code, out, err = self.run_verify(line_data, False, label, "sha256")

        # 3. Validation
        actual_ttfr = (first_result_time - start_time) if first_result_time else 999
        print(f"   [Metric] TTFR (First Print): {actual_ttfr:.4f}s")

        self.assertTrue(out, "No output captured.")
        self.assertLess(actual_ttfr, 0.2, f"TTFR failed; first result was blocked. Time: {actual_ttfr:.4f}s")
        self.assertEqual(code, 0)

    def test_hashing_performance(self):
        """Performance: Measure throughput and execution time for 100 MiB."""
        # 1. Setup: Create 100 files of 1 MiB each
        file_count = 100
        size_per_file = 1024 * 1024  # 1 MiB
        total_mib = (file_count * size_per_file) / (1024 * 1024)

        print(f"\n   [Perf] Generating {total_mib} MiB of test data...")
        sums_content = []
        for i in range(file_count):
            name = f"perf_test_{i}.bin"
            data = os.urandom(size_per_file)
            self.create_file(name, data)
            h = hashlib.sha256(data).hexdigest()
            sums_content.append(f"{h}  {name}\n")

        sums_file = self.create_file("perf.txt", "".join(sums_content).encode())
        line_data, is_tag, label = shasum.get_input_and_format(str(sums_file))

        # 2. Execution: Measure the time taken to verify
        start_time = time.perf_counter()
        code, out, err = self.run_verify(line_data, is_tag, label, "sha256")
        end_time = time.perf_counter()

        duration = end_time - start_time
        throughput = total_mib / duration

        # 3. Log Statistics
        print(f"   [Perf] Verified {file_count} files ({total_mib} MiB)")
        print(f"   [Perf] Total Time: {duration:.4f} seconds")
        print(f"   [Perf] Throughput: {throughput:.2f} MiB/s")

        self.assertEqual(code, 0, "Performance test verification failed")
        self.assertGreater(throughput, 0, "Throughput should be a positive value")


if __name__ == "__main__":
    # ANSI Color Runner for friendly output
    print(f"\n\033[1;34m--- Stress Testing {shasum.PROG_NAME} {shasum.VERSION_STR} ---\033[0m")
    suite = unittest.TestLoader().loadTestsFromTestCase(TestShasum)
    result = unittest.TextTestRunner(verbosity=2).run(suite)

    if result.wasSuccessful():
        print(f"\n\033[1;32mSUCCESS: All {result.testsRun} nightmare cases passed.\033[0m\n")
    else:
        print("\n\033[1;31mFAILURE: Check logic errors above.\033[0m\n")
        sys.exit(1)

