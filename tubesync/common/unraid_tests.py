import unittest
from unittest.mock import patch, mock_open
import io

# Explicit namespace assignment from your production module file
from unraid import Unraid, detect_unraid, _stream_contains_keyword


class TestUnraidDetector(unittest.TestCase):

    def setUp(self):
        """Resets the mutable state sentinel description prior to every single test pass."""
        Unraid.reason = 'Unraid Host Environment Detected'

    @patch('builtins.open', new_callable=mock_open, read_data=b'6.1.64-unraid-slackware')
    def test_detection_via_proc_version_success(self, mock_file):
        """Validates successful matching when an Unraid kernel signature is present."""
        result = detect_unraid()
        self.assertIs(result, Unraid)
        self.assertEqual(Unraid.reason, 'Unraid detected via host path: /proc/version')

    @patch('builtins.open')
    def test_detection_via_proc_cmdline_success(self, mock_open_func):
        """Validates fallback execution when previous metrics miss but boot line matches."""
        def side_effect(filepath, mode):
            if filepath == '/proc/version':
                return io.BytesIO(b'standard linux kernel version configuration pool')
            if filepath == '/proc/cmdline':
                return io.BytesIO(b'initrd=bzroot unraid.cmdline BOOT_IMAGE=bzimage root=tmpfs')
            return io.BytesIO(b'')

        mock_open_func.side_effect = side_effect
        result = detect_unraid()
        self.assertIs(result, Unraid)
        self.assertEqual(Unraid.reason, 'Unraid detected via host path: /proc/cmdline')

    @patch('builtins.open')
    def test_detection_via_proc_mdstat_success(self, mock_open_func):
        """Validates that custom array definitions flag the sentinel successfully."""
        def side_effect(filepath, mode):
            if filepath in ('/proc/version', '/proc/cmdline'):
                return io.BytesIO(b'generic linux system environment parameters')
            if filepath == '/proc/mdstat':
                return io.BytesIO(b'Personalities : \nUnraid MD status: online, parity checked ok\n')
            return io.BytesIO(b'')

        mock_open_func.side_effect = side_effect
        result = detect_unraid()
        self.assertIs(result, Unraid)
        self.assertEqual(Unraid.reason, 'Unraid detected via host path: /proc/mdstat')

    @patch('builtins.open')
    def test_detection_via_shfs_mount_success(self, mock_open_func):
        """Validates that a clean raw shfs storage filesystem type registers correctly."""
        def side_effect(filepath, mode):
            if filepath in ('/proc/version', '/proc/cmdline', '/proc/mdstat'):
                return io.BytesIO(b'standard non-raid system layout configurations')
            if filepath == '/proc/mounts':
                return io.BytesIO(b'shfs /config shfs rw,noatime,uid=99,gid=100 0 0\n')
            return io.BytesIO(b'')

        mock_open_func.side_effect = side_effect
        result = detect_unraid()
        self.assertIs(result, Unraid)
        self.assertEqual(Unraid.reason, 'Unraid detected via active storage pool mount (shfs)')

    @patch('builtins.open')
    def test_detection_via_fuse_shfs_mount_success(self, mock_open_func):
        """Validates that case-insensitive user-space FUSE shfs wrappers map correctly."""
        def side_effect(filepath, mode):
            if filepath in ('/proc/version', '/proc/cmdline', '/proc/mdstat'):
                return io.BytesIO(b'standard non-raid system layout configurations')
            if filepath == '/proc/mounts':
                return io.BytesIO(b'shfs /data fuse.SHFS rw,nosuid,nodev,noatime 0 0\n')
            return io.BytesIO(b'')

        mock_open_func.side_effect = side_effect
        result = detect_unraid()
        self.assertIs(result, Unraid)
        self.assertEqual(Unraid.reason, 'Unraid detected via active storage pool mount (fuse.shfs)')

    @patch('builtins.open')
    def test_detection_all_signals_missing_failure(self, mock_open_func):
        """Validates that a default non-Unraid host returns an implicit None validation path."""
        def side_effect(filepath, mode):
            if filepath == '/proc/mounts':
                return io.BytesIO(b'overlay / overlay rw,relatime 0 0\ntmpfs /run tmpfs rw 0 0\n')
            return io.BytesIO(b'generic baseline linux kernel signature file description text')

        mock_open_func.side_effect = side_effect
        result = detect_unraid()
        self.assertIsNone(result)

    @patch('builtins.open')
    def test_boundary_split_keyword_success(self, mock_open_func):
        """Validates out-of-order slice tracking when a keyword splits across read blocks."""
        class SplitBytesIO:
            def __init__(self):
                self.chunks = [b'aaun', b'raid']
                self.index = 0
            def read(self, size):
                if self.index < len(self.chunks):
                    data = self.chunks[self.index]
                    self.index += 1
                    return data
                return b''
            def __enter__(self): return self
            def __exit__(self, *args): pass

        mock_open_func.return_value = SplitBytesIO()

        # Enforcing a tiny 4-byte block size forces the word "unraid" to break exactly across steps
        is_found = _stream_contains_keyword('/proc/version', b'unraid', block_size=4)
        self.assertTrue(is_found)

    @patch('builtins.open')
    def test_malformed_mounts_file_ignored_safely(self, mock_open_func):
        """Validates that row parsing abnormalities or raw binary noises avoid crashing loops."""
        def side_effect(filepath, mode):
            if filepath in ('/proc/version', '/proc/cmdline', '/proc/mdstat'):
                return io.BytesIO(b'standard system specifications')
            if filepath == '/proc/mounts':
                return io.BytesIO(b'short_row\nbad_column_count string\n\\xff\\xfe mount corrupted_fs_type rw 0\n')
            return io.BytesIO(b'')

        mock_open_func.side_effect = side_effect
        result = detect_unraid()
        self.assertIsNone(result)

    @patch('builtins.open')
    def test_permission_or_missing_file_errors_handled_safely(self, mock_open_func):
        """Validates defensive exception exclusions if file layers are locked by AppArmor/SELinux."""
        mock_open_func.side_effect = PermissionError('System file access restricted by environment profile')

        try:
            result = detect_unraid()
            raised = False
        except Exception:
            raised = True

        self.assertFalse(raised)
        self.assertIsNone(result)


if __name__ == '__main__':
    unittest.main()

