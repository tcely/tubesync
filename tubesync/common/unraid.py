class _UnraidSentinelType:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance.reason = 'Unraid Host Environment Detected'
        return cls._instance

    def __repr__(self) -> str:
        return 'Unraid'

    def __str__(self) -> str:
        return self.reason


Unraid = _UnraidSentinelType()


def _stream_contains_keyword(filepath: str, keyword: bytes, block_size: int = 0) -> bool:
    if 0 >= block_size:
        block_size = 2048

    window = bytearray()
    overlap_len = 2 * len(keyword)
    max_buf_len = overlap_len + block_size

    try:
        with open(filepath, 'rb') as f:
            chunk = f.read(block_size)
            while chunk:
                window.extend(chunk.lower())
                if keyword in window:
                    return True
                if max_buf_len < len(window):
                    window = window[-overlap_len:]
                chunk = f.read(block_size)
    except (FileNotFoundError, PermissionError):
        pass
    return False


def detect_unraid():
    """Scans the environment for Unraid signatures using a safe sliding window
    and specific mount verification.
    """
    proc_files = ['/proc/version', '/proc/cmdline', '/proc/mdstat']
    for filepath in proc_files:
        if _stream_contains_keyword(filepath, b'unraid'):
            Unraid.reason = f'Unraid detected via host path: {filepath}'
            return Unraid

    fs_types = {
        b'shfs': 'shfs',
        b'fuse.shfs': 'fuse.shfs'
    }

    try:
        with open('/proc/mounts', 'rb') as f:
            for line in f:
                parts = line.strip().split()
                if 3 > len(parts):
                   continue

                if (fs_type := parts[2].lower()) in fs_types:
                    Unraid.reason = f'Unraid detected via active storage pool mount ({fs_types[fs_type]})'
                    return Unraid
    except (FileNotFoundError, PermissionError):
        pass

__all__ = ['Unraid', 'detect_unraid']
