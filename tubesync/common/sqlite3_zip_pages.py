import contextlib
import os
import zipfile

import apsw

from common.logger import log


class ZippedLzmaPagesFile(apsw.VFSFile):
    SIZE_4K = 4096
    SIZE_64K = 65536

    # Class-level registry containing ONLY active 4K bound method sets mapped by path
    _import_listeners = {}

    def __init__(self, vfs, filename, flags):
        self.zip_path = os.path.abspath(filename.filename())
        self.zip_config = dict(
            file=self.zip_path,
            mode='r',
            compression=zipfile.ZIP_LZMA,
            compresslevel=9,
        )
        self.max_page_seen = 0
        self.dirty_page_names = set()
        self.total_dirty_entries_on_disk = 0

        self.page_size = self.SIZE_64K
        self.frozen_page_size = True
        self.import_mode = False

        # Check the SQLite connection string for our custom import flag
        import_param = filename.uri_parameter('import4k')
        if import_param and import_param.lower() in ('true', '1', 'yes'):
            self.page_size = self.SIZE_4K
            self.frozen_page_size = False
            self.import_mode = True
            self._import_listeners.setdefault(self.zip_path, set()).add(self.freeze_geometry)

        try:
            check_zf = zipfile.ZipFile(**self.zip_config)
        except FileNotFoundError:
            self._create_empty_zip_archive()
        except zipfile.BadZipFile:
            os.replace(self.zip_path, self.zip_path + '.old.tmp')
            self._create_empty_zip_archive()
        else:
            check_zf.close()

        with contextlib.suppress(FileNotFoundError):
            with zipfile.ZipFile(**self.zip_config) as zf:
                for name in zf.namelist():
                    if len(name) == 12 and all(c in '0123456789abcdef' for c in name):
                        logical_name = self.restore_logical_name(name)

                        if name.startswith('4'):
                            self.dirty_page_names.add(logical_name)
                            self.total_dirty_entries_on_disk += 1

                        self.max_page_seen = max(self.max_page_seen, int(logical_name, 16))

        log.debug(flags)
        with contextlib.suppress(apsw.CantOpenError):
            super().__init__('unix-dotfile', self.zip_path, flags)
        log.debug(flags)

    @staticmethod
    def to_clean_name(page_num: int) -> str:
        return f'{page_num:012x}'

    @staticmethod
    def to_dirty_name(logical_name: str) -> str:
        return '4' + logical_name[1:]

    @staticmethod
    def restore_logical_name(zip_entry_name: str) -> str:
        if zip_entry_name.startswith('4'):
            return '0' + zip_entry_name[1:]
        return zip_entry_name

    @staticmethod
    def _fsync_file(file: str) -> None:
        file_path = os.path.abspath(file)
        fd = os.open(file_path, os.O_RDWR)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    @staticmethod
    def _fsync_directory(directory: str) -> None:
        directory_path = os.path.abspath(directory)
        dir_fd = os.open(
            directory_path,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
        )
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)

    @staticmethod
    def _replace_durably(src: str, dst: str) -> None:
        src_path = os.path.abspath(src)
        dst_path = os.path.abspath(dst)

        src_dir_path = os.path.dirname(src_path)
        dst_dir_path = os.path.dirname(dst_path)

        # ensure the filesystem wrote the file to storage
        self._fsync_file(src_path)

        # ensure the filesystem wrote the directory to storage
        self._fsync_directory(src_dir_path)

        if src_dir_path != dst_dir_path:
            raise ValueError("Source file must be in the destination directory")

        os.replace(src_path, dst_path)

        # ensure the filesystem wrote the directory to storage
        self._fsync_directory(dst_dir_path)

    def rewrite_zip_archive(self) -> None:
        dest_file = f'{self.zip_path}.new.tmp'
        dest_config = {
            **self.zip_config,
            'file': dest_file,
            'mode': 'w',
        }
        try:
            with zipfile.ZipFile(**self.zip_config) as zf_src, \
                 zipfile.ZipFile(**dest_config) as zf_dest:

                latest_zip_infos = {info.filename: info for info in zf_src.infolist()}

                for filename, info in latest_zip_infos.items():
                    logical_name = self.restore_logical_name(filename)

                    where = None
                    if filename.startswith('4'):
                        where = logical_name
                    elif info == latest_zip_infos.get(logical_name):
                        where = info
                    if where is not None:
                        zf_dest.writestr(
                            where,
                            zf_src.read(info),
                        )

                if (bad_file := zf_dest.testzip()) is not None:
                    raise zipfile.BadZipFile(f'test failed: {bad_file}')

            self._replace_durably(dest_file, self.zip_path)

        except Exception:
            if os.path.exists(dest_file):
                os.remove(dest_file)
            raise

    def _create_empty_zip_archive(self) -> None:
        new_config = {
            **self.zip_config,
            'mode': 'x',
        }
        with contextlib.suppress(FileExistsError):
            zf_new = zipfile.ZipFile(**new_config)
            zf_new.close()

    def _close_zip_archive(self) -> None:
        if self.zip_path in self._import_listeners:
            self._import_listeners[self.zip_path].discard(self.freeze_geometry)
            if not self._import_listeners[self.zip_path]:
                del self._import_listeners[self.zip_path]

        zip_config = {
            **self.zip_config,
            'mode': 'a',
        }
        with zipfile.ZipFile(**zip_config) as zf:
            while self.dirty_page_names:
                logical_name = self.dirty_page_names.pop()
                dirty_name = self.to_dirty_name(logical_name)
                zf.writestr(logical_name, zf.read(dirty_name))
        self._fsync_file(self.zip_path)

        total_pages = 1 + self.max_page_seen
        ratio = self.total_dirty_entries_on_disk / total_pages

        if 0.05 < ratio:
            self.rewrite_zip_archive()

        # The transition only changes in close: Broadcast to elevate active 4K listeners to 64K here
        callbacks = self._import_listeners.pop(self.zip_path, set())
        for callback in callbacks:
            callback(self.SIZE_64K)

    def freeze_geometry(self, target_page_size: int):
        """Bound method callback invoked directly by the closing vacuum file handle."""
        self.max_page_seen = 0
        if not self.frozen_page_size:
            self.page_size = target_page_size
        self.frozen_page_size = True

    def xRead(self, amount: int, offset: int) -> bytes:
        page_num = offset // self.page_size
        logical_name = self.to_clean_name(page_num)
        target_name = self.to_dirty_name(logical_name) if logical_name in self.dirty_page_names else logical_name

        try:
            with zipfile.ZipFile(**self.zip_config) as zf:
                with zf.open(target_name) as pf:
                    data = pf.read()
        except (FileNotFoundError, KeyError):
            return b'\x00' * amount
        else:
            if self.frozen_page_size:
                self.max_page_seen = max(self.max_page_seen, page_num)
            return data

    def xWrite(self, data: bytes, offset: int) -> None:
        # Local page_size variable handles calculations independently for this block write
        page_size = max(self.page_size, len(data))

        if not self.frozen_page_size and page_size > self.page_size:
            # Trigger our own bound method callback passing the original self.page_size
            self.freeze_geometry(self.page_size)

        page_num = offset // page_size
        self.max_page_seen = max(self.max_page_seen, page_num)

        logical_name = self.to_clean_name(page_num)
        dirty_name = self.to_dirty_name(logical_name)

        self.dirty_page_names.add(logical_name)
        self.total_dirty_entries_on_disk += 1

        zip_config = {
            **self.zip_config,
            'mode': 'a',
        }
        with zipfile.ZipFile(**zip_config) as zf:
            zf.writestr(
                dirty_name,
                bytes(data),
                compress_type=zipfile.ZIP_STORED,
            )

    def xDeviceCharacteristics(self) -> int:
        return 0

    def xFileSize(self) -> int:
        active_size = self.SIZE_64K if self.frozen_page_size else self.SIZE_4K
        return (self.max_page_seen + 1) * active_size

    def xClose(self) -> None:
        with contextlib.ExitStack() as stack:
            stack.callback(super().xClose)
            self._close_zip_archive()


class ZippedLzmaPagesVFS(apsw.VFS):
    def __init__(self, name='zip-lzma'):
        super().__init__(name, base='unix-dotfile')
    def xOpen(self, filename, flags):
        return ZippedLzmaPagesFile(self, filename, flags)

try:
    hybrid_vfs = ZippedLzmaPagesVFS()
except apsw.VFSAlreadyExistsError:
    pass

