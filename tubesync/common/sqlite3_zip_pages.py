import contextlib
import io
import os
import tempfile
import warnings
import zipfile

import apsw


class ZippedLzmaPagesFile(apsw.VFSFile):
    SIZE_4K = 1<<12
    SIZE_64K = 1<<16

    # Class-level registry containing ONLY active 4K bound method sets mapped by path
    _import_listeners = {}

    def __init__(self, vfs, filename, flags):
        import_param = None
        if filename is None:
            self.temporary_directory = tempfile.TemporaryDirectory(
                ignore_cleanup_errors=True,
            )
            temporary_file = tempfile.NamedTemporaryFile(
                suffix='.sqlite3.db.zip',
                dir=self.temporary_directory.name,
            )
            file_name = temporary_file.name
            temporary_file.close()
        elif not isinstance(filename, str):
            file_name = filename.filename()
            import_param = filename.uri_parameter('import4k')
        else:
            file_name = filename
        self.zip_path = os.path.abspath(file_name)
        self.zip_config = dict(
            file=self.zip_path,
            mode='r',
            # compression=zipfile.ZIP_LZMA,
            compression=zipfile.ZIP_DEFLATED,
            compresslevel=9,
        )
        self.filterwarnings_config = dict(
            category=UserWarning,
            message=r"Duplicate name: '[0-9a-f]{12}'",
        )
        self.max_page_seen = 0
        self.dirty_page_names = set()
        self.total_dirty_entries_on_disk = 0
        self.page_size = self.SIZE_64K
        self.frozen_page_size = True
        self.import_mode = False
        self.main_database = True

        # Check the SQLite connection string for our custom import flag
        if import_param and import_param.lower() in ('true', '1', 'yes'):
            self.page_size = self.SIZE_4K
            self.frozen_page_size = False
            self.import_mode = True
            self._import_listeners.setdefault(self.zip_path, set()).add(self.freeze_geometry)

        print(f'in init: page_size={self.page_size}', flush=True)
        if (0 == (apsw.SQLITE_OPEN_MAIN_DB & flags[0])):
            self.main_database = False
            print(f'in init: main_db={self.main_database}', flush=True)
            return super().__init__('unix-dotfile', filename, flags)

        try:
            check_zf = zipfile.ZipFile(**self.zip_config)
        except FileNotFoundError:
            self._create_empty_zip_archive()
        except zipfile.BadZipFile:
            os.replace(self.zip_path, self.zip_path + '.old.tmp')
            self._create_empty_zip_archive()
        else:
            check_zf.close()

        with warnings.catch_warnings(), \
             contextlib.suppress(FileNotFoundError), \
             zipfile.ZipFile(**self.zip_config) as zf:

            warnings.filterwarnings('ignore', **self.filterwarnings_config)

            for name in zf.namelist():
                if 12 == len(name) and all(c in '0123456789abcdef' for c in name):
                    logical_name = self.restore_logical_name(name)

                    if name.startswith('4'):
                        self.dirty_page_names.add(logical_name)
                        self.total_dirty_entries_on_disk += 1

                    self.max_page_seen = max(self.max_page_seen, int(logical_name, 16))

        return super().__init__('unix-dotfile', self.zip_path, flags)

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

    def _replace_durably(self, src: str, dst: str) -> None:
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

    def _latest_by_filename(self) -> dict[str, zipfile.ZipInfo]:
        with zipfile.ZipFile(**self.zip_config) as zf_src:
            return {info.filename: info for info in zf_src.infolist()}

    def rewrite_zip_archive(self) -> None:
        dest_file = f'{self.zip_path}.new.tmp'
        dest_config = {
            **self.zip_config,
            'file': dest_file,
            'mode': 'w',
        }
        try:
            latest_zip_infos = self._latest_by_filename()
            with warnings.catch_warnings(), \
                 zipfile.ZipFile(**self.zip_config) as zf_src, \
                 zipfile.ZipFile(**dest_config) as zf_dest:

                warnings.filterwarnings('ignore', **self.filterwarnings_config)

                for filename, info in latest_zip_infos.items():
                    logical_name = self.restore_logical_name(filename)
                    dirty_name = self.to_dirty_name(logical_name)
                    print(f'rewrite loop: {filename=} {info=} {logical_name=} {dirty_name=}', flush=True)

                    where = None
                    if dirty_name == filename:
                        where = logical_name
                    elif dirty_name in latest_zip_infos:
                        where = None
                    elif info == latest_zip_infos.get(logical_name):
                        where = info
                    if where is not None:
                        print(f'rewrite to dst: {where=} len(data)={len(zf_src.read(info))} {info=}', flush=True)
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

        latest_zip_infos = self._latest_by_filename()
        zip_config = {
            **self.zip_config,
            'mode': 'a',
        }
        with warnings.catch_warnings(), \
             zipfile.ZipFile(**zip_config) as zf:

            warnings.filterwarnings('ignore', **self.filterwarnings_config)

            while self.dirty_page_names:
                logical_name = self.dirty_page_names.pop()
                dirty_name = self.to_dirty_name(logical_name)
                zf.writestr(
                    logical_name,
                    zf.read(latest_zip_infos[dirty_name]),
                )
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
        print(f'in xRead: {offset=} {amount=} main_db={self.main_database}', flush=True)
        if not self.main_database:
            return super().xRead(amount, offset)

        page_num = offset // self.page_size
        begin = offset % self.page_size
        logical_name = self.to_clean_name(page_num)
        target_name = self.to_dirty_name(logical_name) if logical_name in self.dirty_page_names else logical_name

        print(f'reading: {target_name=} {begin=}', flush=True)
        page = io.BytesIO()
        try:
            latest_zip_infos = self._latest_by_filename()
            with page.getbuffer() as page_buffer, \
                 zipfile.ZipFile(**self.zip_config) as zf, \
                 zf.open(latest_zip_infos[target_name]) as pf:
                pf.readinto(page_buffer)
        except (FileNotFoundError, KeyError):
            page.seek(0, io.SEEK_SET)
            page.write(b'\x00' * self.page_size)
        else:
            if self.frozen_page_size:
                self.max_page_seen = max(self.max_page_seen, page_num)
        page.seek(begin, io.SEEK_SET)
        data = bytes(page.read(amount))
        page.close()
        print(f'read: {len(data)=}', flush=True)
        return data

    def xWrite(self, data: bytes, offset: int) -> None:
        print(f'in xWrite: {offset=} len(data)={len(data)} main_db={self.main_database}', flush=True)
        if not self.main_database:
            return super().xWrite(data, offset)

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

        page = io.BytesIO(
            self.xRead(amount=page_size, offset=page_size*page_num),
        )
        page.seek(offset % page_size, io.SEEK_SET)
        page.write(data)
        page.seek(0, io.SEEK_SET)

        zip_config = {
            **self.zip_config,
            'mode': 'a',
        }
        with warnings.catch_warnings(), \
             zipfile.ZipFile(**zip_config) as zf:

            warnings.filterwarnings('ignore', **self.filterwarnings_config)

            zf.writestr(
                dirty_name,
                page.getvalue(),
                compress_type=zipfile.ZIP_STORED,
            )

    def xDeviceCharacteristics(self) -> int:
        if not self.main_database:
            return super().xDeviceCharacteristics()

        return 0

    def xFileSize(self) -> int:
        """Returns the size of the file in bytes."""
        if not self.main_database:
            return super().xFileSize()

        # file_size = os.stat(self.zip_path).st_size
        # total_pages = 1 + self.max_page_seen
        try:
            latest_zip_infos = self._latest_by_filename()
        except FileNotFoundError:
            total_pages = self.max_page_seen
        else:
            total_pages = len({
                self.restore_logical_name(name)
                for name in latest_zip_infos
                if 12 == len(name)
                and all(c in '0123456789abcdef' for c in name)
            })

        page_size = self.SIZE_64K if self.frozen_page_size else self.SIZE_4K
        total_pages_size = total_pages * page_size

        # return max(file_size, total_pages_size)
        print(f'in xFileSize: {total_pages_size=}', flush=True)
        return total_pages_size

    def xTruncate(self, newsize: int) -> None:
        if not self.main_database:
            return super().xTruncate(newsize)

        page_size = self.SIZE_64K if self.frozen_page_size else self.SIZE_4K
        self.max_page_seen = (max(0, newsize) // page_size)

    def xClose(self) -> None:
        with contextlib.ExitStack() as stack:
            stack.callback(super().xClose)
            if self.main_database:
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

