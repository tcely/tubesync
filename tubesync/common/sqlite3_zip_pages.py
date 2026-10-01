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

    def __init__(self, vfs, filename, flags):
        self.main_database = False
        if (0 == (apsw.SQLITE_OPEN_MAIN_DB & flags[0])):
            return super().__init__('unix-dotfile', filename, flags)

        self.dirty_page_names = set()
        self.filterwarnings_config = dict(
            category=UserWarning,
            message=r"Duplicate name: '[0-9a-f]{12}'",
        )
        self.main_database = True
        self.max_file_seen = 0
        self.split_size = self.SIZE_64K
        self.total_dirty_entries_on_disk = 0

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

        dir_path = os.path.dirname(self.zip_path)
        try:
            check_zf = zipfile.ZipFile(**self.zip_config)
        except FileNotFoundError:
            self._create_empty_zip_archive()
            self._fsync_directory(dir_path)
        except zipfile.BadZipFile:
            os.replace(self.zip_path, self.zip_path + '.old.tmp')
            self._fsync_directory(dir_path)
            self._create_empty_zip_archive()
            self._fsync_directory(dir_path)
        else:
            check_zf.close()

        with warnings.catch_warnings(), \
             contextlib.suppress(FileNotFoundError), \
             zipfile.ZipFile(**self.zip_config) as zf:

            warnings.filterwarnings('ignore', **self.filterwarnings_config)

            for name in zf.namelist():
                if 12 == len(name) and all(c in '0123456789abcdef' for c in name):
                    logical_name = self.restore_logical_name(name)

                    if name != logical_name:
                        self.dirty_page_names.add(logical_name)
                        self.total_dirty_entries_on_disk += 1

                    self.max_file_seen = max(self.max_file_seen, int(logical_name, 16))

        return super().__init__('unix-dotfile', self.zip_path, flags)

    @staticmethod
    def to_clean_name(file_num: int) -> str:
        return f'{file_num:012x}'

    @staticmethod
    def to_dirty_name(logical_name: str) -> str:
        return '4' + logical_name[1:]

    @staticmethod
    def restore_logical_name(dirty_name: str) -> str:
        if dirty_name.startswith('4'):
            return '0' + dirty_name[1:]
        return dirty_name

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

                    where = None
                    if dirty_name == filename:
                        where = logical_name
                    elif dirty_name in latest_zip_infos:
                        where = None
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
        self._fsync_file(self.zip_path)

    def _close_zip_archive(self) -> None:
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

        ratio = self.total_dirty_entries_on_disk / max(1, self.max_file_seen)
        if 0.05 < ratio:
            self.rewrite_zip_archive()

    def xRead(self, amount: int, offset: int) -> bytes:
        if not self.main_database:
            return super().xRead(amount, offset)

        file_num = offset // self.split_size
        begin = offset % self.split_size
        logical_name = self.to_clean_name(file_num)
        dirty_name = self.to_dirty_name(logical_name)
        target_name = dirty_name if logical_name in self.dirty_page_names else logical_name

        file_data = io.BytesIO()
        try:
            file_data.seek(0, io.SEEK_SET)
            latest_zip_infos = self._latest_by_filename()
            with zipfile.ZipFile(**self.zip_config) as zf, \
                 zf.open(latest_zip_infos[target_name]) as pf:
                file_data.write(pf.read())
        except (FileNotFoundError, KeyError) as e:
            file_data.seek(0, io.SEEK_SET)
            file_data.write(b'\x00' * self.split_size)
        else:
            self.max_file_seen = max(self.max_file_seen, file_num)
        file_data.seek(begin, io.SEEK_SET)
        data = bytes(file_data.read(amount))
        file_data.close()
        return data

    def xWrite(self, data: bytes, offset: int) -> None:
        if not self.main_database:
            return super().xWrite(data, offset)

        file_num = offset // self.split_size
        begin = offset % self.split_size
        logical_name = self.to_clean_name(file_num)
        dirty_name = self.to_dirty_name(logical_name)
        self.max_file_seen = max(self.max_file_seen, file_num)
        self.total_dirty_entries_on_disk += 1

        file_data = io.BytesIO(
            self.xRead(amount=self.split_size, offset=file_num*self.split_size),
        )
        file_data.seek(begin, io.SEEK_SET)
        file_data.write(data)
        file_data.seek(0, io.SEEK_SET)
        file_data_bytes = file_data.getvalue()[:offset+len(data)]
        file_data.close()

        zip_config = {
            **self.zip_config,
            'mode': 'a',
        }
        with warnings.catch_warnings(), \
             zipfile.ZipFile(**zip_config) as zf:

            warnings.filterwarnings('ignore', **self.filterwarnings_config)

            zf.writestr(
                dirty_name,
                file_data_bytes,
                compress_type=zipfile.ZIP_STORED,
            )
        self._fsync_file(self.zip_path)

        self.dirty_page_names.add(logical_name)

    def xDeviceCharacteristics(self) -> int:
        if not self.main_database:
            return super().xDeviceCharacteristics()

        return 0

    def xFileSize(self) -> int:
        """Returns the size of the file in bytes."""
        if not self.main_database:
            return super().xFileSize()

        total_files_size = None
        try:
            latest_zip_infos = self._latest_by_filename()
        except FileNotFoundError:
            total_files = self.max_file_seen
        else:
            all_files = {
                self.restore_logical_name(name)
                for name in latest_zip_infos
                if 12 == len(name)
                and all(c in '0123456789abcdef' for c in name)
            }
            total_files = len(all_files)

            sizes = {n: latest_zip_infos[n].file_size for n in all_files if n in latest_zip_infos}
            total_files_size = sum(sizes.values()) or None

        if total_files_size is None:
            total_files_size = total_files * self.split_size

        return total_files_size

    def xTruncate(self, newsize: int) -> None:
        if not self.main_database:
            return super().xTruncate(newsize)

        self.max_file_seen = (max(0, newsize) // self.split_size)

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

