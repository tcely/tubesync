import contextlib
import os
import zipfile

import apsw


class ZippedLzmaPagesFile(apsw.VFSFile):
    SIZE_4K = 4096
    SIZE_64K = 65536

    # Class-level registry containing ONLY active 4K bound method sets mapped by path
    _import_listeners = {}

    def __init__(self, vfs, filename, flags):
        self.zip_path = os.path.abspath(filename.filename())
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

        with contextlib.suppress(FileNotFoundError):
            with zipfile.ZipFile(self.zip_path, 'r') as zf:
                for name in zf.namelist():
                    if len(name) == 12 and all(c in '0123456789abcdef' for c in name):
                        logical_name = self.restore_logical_name(name)

                        if name.startswith('4'):
                            self.dirty_page_names.add(logical_name)
                            self.total_dirty_entries_on_disk += 1

                        self.max_page_seen = max(self.max_page_seen, int(logical_name, 16))

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

    def freeze_geometry(self, target_page_size: int):
        """Bound method callback invoked directly by the closing vacuum file handle."""
        self.frozen_page_size = True
        self.max_page_seen = 0
        self.page_size = target_page_size

    def xRead(self, amount: int, offset: int) -> bytes:
        page_num = offset // self.page_size
        logical_name = self.to_clean_name(page_num)
        target_name = self.to_dirty_name(logical_name) if logical_name in self.dirty_page_names else logical_name

        try:
            with zipfile.ZipFile(self.zip_path, 'r') as zf:
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

        with zipfile.ZipFile(self.zip_path, 'a', compression=zipfile.ZIP_LZMA) as zf:
            zf.writestr(dirty_name, bytes(data))

    def xFileSize(self) -> int:
        active_size = self.SIZE_64K if self.frozen_page_size else self.SIZE_4K
        return (self.max_page_seen + 1) * active_size

    def _execute_single_file_compaction(self):
        final_new_zip = f'{self.zip_path}.new.tmp'
        try:
            with zipfile.ZipFile(self.zip_path, 'r') as zf_src, \
                 zipfile.ZipFile(final_new_zip, 'w', compression=zipfile.ZIP_LZMA) as zf_dest:

                latest_zip_infos = {info.filename: info for info in zf_src.infolist()}

                for filename, info in latest_zip_infos.items():
                    logical_name = self.restore_logical_name(filename)

                    if filename.startswith('4'):
                        zf_dest.writestr(logical_name, zf_src.read(filename))
                    elif info == latest_zip_infos.get(logical_name):
                        with zf_src.open(info, 'r') as src_entry:
                            zf_dest.writestr(info, src_entry.read())

            os.replace(final_new_zip, self.zip_path)

        except Exception:
            if os.path.exists(final_new_zip):
                os.remove(final_new_zip)
            raise

    def xClose(self) -> None:
        if self.zip_path in self._import_listeners:
            self._import_listeners[self.zip_path].discard(self.freeze_geometry)
            if not self._import_listeners[self.zip_path]:
                del self._import_listeners[self.zip_path]

        with zipfile.ZipFile(self.zip_path, 'a', compression=zipfile.ZIP_LZMA) as zf:
            while self.dirty_page_names:
                logical_name = self.dirty_page_names.pop()
                dirty_name = self.to_dirty_name(logical_name)
                zf.writestr(dirty_name, zf.read(logical_name))

        total_pages = self.max_page_seen + 1

        if (self.total_dirty_entries_on_disk / total_pages) > 0.05:
            self._execute_single_file_compaction()

            # The transition only changes in close: Broadcast to elevate active 4K listeners to 64K here
            callbacks = self._import_listeners.pop(self.zip_path, set())
            for callback in callbacks:
                callback(self.SIZE_64K)

class ZippedLzmaPagesVFS(apsw.VFS):
    def __init__(self, name='zip_lzma_vfs'):
        super().__init__(name, base='')
    def xOpen(self, filename, flags):
        return ZippedLzmaPagesFile(self, filename, flags)

try:
    hybrid_vfs = ZippedLzmaPagesVFS()
except apsw.VFSAlreadyExistsError:
    pass

