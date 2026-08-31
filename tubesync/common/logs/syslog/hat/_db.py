import contextlib
import lzma
import os
import re
import shutil
from collections.abc import Iterator
from pathlib import Path

from ....logger import log


def get_rotated_databases(db_path: str | Path) -> Iterator[tuple[int, Path]]:
    """
    Scans the directory using high-performance os.scandir to isolate valid,
    non-empty database targets, sorting them ascending so the highest index
    can be popped off before yielding the remaining elements in reverse.
    """
    resolved_db = Path(db_path).resolve(strict=True)
    pattern = re.compile(rf'^{re.escape(resolved_db.name)}\.(\d+)$')
    rotated_items: list[tuple[int, Path]] = []

    with os.scandir(resolved_db.parent) as entries:
        for entry in entries:
            accepted_file = (
                entry.is_file() and
                not entry.is_symlink() and
                0 < entry.stat().st_size and
                (match := pattern.match(entry.name)) and
                1 < (index := int(match.group(1)))
            )
            if accepted_file:
                rotated_items.append((index, Path(entry.path)))

    # Sort ascending so the absolute highest number index is at the end of the list
    rotated_items.sort(key=lambda x: x.__getitem__(0))

    # Safely remove the highest element to isolate active server activity
    if rotated_items:
        rotated_items.pop()

    return reversed(rotated_items)


def isolate_source_file(src_path: Path, stage_path: Path) -> bool:
    """
    Locks the source path to 0o444, moves it to staging, and drops a 0-byte
    placeholder. Returns True if placeholder was secured, False if hijacked.
    """
    if stage_path.exists():
        log.error(f'Staging collision: Target path already occupied, skipping: {stage_path.name}')
        return False

    try:
        src_path.chmod(0o444)
        src_path.rename(stage_path)
        src_path.touch(exist_ok=False)
    except FileExistsError:
        log.error(f'Index collision: Server hijacked {src_path.name} mid-rename. Restoring via replace.')
        with contextlib.suppress(OSError):
            stage_path.replace(src_path)
    except (FileNotFoundError, OSError):
        log.exception(f'Operational error isolating index {src_path.name}. Performing fallback check.')
        if stage_path.exists() and not src_path.exists():
            with contextlib.suppress(OSError):
                stage_path.replace(src_path)
        raise
    else:
        return True

    return False


def run_staged_compression(src_path: Path, dest_path: Path) -> None:
    """
    Executes the long-running xz (LZMA2) data compression from staging to storage,
    immediately applying strict read-only lock permissions on success.
    """
    log.info(f'Compressing {src_path.name} to xz format...')
    with open(src_path, 'rb') as f_in:
        with lzma.open(dest_path, 'wb', preset=9) as f_out:
            shutil.copyfileobj(f_in, f_out)

    dest_path.chmod(0o400)


def finalize_link_swap(src_path: Path, dest_path: Path, index: int, compressing_dir: Path) -> bool:
    """
    Verifies that the placeholder remains unhijacked and executes an atomic
    symlink replacement. Returns True if swapped, False if aborted.
    """
    src_stat = None
    try:
        src_stat = src_path.stat()
    except FileNotFoundError:
        log.error(f'Placeholder for index {index} disappeared before link swap. Aborting.')
    except OSError:
        log.exception(f'Operational failure reading state for placeholder index {index}. Aborting.')
    else:
        if 0 < src_stat.st_size:
            log.error(f'Race condition lost: Placeholder {src_path.name} modified by server. Aborting link swap.')
            src_stat = None

    if src_stat is None:
        return False

    tmp_symlink = compressing_dir / f'tmp_link.{index}'
    try:
        tmp_symlink.symlink_to(Path(dest_path.parent.name) / dest_path.name)
        tmp_symlink.replace(src_path)
        return True
    except Exception:
        if tmp_symlink.is_symlink() or tmp_symlink.exists():
            tmp_symlink.unlink(missing_ok=True)
        raise


def compress_rotated_databases(db_path: str | Path) -> None:
    """
    Main orchestrator for identifying, staging, compressing, and archiving
    historical database files in reverse order without clobbering active data.
    """
    try:
        resolved_db = Path(db_path).resolve(strict=True)
    except FileNotFoundError:
        log.exception(f'Configuration Error: Target database does not exist: {db_path}')
        raise

    compressing_dir = resolved_db.parent / '.compressing'
    compressed_dir = resolved_db.parent / '.compressed'

    compressing_dir.mkdir(parents=True, exist_ok=True)
    compressed_dir.mkdir(parents=True, exist_ok=True)

    # Directly consumes the clean, reversed iterator stream
    targets_to_compress = get_rotated_databases(resolved_db)

    for index, src_path in targets_to_compress:
        stage_path = compressing_dir / src_path.name
        dest_name = src_path.with_suffix(src_path.suffix + '.xz').name
        dest_path = compressed_dir / dest_name

        if dest_path.exists():
            log.warning(f'Archive destination already exists, skipping: {dest_name}')
            continue

        try:
            placeholder_secured = isolate_source_file(src_path, stage_path)
        except Exception:
            continue

        try:
            run_staged_compression(stage_path, dest_path)
        except Exception:
            log.exception(f'Error compressing data stream for {src_path.name}. Initiating rollback.')
            if dest_path.exists():
                dest_path.unlink()

            if placeholder_secured:
                try:
                    if src_path.exists() and not src_path.is_symlink() and 0 == src_path.stat().st_size:
                        stage_path.chmod(0o644)
                        stage_path.replace(src_path)
                except OSError:
                    pass
            continue

        if not placeholder_secured:
            stage_path.unlink()
            log.info(f'Archive locked successfully: {dest_name} saved. Active index left with server.')
            continue

        try:
            if finalize_link_swap(src_path, dest_path, index, compressing_dir):
                stage_path.unlink()
                log.info(f'Successfully compressed and swapped index: {src_path.name} -> {dest_path.name}')
        except Exception:
            log.exception(f'Failed to execute link swap for index {index}. Preserving staging file for recovery.')
