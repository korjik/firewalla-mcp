"""Bounded in-memory archive intake. Never extracts files or logs profile bytes."""
import io
import re
import stat
import zipfile
import zlib

from .vpn_import import ImportBlocked, need


def read_profile_archive(data, *, allow_macos_metadata=False):
    """Return up to three opaque profile byte strings, still requiring validation.

    Reject paths, links, duplicates, encryption, unknown members and ZIP bombs.
    Callers must treat returned bytes as secret-bearing, never log their repr.
    No profile is approved for import by this archive-level check.
    """
    need(isinstance(data, bytes) and 1 <= len(data) <= 524288, "Invalid archive size")
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            entries = archive.infolist()
            need(type(allow_macos_metadata) is bool, "Invalid metadata option")
            need(1 <= len(entries) <= (6 if allow_macos_metadata else 3), "Archive must contain one to three profiles only")
            metadata = []
            if allow_macos_metadata:
                metadata = [e for e in entries if e.filename.startswith("__MACOSX/._")]
                entries = [e for e in entries if e not in metadata]
                names = {e.filename for e in entries}
                need(1 <= len(entries) <= 3, "Archive must contain one to three profiles only")
                need(len({e.filename for e in metadata}) == len(metadata), "Duplicate archive metadata")
                for e in metadata:
                    need(e.filename == e.orig_filename and e.filename[len("__MACOSX/._"):] in names,
                         "Unmatched archive metadata")
                    need(stat.S_IFMT(e.external_attr >> 16) in (0, stat.S_IFREG) and not e.flag_bits & 1
                         and e.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)
                         and e.file_size <= 16384 and e.file_size <= max(1,e.compress_size)*100,
                         "Unsafe archive metadata")
                # AppleDouble entries are never opened or extracted.
            seen = set()
            total = 0
            for entry in entries:
                name = entry.filename
                need(entry.orig_filename == name and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,119}\.ovpn", name),
                     "Invalid archive member name")
                need(name.casefold() not in seen, "Duplicate archive member")
                seen.add(name.casefold())
                mode = entry.external_attr >> 16
                need(stat.S_IFMT(mode) in (0, stat.S_IFREG), "Unsupported archive member type")
                need(not entry.flag_bits & 1 and entry.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED),
                     "Unsupported archive encoding")
                need(1 <= entry.file_size <= 131072 and entry.file_size <= max(1, entry.compress_size) * 100,
                     "Archive member exceeds bounds")
                total += entry.file_size
            need(total <= 393216, "Archive exceeds expanded size bound")
            result = {}
            for entry in entries:
                with archive.open(entry) as stream:
                    content = stream.read(131073)
                need(len(content) == entry.file_size, "Archive member size mismatch")
                result[entry.filename] = content
            return result
    except ImportBlocked:
        raise
    except (OSError, ValueError, RuntimeError, zipfile.BadZipFile, EOFError, NotImplementedError, zlib.error):
        raise ImportBlocked("Invalid or unreadable profile archive") from None
