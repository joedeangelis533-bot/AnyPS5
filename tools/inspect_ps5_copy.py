import argparse
import json
import os
import re
import stat
import struct
import sys
from collections import deque
from pathlib import Path, PurePosixPath


MODULE_DIRS = ("sce_module", "sce_modules", "prx")
MODULE_SUFFIXES = (".debug_prx", ".suprx", ".sprx", ".prx")
SELF_MAGICS = (b"\x4f\x15\x3d\x1d", b"\x54\x14\xf5\xee")
MAX_TABLE_BYTES = 1024 * 1024
MAX_DEPENDENCIES = 4096
MAX_NAME_BYTES = 1024
LIMITATIONS = [
    "No files are executed, extracted, decrypted, converted, mounted or written by this tool.",
    "ELF checks cover headers, load ranges and declared dependencies, not complete relinker acceptance or decryption proof.",
    "Asset completeness, runtime-loaded modules, host runtime support and game playability require separate validation.",
    "Unrecognized bytes do not establish encryption, a PS5 origin or absence of game files.",
]


class InspectionError(Exception):
    pass


class ReadBudget:
    def __init__(self, maximum):
        self.maximum = maximum
        self.used = 0

    def read(self, stream, offset, size, file_size=None):
        if offset < 0 or size < 0 or (file_size is not None and (offset > file_size or size > file_size - offset)):
            raise InspectionError("requested data lies outside the file")
        if size > self.maximum - self.used:
            raise InspectionError("read budget exhausted; inspection is incomplete")
        stream.seek(offset)
        data = stream.read(size)
        self.used += len(data)
        if len(data) != size:
            raise InspectionError("short read; source may have changed or be unreadable")
        return data


def is_link(info):
    return stat.S_ISLNK(info.st_mode) or bool(getattr(info, "st_file_attributes", 0) & 0x400)


def open_regular(path, expected):
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    descriptor = os.open(path, flags)
    stream = os.fdopen(descriptor, "rb", buffering=0)
    actual = os.fstat(stream.fileno())
    if not stat.S_ISREG(actual.st_mode) or (actual.st_dev, actual.st_ino, actual.st_size) != (expected.st_dev, expected.st_ino, expected.st_size):
        stream.close()
        raise InspectionError("source changed before opening; skipped")
    return stream


def signature(data):
    if data.startswith(b"\x7fELF"):
        return "elf"
    if data[:4] in SELF_MAGICS:
        return "self"
    if data.startswith((b"PK\x03\x04", b"PK\x05\x06", b"7z\xbc\xaf\x27\x1c", b"Rar!\x1a\x07")):
        return "archive"
    if data.startswith(b"\x7fCNT"):
        return "pkg_container"
    if data.startswith(b"MZ"):
        return "windows_executable"
    return "unrecognized"


def image_signatures(data):
    found = []
    for offset in (512, 4096):
        if data[offset:offset + 8] == b"EFI PART":
            found.append(f"GPT signature at byte {offset}; partition table not validated")
    if data[510:512] == b"\x55\xaa":
        found.append("MBR/boot-sector signature; partition table not validated")
    for offset, marker, name in ((3, b"EXFAT   ", "exFAT"), (3, b"NTFS    ", "NTFS"),
                                  (54, b"FAT16   ", "FAT16"), (82, b"FAT32   ", "FAT32")):
        if data[offset:offset + len(marker)] == marker:
            found.append(f"{name} boot-sector marker; filesystem not validated")
    return found


def inspect_elf(stream, size, budget):
    header = struct.unpack("<16sHHIQQQIHHHHHH", budget.read(stream, 0, 64, size))
    ident, kind, machine, version, entry, phoff, _, _, ehsize, phsize, phcount, _, _, _ = header
    if ident[4:7] != b"\x02\x01\x01" or machine != 62 or version != 1:
        raise InspectionError("AnyPS5 requires little-endian ELF64 x86-64 version 1")
    if kind in (0, 1, 4) or ehsize != 64 or phsize != 56 or not phcount or phcount == 0xffff or phoff < 64:
        raise InspectionError("unsupported ELF type or invalid/extended program header table")
    table = budget.read(stream, phoff, phsize * phcount, size)
    segments = list(struct.iter_unpack("<IIQQQQQQ", table))
    loads = []
    dynamics = []
    dynlibs = []
    for segment in segments:
        tag, flags, offset, address, _, file_bytes, memory_bytes, alignment = segment
        if tag not in (0x6fffff00, 0x6fffff01) and (offset > size or file_bytes > size - offset):
            raise InspectionError("ELF segment extends beyond the file")
        if tag == 1:
            if file_bytes > memory_bytes or address + memory_bytes > (1 << 64) - 1 or flags & ~7:
                raise InspectionError("invalid ELF load segment")
            if alignment > 1 and (alignment & (alignment - 1) or offset % alignment != address % alignment):
                raise InspectionError("invalid ELF load alignment")
            loads.append(segment)
        elif tag == 2:
            dynamics.append(segment)
        elif tag == 0x61000000:
            dynlibs.append(segment)
    if not loads or not any(load[1] & 1 and load[5] for load in loads):
        raise InspectionError("ELF has no file-backed executable load segment")
    ordered = sorted((load[3], load[3] + load[6]) for load in loads if load[6])
    if any(left[1] > right[0] for left, right in zip(ordered, ordered[1:])):
        raise InspectionError("overlapping ELF load segments")
    if len(dynamics) != 1 or len(dynlibs) > 1:
        raise InspectionError("expected one dynamic segment and at most one SCE dynamic-data segment")
    dynamic = dynamics[0]
    if not dynamic[5] or dynamic[5] % 16 or dynamic[5] > MAX_TABLE_BYTES:
        raise InspectionError("invalid or over-limit dynamic table")
    tags = {}
    needed = []
    terminated = False
    for tag, value in struct.iter_unpack("<qQ", budget.read(stream, dynamic[2], dynamic[5], size)):
        if tag == 0:
            terminated = True
            break
        if tag == 1:
            if len(needed) >= MAX_DEPENDENCIES:
                raise InspectionError("dependency count exceeds inspection limit")
            needed.append(value)
        elif tag in (5, 10, 0x61000035, 0x61000037):
            if tag in tags:
                raise InspectionError("duplicate ELF string-table tag")
            tags[tag] = value
    if not terminated:
        raise InspectionError("unterminated dynamic table")
    if (5 in tags) == (0x61000035 in tags) or (10 in tags) == (0x61000037 in tags):
        raise InspectionError("missing or ambiguous dynamic string table")
    string_size = tags.get(10, tags.get(0x61000037))
    if not string_size or string_size > MAX_TABLE_BYTES:
        raise InspectionError("invalid or over-limit dynamic string table")
    if 5 in tags:
        matches = [load[2] + tags[5] - load[3] for load in loads
                   if load[3] <= tags[5] and tags[5] - load[3] <= load[5]
                   and string_size <= load[5] - (tags[5] - load[3])]
        if len(matches) != 1:
            raise InspectionError("dynamic string table is not mapped to one file-backed load segment")
        string_offset = matches[0]
    else:
        if not dynlibs or tags[0x61000035] > dynlibs[0][5] or string_size > dynlibs[0][5] - tags[0x61000035]:
            raise InspectionError("SCE string table exceeds dynamic-data segment")
        string_offset = dynlibs[0][2] + tags[0x61000035]
    strings = budget.read(stream, string_offset, string_size, size)
    if strings[0] != 0:
        raise InspectionError("dynamic string table lacks its initial NUL")
    dependencies = set()
    for offset in needed:
        end = strings.find(b"\0", offset, offset + MAX_NAME_BYTES + 1) if offset < len(strings) else -1
        if end < 0:
            raise InspectionError("dependency name exceeds string table or inspection name limit")
        name = strings[offset:end].decode("utf-8", errors="strict")
        if not name or any(character in name for character in "/\\:$\r\n"):
            raise InspectionError("invalid dependency filename")
        dependencies.add(name)
    return {"type": kind, "entry": entry, "console_markers": bool(dynlibs) or 0xfe00 <= kind <= 0xfe1f,
            "dependencies": sorted(dependencies), "validation": "headers_and_dependencies_only"}


def inspect_file(path, relative, info, budget, header_bytes=512):
    result = {"path": relative, "size": info.st_size, "kind": "unrecognized"}
    try:
        with open_regular(path, info) as stream:
            prefix = budget.read(stream, 0, min(header_bytes, info.st_size), info.st_size)
            result["kind"] = signature(prefix)
            markers = image_signatures(prefix)
            if markers:
                result["storage_markers"] = markers
            if result["kind"] == "elf":
                result["elf"] = inspect_elf(stream, info.st_size, budget)
            elif path.name.casefold() == "param.json" and path.parent.name.casefold() == "sce_sys":
                if info.st_size > MAX_TABLE_BYTES:
                    raise InspectionError("param.json exceeds 1 MiB metadata limit")
                metadata = json.loads(budget.read(stream, 0, info.st_size, info.st_size))
                if not isinstance(metadata, dict):
                    raise InspectionError("param.json must contain a JSON object")
                result["kind"] = "param_json"
                result["metadata"] = {key: metadata[key] for key in ("titleId", "contentId", "contentVersion")
                                      if key in metadata and isinstance(metadata[key], str)}
    except (OSError, ValueError, InspectionError, RecursionError) as error:
        result["error"] = str(error)
    return result


def scan_directory(root, budget, max_entries, max_depth):
    records = []
    directories = set()
    issues = []
    visited = 0
    files = 0
    pending = deque([(root, 0)])
    while pending:
        directory, depth = pending.popleft()
        try:
            if is_link(directory.lstat()):
                issues.append({"path": directory.relative_to(root).as_posix(), "reason": "link/reparse point skipped"})
                continue
            with os.scandir(directory) as entries:
                for entry in entries:
                    if visited >= max_entries:
                        issues.append({"path": ".", "reason": "entry limit reached; inspection is incomplete"})
                        return records, directories, issues, visited, files
                    visited += 1
                    path = Path(entry.path)
                    relative = path.relative_to(root).as_posix()
                    try:
                        info = path.lstat()
                        if is_link(info):
                            issues.append({"path": relative, "reason": "link/reparse point skipped"})
                        elif stat.S_ISDIR(info.st_mode):
                            directories.add(relative)
                            if depth >= max_depth:
                                issues.append({"path": relative, "reason": "depth limit reached; directory not inspected"})
                            else:
                                pending.append((path, depth + 1))
                        elif stat.S_ISREG(info.st_mode):
                            files += 1
                            record = inspect_file(path, relative, info, budget)
                            if record["kind"] != "unrecognized" or "error" in record or "storage_markers" in record or path.name.casefold() == "eboot.bin":
                                records.append(record)
                            if "read budget exhausted" in record.get("error", ""):
                                issues.append({"path": relative, "reason": record["error"]})
                                return records, directories, issues, visited, files
                        else:
                            issues.append({"path": relative, "reason": "non-regular file skipped"})
                    except OSError as error:
                        issues.append({"path": relative, "reason": str(error)})
        except OSError as error:
            issues.append({"path": directory.relative_to(root).as_posix(), "reason": str(error)})
    return sorted(records, key=lambda record: record["path"]), directories, issues, visited, files


def normalized_module(name):
    for suffix in MODULE_SUFFIXES:
        if name.endswith(suffix):
            return name[:-len(suffix)] + ".prx"
    return name


def assess(records, directories, complete, folder):
    module_index = {}
    directory_index = {}
    for record in records:
        path = PurePosixPath(record["path"])
        directory_index.setdefault(str(path.parent), []).append(record)
        module_index.setdefault((str(path.parent), normalized_module(path.name)), []).append(record)
    candidates = [record for record in records if PurePosixPath(record["path"]).name.casefold() == "eboot.bin"]
    if not candidates:
        candidates = [record for record in records if "elf" in record and record["elf"]["type"] != 0xfe18
                      and not any(PurePosixPath(record["path"]).name.endswith(suffix) for suffix in MODULE_SUFFIXES)]
    assessments = []
    for candidate in candidates:
        parent = PurePosixPath(candidate["path"]).parent
        module_dirs = [str(parent / name) for name in MODULE_DIRS if str(parent / name) in directories]
        blockers = []
        if "elf" not in candidate:
            blockers.append("A validated plain ELF executable was not observed at this path.")
            if candidate["kind"] == "self":
                blockers.append("SELF decryption status is unknown; a decrypted SELF still needs unwrapping before relinking.")
        if not folder:
            blockers.append("A single file does not establish the surrounding module layout or game assets; inspect its containing game folder.")
        elif not module_dirs:
            blockers.append("No standard module directory was observed beside this executable; supply the bundled modules or an explicit relinker --module-dir after verifying the layout.")
        if str(parent / "sce_module") in module_dirs and str(parent / "sce_modules") in module_dirs:
            blockers.append("Both sce_module and sce_modules exist; the relinker rejects this ambiguous layout.")
        dependencies = []
        inputs = [candidate] + [record for directory in module_dirs for record in directory_index.get(directory, [])]
        for source in inputs:
            for name in source.get("elf", {}).get("dependencies", []):
                matches = [record for directory in module_dirs for record in module_index.get((directory, normalized_module(name)), [])]
                dependencies.append({"requested_by": source["path"], "name": name,
                                     "observed_files": [record["path"] for record in matches],
                                     "status": "observed_elf_candidate" if len(matches) == 1 and "elf" in matches[0]
                                     else "observed_but_needs_validation" if matches else "not_observed_in_standard_module_dirs",
                                     "next_step": "Check imports against the AnyPS5 host runtime and bundled module exports with tools/import_audit.py; an unobserved dependency is not proof of a missing game file."})
        unresolved = any(item["status"] != "observed_elf_candidate" for item in dependencies)
        assessments.append({"executable": candidate["path"], "module_directories": module_dirs,
                            "status": "blocked" if blockers else "candidate_needs_validation",
                            "observed_blockers": blockers, "dependencies": dependencies,
                            "unknown": ["Decryption authenticity and full ELF acceptance", "Game asset completeness and version consistency",
                                        "AnyPS5 import/runtime support and actual boot/playability"]
                            + (["Dependency resolution is incomplete"] if unresolved or not complete else [])})
    return assessments


def inspect_source(source, max_entries=10000, max_depth=16, max_read_bytes=64 * 1024 * 1024, device=False):
    budget = ReadBudget(max_read_bytes)
    report = {"format": 1, "source": str(source), "mode": "device_header" if device else "filesystem",
              "read_only": True, "files": [], "issues": [], "limitations": LIMITATIONS.copy()}
    path = Path(source)
    if device:
        if os.name == "nt":
            if not re.fullmatch(r"\\\\\.\\PhysicalDrive[0-9]+", str(source), re.IGNORECASE):
                raise InspectionError("--device requires an explicit Windows \\\\.\\PhysicalDriveN path")
        elif not stat.S_ISBLK(path.lstat().st_mode):
            raise InspectionError("--device requires a block device; use a positional path for an image file")
        with open(source, "rb", buffering=0) as stream:
            data = stream.read(min(8192, max_read_bytes))
        budget.used = len(data)
        report["storage_markers"] = image_signatures(data)
        report["header_kind"] = signature(data)
        report["inspection_complete"] = False
        report["next_steps"] = ["Only device header bytes were inspected. Filesystem traversal and decryption status are unknown; provide a readable game folder or research the identified storage format."]
    else:
        if str(source).startswith(("\\\\.\\", "\\\\?\\")):
            raise InspectionError("device namespace paths require --device; only PhysicalDriveN is supported")
        info = path.lstat()
        if is_link(info):
            raise InspectionError("source is a symlink/reparse point; specify its intended target explicitly")
        folder = stat.S_ISDIR(info.st_mode)
        if folder:
            records, directories, issues, entries, files = scan_directory(path, budget, max_entries, max_depth)
        elif stat.S_ISREG(info.st_mode):
            records = [inspect_file(path, path.name, info, budget, 8192)]
            directories, issues, entries, files = set(), [], 1, 1
        else:
            raise InspectionError("source must be a regular file or directory; explicit block-device access uses --device")
        report.update(files=records, issues=issues, entries_visited=entries, regular_files_seen=files,
                      inspection_complete=not issues and not any("error" in record for record in records)
                      and (folder or any("elf" in record for record in records)))
        report["assessments"] = assess(records, directories, report["inspection_complete"], folder)
        report["next_steps"] = []
        if not report["assessments"]:
            report["next_steps"].append("No executable candidate was observed in inspected files. This does not establish that a backup/image lacks game data. A readable game executable and its surrounding files are needed for further assessment.")
        if not folder:
            report["limitations"].append("Image/archive/container files are identified by header only; their filesystems and enclosed files are not traversed.")
    report["bytes_read"] = budget.used
    report["status"] = "incomplete" if not report["inspection_complete"] else "blocked" if not report.get("assessments") or any(item["status"] == "blocked" for item in report["assessments"]) else "candidate_needs_validation"
    return report


def render_text(report):
    lines = [f"Source: {report['source']}", f"Result: {report['status']}",
             f"Read {report['bytes_read']} bytes; no writes performed by the inspector."]
    for marker in report.get("storage_markers", []):
        lines.append(f"Storage: {marker}")
    for record in report["files"]:
        lines.append(f"File: {record['path']} ({record['kind']}, {record['size']} bytes)")
        if "metadata" in record:
            lines.append("  Metadata (unverified): " + json.dumps(record["metadata"], ensure_ascii=True))
        if "error" in record:
            lines.append("  Error: " + record["error"])
        for marker in record.get("storage_markers", []):
            lines.append("  Storage: " + marker)
    for item in report.get("assessments", []):
        lines.append(f"Executable: {item['executable']} ({item['status']})")
        lines.extend("  Blocker: " + value for value in item["observed_blockers"])
        for dependency in item["dependencies"]:
            lines.append(f"  Dependency: {dependency['requested_by']} requests {dependency['name']} = {dependency['status']}")
            lines.extend("    Observed: " + value for value in dependency["observed_files"])
            lines.append("    Next: " + dependency["next_step"])
        lines.extend("  Unknown: " + value for value in item["unknown"])
    lines.extend(f"Skipped/incomplete: {item['path']}: {item['reason']}" for item in report["issues"])
    lines.extend("Next: " + value for value in report["next_steps"])
    lines.extend("Limit: " + value for value in report["limitations"])
    return "\n".join(re.sub(r"[\x00-\x1f\x7f-\x9f]", lambda match: f"\\u{ord(match[0]):04x}", line) for line in lines)


def positive(value):
    number = int(value)
    if number <= 0:
        raise argparse.ArgumentTypeError("must be positive")
    return number


def main(argv=None):
    parser = argparse.ArgumentParser(description="Inspect PS5 copy inputs without executing or modifying source files. Reports candidates, blockers and unknowns; never certifies playability.")
    parser.add_argument("source", nargs="?", help="readable folder or regular file/image")
    parser.add_argument("--device", help="explicit block device; Windows example: \\\\.\\PhysicalDrive2 (header only)")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument("--max-entries", type=positive, default=10000)
    parser.add_argument("--max-depth", type=positive, default=16)
    parser.add_argument("--max-read-mib", type=positive, default=64)
    args = parser.parse_args(argv)
    if bool(args.source) == bool(args.device):
        parser.error("specify exactly one source or --device")
    try:
        report = inspect_source(args.source or args.device, args.max_entries, args.max_depth,
                                args.max_read_mib * 1024 * 1024, bool(args.device))
    except (OSError, InspectionError) as error:
        report = {"format": 1, "status": "error", "error": str(error), "read_only": True}
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
    print(json.dumps(report, indent=2, ensure_ascii=True) if args.format == "json" else
          "Error: " + report["error"] if report["status"] == "error" else render_text(report))
    return 2 if report["status"] in ("error", "incomplete") else 1 if report["status"] == "blocked" else 0


if __name__ == "__main__":
    sys.exit(main())
