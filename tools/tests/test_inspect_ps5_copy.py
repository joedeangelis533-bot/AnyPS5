import contextlib
import hashlib
import io
import json
import os
import stat
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import inspect_ps5_copy as inspector


def elf(needed=(), sce=True, kind=0xfe10):
    strings = bytearray(b"\0")
    offsets = []
    for name in needed:
        offsets.append(len(strings))
        strings.extend(name.encode() + b"\0")
    tags = [(1, offset) for offset in offsets]
    tags += [(0x61000035 if sce else 5, 0 if sce else 0x800),
             (0x61000037 if sce else 10, len(strings)), (0, 0)]
    data = bytearray(0x1000)
    ident = b"\x7fELF\x02\x01\x01\x09" + b"\0" * 8
    struct.pack_into("<16sHHIQQQIHHHHHH", data, 0, ident, kind, 62, 1, 0x300, 64, 0, 0, 64, 56, 3, 64, 0, 0)
    struct.pack_into("<IIQQQQQQ", data, 64, 1, 5, 0, 0, 0, len(data), len(data), 0x1000)
    struct.pack_into("<IIQQQQQQ", data, 120, 2, 4, 0x400, 0x400, 0x400, len(tags) * 16, len(tags) * 16, 8)
    struct.pack_into("<IIQQQQQQ", data, 176, 0x61000000 if sce else 0, 4, 0x800, 0x800, 0x800, len(strings), len(strings), 1)
    for index, tag in enumerate(tags):
        struct.pack_into("<qQ", data, 0x400 + index * 16, *tag)
    data[0x800:0x800 + len(strings)] = strings
    return data


class InspectorTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def write(self, name, data):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def run_cli(self, *arguments):
        result = subprocess.run([sys.executable, "-B", str(Path(inspector.__file__)), *map(str, arguments)],
                                capture_output=True, text=True, encoding="utf-8", timeout=10)
        return result

    def test_empty_folder_reports_no_observed_executable(self):
        report = inspector.inspect_source(self.root)
        self.assertEqual(report["status"], "blocked")
        self.assertTrue(report["inspection_complete"])
        self.assertIn("does not establish", report["next_steps"][0])

    def test_opaque_backup_does_not_claim_missing_or_encrypted_files(self):
        self.write("PS5/EXPORT/BACKUP/archive.dat", bytes(range(256)) * 8)
        report = inspector.inspect_source(self.root)
        self.assertFalse(report["assessments"])
        self.assertIn("does not establish", report["next_steps"][0])
        self.assertNotIn("encrypted", json.dumps(report))

    def test_main_elf_with_modules_remains_unverified(self):
        self.write("Game/eboot.bin", elf(["engine.prx"]))
        self.write("Game/sce_module/engine.prx", elf(kind=0xfe18))
        self.write("Game/data/level.dat", b"assets")
        report = inspector.inspect_source(self.root)
        self.assertEqual(report["status"], "candidate_needs_validation")
        assessment = report["assessments"][0]
        self.assertEqual(assessment["dependencies"][0]["status"], "observed_elf_candidate")
        self.assertIn("Game asset completeness and version consistency", assessment["unknown"])
        self.assertNotIn("ready", json.dumps(report))

    def test_missing_dependency_may_be_host_system_library(self):
        self.write("eboot.bin", elf(["libkernel.prx"]))
        (self.root / "sce_module").mkdir()
        report = inspector.inspect_source(self.root)
        dependency = report["assessments"][0]["dependencies"][0]
        self.assertEqual(dependency["status"], "not_observed_in_standard_module_dirs")
        self.assertIn("not proof of a missing game file", dependency["next_step"])

    def test_module_dependencies_are_also_inspected(self):
        self.write("eboot.bin", elf(["engine.prx"]))
        self.write("prx/engine.prx", elf(["codec.prx"], kind=0xfe18))
        dependencies = inspector.inspect_source(self.root)["assessments"][0]["dependencies"]
        self.assertEqual(len(dependencies), 2)
        self.assertEqual(dependencies[1]["requested_by"], "prx/engine.prx")
        self.assertEqual(dependencies[1]["name"], "codec.prx")
        self.assertEqual(dependencies[1]["status"], "not_observed_in_standard_module_dirs")

    def test_dependency_matching_does_not_cross_games_or_recurse(self):
        self.write("A/eboot.bin", elf(["engine.prx"]))
        self.write("A/sce_module/nested/engine.prx", elf(kind=0xfe18))
        self.write("B/sce_module/engine.prx", elf(kind=0xfe18))
        report = inspector.inspect_source(self.root)
        self.assertEqual(report["assessments"][0]["dependencies"][0]["observed_files"], [])

    def test_suffix_alias_and_ambiguous_alias_are_reported(self):
        self.write("eboot.bin", elf(["engine.prx"]))
        self.write("sce_module/engine.sprx", elf(kind=0xfe18))
        dependency = inspector.inspect_source(self.root)["assessments"][0]["dependencies"][0]
        self.assertEqual(dependency["status"], "observed_elf_candidate")
        self.write("sce_module/engine.prx", elf(kind=0xfe18))
        dependency = inspector.inspect_source(self.root)["assessments"][0]["dependencies"][0]
        self.assertEqual(dependency["status"], "observed_but_needs_validation")

    def test_self_executable_requires_plain_elf_without_assuming_encryption(self):
        self.write("eboot.bin", inspector.SELF_MAGICS[0] + b"\0" * 2048)
        report = inspector.inspect_source(self.root)
        self.assertEqual(report["status"], "blocked")
        self.assertEqual(report["files"][0]["kind"], "self")
        self.assertIn("decryption status is unknown", report["assessments"][0]["observed_blockers"][1])

    def test_self_module_is_not_accepted_as_a_plain_elf(self):
        self.write("eboot.bin", elf(["engine.prx"]))
        self.write("prx/engine.prx", inspector.SELF_MAGICS[1])
        dependency = inspector.inspect_source(self.root)["assessments"][0]["dependencies"][0]
        self.assertEqual(dependency["status"], "observed_but_needs_validation")

    def test_missing_module_layout_and_conflicting_layout(self):
        self.write("eboot.bin", elf())
        report = inspector.inspect_source(self.root)
        self.assertEqual(report["status"], "blocked")
        self.assertIn("--module-dir", report["assessments"][0]["observed_blockers"][0])
        (self.root / "sce_module").mkdir()
        (self.root / "sce_modules").mkdir()
        report = inspector.inspect_source(self.root)
        self.assertIn("ambiguous", report["assessments"][0]["observed_blockers"][0])

    def test_single_executable_does_not_assume_assets_or_module_layout(self):
        path = self.write("eboot.bin", elf())
        report = inspector.inspect_source(path)
        self.assertEqual(report["status"], "blocked")
        self.assertIn("containing game folder", report["assessments"][0]["observed_blockers"][0])

    def test_metadata_does_not_establish_game_readiness(self):
        self.write("sce_sys/param.json", json.dumps({"titleId": "TEST00001", "contentVersion": "01.000.000", "secret": "not included"}).encode())
        report = inspector.inspect_source(self.root)
        self.assertEqual(report["status"], "blocked")
        self.assertEqual(report["files"][0]["metadata"]["titleId"], "TEST00001")
        self.assertNotIn("not included", json.dumps(report))

    def test_malformed_and_oversize_metadata(self):
        for data in (b"{broken", b"[]", b"\xff", b"x" * (1024 * 1024 + 1)):
            with self.subTest(size=len(data)):
                self.write("sce_sys/param.json", data)
                report = inspector.inspect_source(self.root)
                self.assertEqual(report["status"], "incomplete")
                self.assertIn("error", report["files"][0])

    def test_deeply_nested_metadata_is_reported(self):
        self.write("sce_sys/param.json", b"[" * 2000 + b"]" * 2000)
        self.assertEqual(inspector.inspect_source(self.root)["status"], "incomplete")

    def test_standard_elf_virtual_address_string_table(self):
        self.write("eboot.bin", elf(["host.so"], sce=False, kind=3))
        (self.root / "prx").mkdir()
        record = inspector.inspect_source(self.root)["files"][0]
        self.assertEqual(record["elf"]["dependencies"], ["host.so"])
        self.assertFalse(record["elf"]["console_markers"])

    def test_truncated_and_wrong_architecture_elfs(self):
        bad_machine = elf()
        struct.pack_into("<H", bad_machine, 18, 183)
        big_endian = elf()
        big_endian[5] = 2
        for data in (b"\x7fELF", elf()[:100], bad_machine, big_endian):
            with self.subTest(size=len(data)):
                self.write("eboot.bin", data)
                report = inspector.inspect_source(self.root)
                self.assertEqual(report["status"], "incomplete")
                self.assertNotIn("elf", report["files"][0])

    def test_hostile_offsets_alignments_and_table_sizes(self):
        for offset, layout, value in ((32, "Q", 2**64 - 1), (96, "Q", 2**64 - 1),
                                      (112, "Q", 3), (104, "Q", 1), (152, "Q", 2**63),
                                      (56, "H", 0xffff)):
            with self.subTest(offset=offset):
                data = elf(["engine.prx"])
                struct.pack_into("<" + layout, data, offset, value)
                self.write("eboot.bin", data)
                report = inspector.inspect_source(self.root)
                self.assertEqual(report["status"], "incomplete")
                self.assertLess(report["bytes_read"], 16384)

    def test_unterminated_dynamic_and_bad_dependency_name(self):
        bad_dynamic = elf()
        struct.pack_into("<qQ", bad_dynamic, 0x420, 4, 0)
        for data in (bad_dynamic, elf(["../escape.prx"]), elf(["bad\nname.prx"])):
            with self.subTest(data=data[0x400:0x410]):
                self.write("eboot.bin", data)
                self.assertEqual(inspector.inspect_source(self.root)["status"], "incomplete")

    def test_bad_string_offset_and_ambiguous_tags(self):
        bad_offset = elf(["engine.prx"])
        struct.pack_into("<Q", bad_offset, 0x408, 2**64 - 1)
        bad_table = elf(["engine.prx"])
        struct.pack_into("<Q", bad_table, 0x418, 2**64 - 1)
        duplicate = elf(["engine.prx"])
        struct.pack_into("<qQ", duplicate, 0x400, 0x61000035, 0)
        for data in (bad_offset, bad_table, duplicate):
            self.write("eboot.bin", data)
            self.assertEqual(inspector.inspect_source(self.root)["status"], "incomplete")

    def test_over_limit_dependency_names_and_counts_are_incomplete(self):
        self.write("eboot.bin", elf(["x" * (inspector.MAX_NAME_BYTES + 1)]))
        self.assertEqual(inspector.inspect_source(self.root)["status"], "incomplete")
        data = elf(["one.prx", "two.prx"])
        self.write("eboot.bin", data)
        with mock.patch.object(inspector, "MAX_DEPENDENCIES", 1):
            report = inspector.inspect_source(self.root)
        self.assertIn("dependency count", report["files"][0]["error"])

    def test_file_and_depth_limits_make_absence_inconclusive(self):
        self.write("deep/inside/eboot.bin", elf())
        self.write("a.dat", b"a")
        report = inspector.inspect_source(self.root, max_entries=1)
        self.assertEqual(report["status"], "incomplete")
        report = inspector.inspect_source(self.root, max_depth=1)
        self.assertEqual(report["status"], "incomplete")
        self.assertFalse(report["assessments"])

    def test_read_budget_limits_total_reads(self):
        self.write("eboot.bin", elf())
        report = inspector.inspect_source(self.root, max_read_bytes=520)
        self.assertEqual(report["status"], "incomplete")
        self.assertLessEqual(report["bytes_read"], 520)

    def test_large_image_reads_only_header(self):
        path = self.root / "disk.img"
        with path.open("wb") as stream:
            stream.write(b"opaque")
            stream.truncate(16 * 1024 * 1024)
        report = inspector.inspect_source(path)
        self.assertEqual(report["bytes_read"], 8192)
        self.assertEqual(report["status"], "incomplete")
        self.assertIn("header only", report["limitations"][-1])

    def test_image_markers_are_not_claimed_as_validated_filesystems(self):
        data = bytearray(8192)
        data[510:512] = b"\x55\xaa"
        data[512:520] = b"EFI PART"
        data[4096:4104] = b"EFI PART"
        path = self.write("disk.img", data)
        report = inspector.inspect_source(path)
        self.assertEqual(len(report["files"][0]["storage_markers"]), 3)
        self.assertTrue(all("not validated" in value for value in report["files"][0]["storage_markers"]))
        self.assertFalse(report["assessments"])

    def test_archive_and_windows_binary_are_identified_without_execution(self):
        self.write("game.zip", b"PK\x03\x04payload")
        self.write("Setup.exe", b"MZpayload")
        report = inspector.inspect_source(self.root)
        self.assertEqual({item["kind"] for item in report["files"]}, {"archive", "windows_executable"})
        self.assertFalse(report["assessments"])

    def test_all_input_opens_are_read_only_and_source_is_unchanged(self):
        self.write("eboot.bin", elf(["engine.prx"]))
        self.write("prx/engine.prx", elf(kind=0xfe18))
        self.write("sce_sys/param.json", b'{"titleId":"TEST00001"}')
        self.write("assets/data.dat", b"assets")
        def snapshot():
            return {str(path.relative_to(self.root)): (hashlib.sha256(path.read_bytes()).hexdigest(), path.stat().st_mtime_ns)
                    for path in self.root.rglob("*") if path.is_file()}
        before = snapshot()
        original_open = os.open
        def checked_open(path, flags, *args, **kwargs):
            self.assertEqual(flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND), 0)
            return original_open(path, flags, *args, **kwargs)
        with mock.patch.object(inspector.os, "open", side_effect=checked_open), mock.patch("builtins.open", side_effect=AssertionError("unexpected file open")):
            report = inspector.inspect_source(self.root)
        self.assertTrue(report["read_only"])
        self.assertEqual(report["status"], "candidate_needs_validation")
        self.assertEqual(before, snapshot())

    def test_links_are_skipped_without_reading_targets(self):
        outside = self.write("outside/eboot.bin", elf())
        scan = self.root / "scan"
        scan.mkdir()
        try:
            (scan / "linked.bin").symlink_to(outside)
            (scan / "linked_dir").symlink_to(outside.parent, target_is_directory=True)
        except OSError as error:
            self.skipTest(f"symlink creation unavailable: {error}")
        report = inspector.inspect_source(scan)
        self.assertEqual(report["bytes_read"], 0)
        self.assertEqual(report["status"], "incomplete")
        self.assertEqual(len(report["issues"]), 2)
        with self.assertRaises(inspector.InspectionError):
            inspector.inspect_source(scan / "linked.bin")

    def test_reparse_point_detection(self):
        info = mock.Mock(st_mode=stat.S_IFDIR, st_file_attributes=0x400)
        self.assertTrue(inspector.is_link(info))

    def test_source_replaced_before_open_is_rejected(self):
        path = self.write("eboot.bin", elf())
        info = path.stat()
        path.write_bytes(b"changed")
        with self.assertRaisesRegex(inspector.InspectionError, "source changed"):
            inspector.open_regular(path, info)

    def test_permission_failure_remains_incomplete(self):
        self.write("eboot.bin", elf())
        with mock.patch.object(inspector, "open_regular", side_effect=PermissionError("denied")):
            report = inspector.inspect_source(self.root)
        self.assertEqual(report["status"], "incomplete")
        self.assertIn("denied", report["files"][0]["error"])

    @unittest.skipUnless(os.name == "nt", "Windows device path validation")
    def test_explicit_physical_device_is_read_only_and_header_only(self):
        device = r"\\.\PhysicalDrive42"
        with mock.patch("builtins.open", return_value=io.BytesIO(b"\0" * 8192)) as opened:
            report = inspector.inspect_source(device, device=True)
        opened.assert_called_once_with(device, "rb", buffering=0)
        self.assertEqual(report["bytes_read"], 8192)
        self.assertEqual(report["status"], "incomplete")
        self.assertEqual(report["mode"], "device_header")
        for path in (r"\\.\C:", r"\\.\PhysicalDrive0\file", "C:\\folder", r"\\.\GLOBALROOT\Device\Harddisk0"):
            with self.subTest(path=path), self.assertRaises(inspector.InspectionError):
                inspector.inspect_source(path, device=True)

    def test_device_namespace_is_not_accepted_as_regular_source(self):
        for path in (r"\\.\PhysicalDrive0", r"\\?\GLOBALROOT\Device\Harddisk0"):
            with self.assertRaises(inspector.InspectionError):
                inspector.inspect_source(path)

    def test_terminal_control_characters_are_escaped(self):
        report = inspector.inspect_source(self.root)
        report["source"] = "name\x1b[31m\nmisleading"
        rendered = inspector.render_text(report)
        self.assertNotIn("\x1b", rendered)
        self.assertIn(r"\u001b", rendered)
        self.assertIn(r"\u000a", rendered)

    def test_cli_json_exit_codes_and_errors(self):
        result = self.run_cli(self.root, "--format", "json")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(json.loads(result.stdout)["status"], "blocked")
        self.write("eboot.bin", elf())
        (self.root / "prx").mkdir()
        result = self.run_cli(self.root, "--format", "json")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["status"], "candidate_needs_validation")
        result = self.run_cli(self.root / "missing", "--format", "json")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(json.loads(result.stdout)["status"], "error")

    def test_cli_rejects_conflicting_sources_and_invalid_limits(self):
        for arguments in ((), (self.root, "--device", "invalid"), (self.root, "--max-entries", "0"),
                          (self.root, "--max-depth", "-1"), (self.root, "--max-read-mib", "bad")):
            with self.subTest(arguments=arguments):
                self.assertEqual(self.run_cli(*arguments).returncode, 2)


if __name__ == "__main__":
    unittest.main()
