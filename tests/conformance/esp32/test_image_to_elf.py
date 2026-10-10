"""Source-owned image checks; no hardware, execution, or proprietary fixtures."""
import hashlib
import importlib.util
from pathlib import Path
import struct
import unittest
import subprocess
import sys
import tempfile

MODULE = Path(__file__).resolve().parents[3] / "scripts/esp32-image-to-elf.py"
spec = importlib.util.spec_from_file_location("esp32_adapter", MODULE)
adapter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(adapter)


def image(segments=((0x40080000, b"\x36\x41\x00\x1d\xf0"),), chip=0):
    header = bytearray(24)
    header[0:2] = bytes([0xE9, len(segments)])
    struct.pack_into("<I", header, 4, 0x40080000)
    struct.pack_into("<H", header, 12, chip)
    header[23] = 1
    result = bytes(header)
    checksum = 0xEF
    for address, payload in segments:
        result += struct.pack("<II", address, len(payload)) + payload
        for byte in payload:
            checksum ^= byte
    result += bytes(15 - len(result) % 16) + bytes([checksum])
    return result + hashlib.sha256(result).digest()


class Esp32AdapterTests(unittest.TestCase):
    def parse(self, value):
        return adapter.parse_image(value, hashlib.sha256(value).hexdigest())

    def test_payloads_and_original_addresses_survive_elf(self):
        original = image(((0x40080000, b"\x36\x41\x00\x1d\xf0"), (0x3F400020, b"literal\x00")))
        parsed = self.parse(original)
        elf, manifest = adapter.build_elf(original, parsed)
        self.assertEqual(struct.unpack_from("<H", elf, 18)[0], 94)
        self.assertEqual(struct.unpack_from("<I", elf, 24)[0], 0x40080000)
        for segment in manifest["segments"]:
            start, size = segment["original_file_offset"], segment["length"]
            elf_start = segment["elf_file_offset"]
            self.assertEqual(original[start:start+size], elf[elf_start:elf_start+size])
            self.assertEqual(segment["sha256"], hashlib.sha256(original[start:start+size]).hexdigest())

    def test_fail_closed(self):
        original = image()
        invalid = [original[:-1], image(chip=9), original+b"trailer",
                   image(((0x40080000, b"ab"), (0x40080001, b"cd"))),
                   image(((0x50000000, b"ab"),)), image(((0x3F400020, b"ab"),)),
                   image(((0, b"nonzero"), (0x40080000, b"code")))]
        checksum = bytearray(original); checksum[-33] ^= 1; invalid.append(checksum)
        digest = bytearray(original); digest[-1] ^= 1; invalid.append(digest)
        for value in invalid:
            with self.subTest(value=value.hex()[:50]):
                with self.assertRaises(ValueError):
                    self.parse(value)
        with self.assertRaises(ValueError):
            adapter.parse_image(original, "0"*64)

    def test_structural_records_retain_provenance_without_load_mappings(self):
        original = image(((0, bytes(24)), (0x40080000, b"code"),
                          (0x3F400000, b""), (0x3F400010, b"literal")))
        parsed = self.parse(original)
        elf, manifest = adapter.build_elf(original, parsed)
        self.assertEqual([r["kind"] for r in manifest["records"]], ["padding", "load", "empty", "load"])
        self.assertEqual([s["index"] for s in manifest["segments"]], [1, 3])
        self.assertEqual(struct.unpack_from("<H", elf, 44)[0], 2)
        for phindex, segment in enumerate(manifest["segments"]):
            self.assertEqual(struct.unpack_from("<I", elf, 52+32*phindex+8)[0], segment["virtual_address"])
            start, size = segment["original_file_offset"], segment["length"]
            self.assertEqual(elf[segment["elf_file_offset"]:segment["elf_file_offset"]+size], original[start:start+size])

    def test_cli_rejects_symlinks_and_preserves_existing_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); source = root / "input.bin"; source.write_bytes(image())
            digest = hashlib.sha256(source.read_bytes()).hexdigest()
            link = root / "link.bin"; link.symlink_to(source)
            output = root / "output"; output.mkdir(); marker = output / "keep"; marker.write_text("existing")
            for input_path in (link, source):
                result = subprocess.run([sys.executable, str(MODULE), str(input_path), str(output), "--expect-sha256", digest], capture_output=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(marker.read_text(), "existing")
            fresh = root / "fresh"
            result = subprocess.run([sys.executable, str(MODULE), str(source), str(fresh), "--expect-sha256", "0"*64], capture_output=True)
            self.assertNotEqual(result.returncode, 0); self.assertFalse(fresh.exists())

    def test_input_unchanged_and_conversion_deterministic(self):
        original = image(); before = bytes(original)
        parsed = self.parse(original)
        self.assertEqual(adapter.build_elf(original, parsed), adapter.build_elf(original, parsed))
        self.assertEqual(original, before)


if __name__ == "__main__":
    unittest.main()
