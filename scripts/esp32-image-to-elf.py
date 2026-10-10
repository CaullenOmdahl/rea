#!/usr/bin/env python3
"""Create an offline ESP32 ELF view and original-byte map. Never execute firmware.

Only chip-ID-0 application images with known segment memory regions are admitted.
The ELF is a derived view, never original source or exact-byte matching authority.
Format: esptool ESP32FirmwareImage; map: esptool.targets.esp32.ESP32ROM.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct

MAX_IMAGE_BYTES = 16 * 1024 * 1024
# ESP32 address spaces only. Permissions express memory capabilities, not proven code.
REGIONS = (
    (0x3F400000, 0x3F800000, "drom", 4),
    (0x3FF80000, 0x3FF82000, "rtc-dram", 6),
    (0x3FFAE000, 0x40000000, "dram", 6),
    (0x40080000, 0x400A0000, "iram", 5),
    (0x400A0000, 0x400BFFFC, "diram-iram", 5),
    (0x400C0000, 0x400C2000, "rtc-iram", 5),
    (0x400D0000, 0x40400000, "irom", 5),
)


def parse_image(data, expected_sha256):
    if not re.fullmatch(r"[0-9a-f]{64}", expected_sha256):
        raise ValueError("Expected SHA256 must be 64 lowercase hexadecimal digits")
    actual = hashlib.sha256(data).hexdigest()
    if actual != expected_sha256:
        raise ValueError("Original image SHA256 does not match the supplied identity")
    if not 24 <= len(data) <= MAX_IMAGE_BYTES or data[0] != 0xE9:
        raise ValueError("Expected a bounded ESP application image with a 24-byte header")
    if struct.unpack_from("<H", data, 12)[0] != 0:
        raise ValueError("Only ESP32 chip ID 0 is supported; ESP32-S3 needs a separate profile")
    if not 1 <= data[1] <= 16 or data[23] not in (0, 1):
        raise ValueError("Unsupported segment count or appended-hash declaration")
    entry = struct.unpack_from("<I", data, 4)[0]
    segments, records, offset, checksum = [], [], 24, 0xEF
    for index in range(data[1]):
        if offset + 8 > len(data):
            raise ValueError("Truncated ESP segment header")
        address, length = struct.unpack_from("<II", data, offset)
        offset += 8
        if offset + length > len(data) or address + length > 0x100000000:
            raise ValueError("Overflowing or truncated ESP segment")
        payload = data[offset:offset+length]
        for byte in payload:
            checksum ^= byte
        record = dict(index=index, original_file_offset=offset, virtual_address=address,
                      length=length, sha256=hashlib.sha256(payload).hexdigest())
        offset += length
        if not length or address == 0:
            if address == 0 and any(payload):
                raise ValueError("Address-zero padding record contains nonzero bytes")
            records.append(dict(record, kind="empty" if not length else "padding"))
            continue
        region = next((r for r in REGIONS if r[0] <= address and address + length <= r[1]), None)
        if region is None:
            raise ValueError("Segment address is outside the supported ESP32 memory map")
        if any(address < s["virtual_address"] + s["length"] and s["virtual_address"] < address + length for s in segments):
            raise ValueError("Overlapping virtual-address ranges require a separate alias/overlay profile")
        records.append(dict(record, kind="load"))
        segments.append(dict(record, memory_region=region[2], permissions=region[3]))
    checksum_end = (offset // 16 + 1) * 16
    digest_length = 32 if data[23] else 0
    if len(data) != checksum_end + digest_length:
        raise ValueError("Unexpected/truncated image trailer; signed/encrypted/merged images are unsupported")
    if any(data[offset:checksum_end-1]) or data[checksum_end-1] != checksum:
        raise ValueError("ESP image padding or XOR checksum mismatch")
    if digest_length and hashlib.sha256(data[:checksum_end]).digest() != data[checksum_end:]:
        raise ValueError("ESP appended SHA256 mismatch")
    if not any(s["permissions"] & 1 and s["virtual_address"] <= entry < s["virtual_address"] + s["length"] for s in segments):
        raise ValueError("Entry is outside the instruction-capable segment ranges")
    return dict(original_sha256=actual, original_size=len(data), chip_id=0, entry=entry,
                appended_hash=bool(digest_length), records=records, segments=segments)


def build_elf(data, parsed):
    """Deterministic ELF32 LE ET_EXEC with original addresses and no synthetic symbols."""
    segments = [dict(s) for s in parsed["segments"]]
    phnum = len(segments)
    elf = bytearray(52 + 32 * phnum)
    names = bytearray(b"\x00")
    section_names = []
    for segment in segments:
        section_names.append(len(names))
        names += f'.esp_segment_{segment["index"]}'.encode() + b"\x00"
        # p_align=1 avoids inventing original flash alignment/physical load semantics.
        while len(elf) % 4:
            elf.append(0)
        segment["elf_file_offset"] = len(elf)
        start, size = segment["original_file_offset"], segment["length"]
        elf += data[start:start+size]
    string_name = len(names)
    names += b".shstrtab\x00"
    string_offset = len(elf)
    elf += names
    while len(elf) % 4:
        elf.append(0)
    section_offset = len(elf)
    elf += bytes(40)  # SHT_NULL
    for segment, name in zip(segments, section_names):
        flags = 2 | (4 if segment["permissions"] & 1 else 0) | (1 if segment["permissions"] & 2 else 0)
        elf += struct.pack("<10I", name, 1, flags, segment["virtual_address"], segment["elf_file_offset"],
                           segment["length"], 0, 0, 1, 0)
    elf += struct.pack("<10I", string_name, 3, 0, 0, string_offset, len(names), 0, 0, 1, 0)
    elf[:52] = struct.pack("<16sHHIIIIIHHHHHH", b"\x7fELF\x01\x01\x01" + bytes(9), 2, 94, 1,
                          parsed["entry"], 52, section_offset, 0x300, 52, 32, phnum, 40, phnum+2, phnum+1)
    for phindex, segment in enumerate(segments):
        struct.pack_into("<8I", elf, 52+32*phindex, 1, segment["elf_file_offset"],
                         segment["virtual_address"], segment["virtual_address"], segment["length"],
                         segment["length"], segment["permissions"], 1)
    manifest = dict(parsed, segments=segments, adapter_profile="esp32-chip0-app-to-elf-v2",
                    elf_sha256=hashlib.sha256(elf).hexdigest(), elf_size=len(elf),
                    limitations=["Derived ELF contains no original function names or trusted boundaries.",
                                 "Permissions reflect ESP32 memory capabilities, not proof that every byte is code.",
                                 "ELF file offsets differ from original image offsets; use this segment map.",
                                 "No firmware execution, hardware behavior, runtime call resolution or exact-byte matching acceptance."])
    return bytes(elf), manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=Path)
    parser.add_argument("output_directory", type=Path)
    parser.add_argument("--expect-sha256", required=True)
    args = parser.parse_args()
    if not args.output_directory.is_absolute():
        parser.error("Output directory must be absolute and absent")
    descriptor = os.open(args.image, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb") as source:
        before = os.fstat(source.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_IMAGE_BYTES:
            parser.error("Input must be a bounded regular file, not a symlink")
        data = source.read(MAX_IMAGE_BYTES + 1)
        after = os.fstat(source.fileno())
        if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            parser.error("Input changed during read")
    parsed = parse_image(data, args.expect_sha256)
    elf, manifest = build_elf(data, parsed)
    # Exclusive directory creation prevents overwriting any previous evidence.
    args.output_directory.mkdir(mode=0o700)
    owned = []
    try:
        for name, payload in (("image.elf", elf), ("image-map.json", (json.dumps(manifest, indent=2)+"\n").encode())):
            path = args.output_directory / name
            with path.open("xb") as output:
                owned.append(path)
                output.write(payload)
                output.flush()
                os.fsync(output.fileno())
            if path.read_bytes() != payload:
                raise ValueError("Output readback mismatch")
    except BaseException:
        for path in owned:
            path.unlink()
        args.output_directory.rmdir()
        raise
    print(json.dumps(dict(elf=str(args.output_directory/"image.elf"), map=str(args.output_directory/"image-map.json"),
                         original_sha256=parsed["original_sha256"], elf_sha256=manifest["elf_sha256"])))


if __name__ == "__main__":
    main()
