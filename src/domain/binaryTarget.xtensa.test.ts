import { describe, expect, it } from "vitest";
import { parseExecutableHeader } from "./binaryTarget.js";

const header = (bits: 32 | 64 = 32, little = true) => {
  const b = Buffer.alloc(bits === 32 ? 52 : 64);
  b.set([0x7f, 0x45, 0x4c, 0x46, bits === 32 ? 1 : 2, little ? 1 : 2, 1]);
  const write16 = little ? b.writeUInt16LE.bind(b) : b.writeUInt16BE.bind(b);
  const write32 = little ? b.writeUInt32LE.bind(b) : b.writeUInt32BE.bind(b);
  write16(94, 18);
  write16(2, 16);
  write32(0x300, bits === 32 ? 36 : 48);
  return b;
};

describe("Xtensa family recognition retains interpretation without provider admission", () => {
  it.each([32, 64] as const)("retains ELF%d declarations", (bits) => {
    expect(parseExecutableHeader(header(bits), "x64")).toMatchObject({
      ok: true,
      value: {
        format: "elf",
        architecture: "xtensa",
        availableArchitectures: ["xtensa"],
        xtensa: { elfClass: bits, byteOrder: "little", type: 2, flags: 0x300 },
      },
    });
  });
  it("retains big endian for explicit provider refusal", () => {
    expect(parseExecutableHeader(header(32, false), "x64")).toMatchObject({
      ok: true,
      value: {
        xtensa: { elfClass: 32, byteOrder: "big", type: 2, flags: 0x300 },
      },
    });
  });
  it("rejects truncated headers and malformed byte order", () => {
    expect(parseExecutableHeader(header().subarray(0, 39), "x64").ok).toBe(
      false,
    );
    const b = header();
    b[5] = 0;
    expect(parseExecutableHeader(b, "x64").ok).toBe(false);
  });
});
