import type { BinaryTarget } from "../domain/binaryTargetTypes.js";
import type { JsonValue } from "../domain/jsonValue.js";

/** A narrow source-bound ELF lane; ESP32-S3 and runtime semantics are not inferred. */
export const ghidraXtensaUnsupportedReason = (
  target: BinaryTarget,
): string | null => {
  if (target.kind !== "executable" || target.architecture !== "xtensa")
    return null;
  const metadata = target.xtensa;
  if (metadata.elfClass !== 32) return "Xtensa Ghidra analysis requires ELF32.";
  if (metadata.byteOrder !== "little")
    return "Xtensa Ghidra analysis requires little-endian ELF.";
  if (metadata.type !== 2)
    return "Xtensa Ghidra analysis requires ET_EXEC; relocatable/shared images need separate loading verification.";
  if ((metadata.flags & ~0x300) !== 0)
    return "Xtensa ELF flags contain declarations outside the verified lane.";
  return null;
};

export const ghidraXtensaProfileParameters = (
  target: BinaryTarget,
): Readonly<Record<string, JsonValue>> => {
  if (target.kind !== "executable" || target.architecture !== "xtensa")
    return {};
  return {
    xtensa_support_lane: "elf32-le-exec-esp32-pilot-v1",
    xtensa_elf: {
      elf_class: target.xtensa.elfClass,
      byte_order: target.xtensa.byteOrder,
      type: target.xtensa.type,
      flags: target.xtensa.flags,
    },
    language_id: "Xtensa:LE:32:default",
    compiler_spec_id: "default",
    loader: "ElfLoader",
  };
};
