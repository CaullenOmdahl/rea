# ESP32 Xtensa pilot in this fork

This fork adds a bounded Ghidra lane for ELF32 little-endian Xtensa ET_EXEC
images and an explicit offline ESP32 application-image adapter. Use existing
Ghidra 12.1.x, its compatible JDK, Python 3, and Node. No setup or agent
registration is needed to run the checkout CLI. The original firmware remains
authoritative; the derived ELF and Ghidra observations do not replace an
exact-byte verifier.

## Prepare an immutable image

Choose an absent absolute output directory outside the repository and provide
the independently known SHA256 of the original input:

```sh
python3 scripts/esp32-image-to-elf.py /absolute/path/mainPcb.bin \
  /absolute/path/new-esp32-view --expect-sha256 ORIGINAL_SHA256
```

The adapter requires a regular non-symlink file, ESP32 chip ID 0, bounded
non-overlapping segments in the supported memory regions, an entry inside an
instruction-capable segment, valid padding/XOR checksum and any declared
appended SHA256. Unexpected trailers fail; ESP32-S3, encrypted/signed/merged
images, other chip IDs and unknown segment addresses need separate profiles.
It never overwrites an existing destination or executes firmware.
Address-zero padding and zero-length structural records remain in the original
record map and checksum calculation, without becoming ELF load segments.

`image.elf` copies each segment at its original virtual address without creating
function symbols. `image-map.json` binds original and derived digests and each
segment's original file offset, ELF offset, address, length and byte digest.
Section permissions describe memory capabilities, not proof that all bytes in
a section are instructions. The ELF is a synthetic analysis view, not recovered
source or a firmware rebuild.

From this source checkout, install locked local dependencies and build the
runtime. The development Node/npm versions are pinned by the upstream project;
its supported runtime range is listed in `package.json`.

```sh
npm ci
npm run build:cached
GHIDRA_INSTALL_DIR=/absolute/path/ghidra JAVA_HOME=/absolute/path/jdk21 \
  node scripts/rea.mjs analyze /absolute/path/new-esp32-view/image.elf \
  --provider ghidra --format json
```

The existing `open_binary` MCP operation also accepts that ELF with
`provider_id: "ghidra"` in a separately configured fork runtime. The upstream
installed REA server does not gain this fork's support automatically. This guide
does not authorize changing registrations.

## Admission and interpretation

Family recognition retains class, byte order, type and raw flags. Ghidra admits
only ELF32, little endian, ET_EXEC and flags within `0x300`. Other declarations
remain recognizable but unsupported. Profile identity commits these facts and
the pilot lane version. The loader is explicitly `ElfLoader`, with
`Xtensa:LE:32:default` and compiler specification `default`. This is a generic
Xtensa ELF interpretation; ELF headers alone do not identify an ESP32 module or
exclude every other Xtensa implementation. Only the raw adapter binds chip ID 0.
Hopper, IDA and Windows Ghidra do not implicitly gain Xtensa support.

## Verify real Ghidra evidence

Use an absolute prefix for already installed GNU Xtensa tools:

```sh
GHIDRA_INSTALL_DIR=/absolute/path/ghidra JAVA_HOME=/absolute/path/jdk21 \
REA_XTENSA_TOOL_PREFIX=/absolute/path/bin/xtensa-esp32-elf- \
  npm run verify:ghidra:xtensa
```

This generates a tiny public source-owned fixture and runs the fork's actual
MCP server/Ghidra provider. GNU readelf/objdump supply the independent address
and instruction oracle. Checks cover target identity, language/compiler,
function addresses, nonempty decompilation, direct and indirect call classifications, literal xrefs
and bytes, and address-to-file-offset mapping. No target is executed. A JSON
report and temporary fixtures remain in the reported private temporary directory.

To also check every segment in a supplied original image against the imported
ELF view, use the built runtime:

```sh
GHIDRA_INSTALL_DIR=/absolute/path/ghidra JAVA_HOME=/absolute/path/jdk21 \
REA_XTENSA_TOOL_PREFIX=/absolute/path/bin/xtensa-esp32-elf- \
  node scripts/verify-real-ghidra-xtensa.mjs /absolute/path/mainPcb.bin \
  ORIGINAL_SHA256 /absolute/path/new-esp32-view
```

The optional image lane independently parses the original segment records,
compares original payloads with the ELF view, then checks the provider's loaded
mapping coverage, offsets and hashes. This is a separate verification report:
REA's native load-image attestation API still labels ELF observations
`unsupported` because its built-in independent attestor currently covers DOS.
It is not silently relabelled as verified. The image lane does not certify
function boundaries or call graphs in the proprietary firmware.

The real-provider verifier uses a 512 MiB Java heap and serial sessions. Actual
startup/query latency is retained per operation; the heap setting is not an RSS
limit. It never reads or writes existing Ghidra projects or integration caches.

## Dependency tracing limits

Prefer typed reference edges and instruction inspection over bare caller/callee
or xref lists. Preserve unresolved sites and multiple candidate targets.
Literal bytes can corroborate an address, but not runtime execution. Ghidra's
function ranges, names, p-code and decompilation remain derived observations;
stripped code, padding, literals and ambiguous indirect flow require independent
byte/boundary checks. Keep imported-model claims separate from hardware behavior
and from exact-byte matching acceptance.

Verification scope: source-owned windowed-call fixture on Linux x64 with Ghidra
12.1.4/JDK 21, plus explicitly requested original-image mapping checks. No S3,
other Xtensa ABI/ISA, device, timing, hardware, or complete dependency-recovery
claim is implied. Independent review and production integration are separate.
