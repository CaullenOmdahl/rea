#!/usr/bin/env node
// Caller-installed GNU Xtensa tools/Ghidra/JDK only; targets are never executed.
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { requireMcpOperationResult } from "./lib/mcp-verifier-results.mjs";
const execute = promisify(execFile);
const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");
const root = fileURLToPath(new URL("..", import.meta.url));
const workspace = await mkdtemp(join(tmpdir(), "rea-xtensa-proof-"));
const toolPrefix = process.env.REA_XTENSA_TOOL_PREFIX;
assert.ok(
  toolPrefix,
  "Set REA_XTENSA_TOOL_PREFIX to the absolute installed GNU tool prefix",
);
assert.ok(toolPrefix.startsWith("/"), "GNU tool prefix must be absolute");
assert.ok(
  process.env.GHIDRA_INSTALL_DIR,
  "Set caller-installed GHIDRA_INSTALL_DIR",
);
const fixture = join(workspace, "fixture.elf");
const object = join(workspace, "fixture.o");
const command = async (tool, args) => {
  const result = await execute(tool, args, {
    maxBuffer: 4 * 1024 * 1024,
    timeout: 20000,
  });
  return { tool, args, stdout: result.stdout, stderr: result.stderr };
};
const producer = [];
producer.push(await command(toolPrefix + "as", ["--version"]));
producer.push(await command(toolPrefix + "objdump", ["--version"]));
producer.push(
  await command(toolPrefix + "as", [
    "-o",
    object,
    join(root, "tests/conformance/esp32/xtensa-probe.S"),
  ]),
);
producer.push(
  await command(toolPrefix + "ld", [
    "--no-relax",
    "-T",
    join(root, "tests/conformance/esp32/xtensa-probe.ld"),
    "-o",
    fixture,
    object,
  ]),
);
producer.push(
  await command(toolPrefix + "readelf", ["-h", "-l", "-s", fixture]),
);
producer.push(await command(toolPrefix + "objdump", ["-d", "-s", fixture]));
const dump = producer.at(-1).stdout;
assert.match(dump, /400d1013:.*call8\s+400d1020/);
assert.match(dump, /400d1016:.*l32r\s+a8, 400d1000/);
assert.match(dump, /400d1019:.*callx8\s+a8/);
const runtime = join(workspace, "runtime");
await mkdir(runtime);
const env = {
  PATH: process.env.PATH ?? "/usr/bin:/bin",
  TMPDIR: runtime,
  REA_LOG_LEVEL: "silent",
  REA_ANALYSIS_PROVIDER: "ghidra",
  GHIDRA_INSTALL_DIR: process.env.GHIDRA_INSTALL_DIR,
  JAVA_HOME: process.env.JAVA_HOME,
  GHIDRA_HEADLESS_MAXMEM: "512M",
  REA_GHIDRA_STARTUP_TIMEOUT_MS: "330000",
  HOPPER_LAUNCHER_PATH: "/rea-unconfigured-deep-provider/hopper",
};
// Do not forward undefined env entries or any ambient credentials.
for (const key of Object.keys(env)) if (env[key] === undefined) delete env[key];
const transport = new StdioClientTransport({
  command: process.execPath,
  args: [join(root, "scripts/rea.mjs"), "mcp"],
  env,
  stderr: "pipe",
});
const client = new Client({ name: "rea-xtensa-proof", version: "1" });
let stderr = "";
transport.stderr?.on("data", (bytes) => {
  stderr = (stderr + bytes.toString()).slice(-65536);
});
const observations = [];
const call = async (name, args = {}) => {
  const start = performance.now();
  const reply = await client.callTool({ name, arguments: args }, undefined, {
    timeout: 360000,
  });
  const value = requireMcpOperationResult(reply, name);
  observations.push({
    name,
    args,
    elapsed_ms: performance.now() - start,
    value,
  });
  return value;
};
const report = {
  workspace,
  producer,
  observations,
  limitations: [
    "Static fixture only; not hardware or runtime call proof.",
    "Unresolved computed calls remain unknown.",
    "Ghidra body boundaries are observations, not exact-byte matching acceptance.",
  ],
};
let opened = false;
try {
  await client.connect(transport);
  const original = await readFile(fixture);
  const target = await call("open_binary", {
    path: fixture,
    provider_id: "ghidra",
  });
  opened = true;
  assert.equal(target.architecture, "xtensa");
  assert.equal(target.sha256, hash(original));
  const image = await call("inspect_native_load_image");
  assert.equal(image.observations.language_id, "Xtensa:LE:32:default");
  assert.equal(image.observations.compiler_spec_id, "default");
  assert.ok(
    image.observations.source_files.some(
      (file) =>
        file.original_sha256 === hash(original) &&
        file.modified_sha256 === hash(original),
    ),
  );
  const names = await call("list_procedures");
  for (const [name, address] of [
    ["fixture_entry", 0x400d1010],
    ["fixture_callee", 0x400d1020],
  ]) {
    const functionRecord = names.find((item) => item.value === name);
    assert.ok(functionRecord, `Missing ${name}`);
    assert.equal(Number(BigInt(functionRecord.address)), address);
  }
  const direct = await call("resolve_native_call_targets", {
    address: "0x400d1013",
  });
  assert.equal(direct.status, "direct");
  assert.ok(
    direct.targets.some((item) => BigInt(item.address) === 0x400d1020n),
  );
  const literal = await call("inspect_native_instruction", {
    address: "0x400d1016",
  });
  assert.equal(literal.bytes, "81faff");
  assert.equal(literal.length, 3);
  assert.ok(
    literal.references.some(
      (ref) => BigInt(ref.target_address) === 0x400d1000n,
    ),
  );
  const data = await call("read_bytes", { address: "0x400d1000", length: 4 });
  assert.equal(data.bytes_hex, "20100d40");
  const indirect = await call("resolve_native_call_targets", {
    address: "0x400d1019",
  });
  assert.ok(
    ["unresolved", "resolved-indirect", "ambiguous"].includes(indirect.status),
  );
  if (indirect.status === "resolved-indirect")
    assert.ok(
      indirect.targets.some((item) => BigInt(item.address) === 0x400d1020n),
    );
  const xrefs = await call("xrefs", { address: "0x400d1020" });
  assert.ok(xrefs.some((addr) => BigInt(addr) === 0x400d1013n));
  const instruction = await call("inspect_native_instruction", {
    address: "0x400d1013",
  });
  assert.equal(instruction.bytes, "e50000");
  const offset = await call("address_to_file_offset", {
    address: "0x400d1013",
  });
  assert.equal(
    original
      .subarray(offset.file_offset, offset.file_offset + 3)
      .toString("hex"),
    "e50000",
  );
  const dossier = await call("analyze_function", { procedure: "0x400d1010" });
  assert.ok(
    dossier.pseudocode.trim().length > 0,
    "Decompiler returned no fixture pseudocode",
  );
  report.fixture_status = "pass";
  await call("close_binary");
  opened = false;
  // Optional proprietary image verification. Inputs and report stay outside Git.
  if (process.argv.length > 2) {
    assert.equal(
      process.argv.length,
      5,
      "Usage: node scripts/verify-real-ghidra-xtensa.mjs [ORIGINAL_IMAGE EXPECTED_SHA256 VIEW_DIRECTORY]",
    );
    const [imagePath, expected, view] = process.argv.slice(2);
    const bytes = await readFile(imagePath);
    assert.equal(hash(bytes), expected);
    const map = JSON.parse(
      await readFile(join(view, "image-map.json"), "utf8"),
    );
    const elf = await readFile(join(view, "image.elf"));
    assert.equal(hash(elf), map.elf_sha256);
    assert.equal(map.original_sha256, expected);
    assert.equal(map.adapter_profile, "esp32-chip0-app-to-elf-v2");
    let originalOffset = 24;
    const loadRecords = [];
    for (let i = 0; i < bytes[1]; i++) {
      const address = bytes.readUInt32LE(originalOffset),
        length = bytes.readUInt32LE(originalOffset + 4);
      originalOffset += 8;
      const record = map.records[i];
      assert.equal(record.index, i);
      assert.equal(record.virtual_address, address);
      assert.equal(record.length, length);
      assert.equal(record.original_file_offset, originalOffset);
      const payload = bytes.subarray(originalOffset, originalOffset + length);
      assert.equal(record.sha256, hash(payload));
      const kind = !length ? "empty" : address === 0 ? "padding" : "load";
      assert.equal(record.kind, kind);
      if (kind === "padding") assert.ok(payload.every((byte) => byte === 0));
      if (kind === "load") loadRecords.push(record);
      originalOffset += length;
    }
    assert.equal(map.records.length, bytes[1]);
    assert.equal(map.segments.length, loadRecords.length);
    for (const [index, record] of loadRecords.entries()) {
      const segment = map.segments[index];
      for (const key of [
        "index",
        "virtual_address",
        "length",
        "original_file_offset",
        "sha256",
      ])
        assert.equal(segment[key], record[key]);
      assert.deepEqual(
        elf.subarray(
          segment.elf_file_offset,
          segment.elf_file_offset + segment.length,
        ),
        bytes.subarray(
          segment.original_file_offset,
          segment.original_file_offset + segment.length,
        ),
      );
    }
    await call("open_binary", {
      path: join(view, "image.elf"),
      provider_id: "ghidra",
    });
    opened = true;
    const loaded = await call("inspect_native_load_image");
    const observed = loaded.observations;
    assert.equal(observed.language_id, "Xtensa:LE:32:default");
    assert.ok(
      observed.entry_points.some(
        (entry) => BigInt(entry) === BigInt(map.entry),
      ),
    );
    assert.ok(
      observed.source_files.some(
        (file) =>
          file.original_sha256 === map.elf_sha256 &&
          file.modified_sha256 === map.elf_sha256,
      ),
    );
    for (const segment of map.segments) {
      const pieces = observed.mappings
        .filter(
          (m) =>
            m.loaded &&
            m.initialized &&
            !m.overlay &&
            m.address_space === observed.default_address_space &&
            BigInt(m.start) >= BigInt(segment.virtual_address) &&
            BigInt(m.start) + BigInt(m.length) <=
              BigInt(segment.virtual_address + segment.length),
        )
        .sort((a, b) => Number(BigInt(a.start) - BigInt(b.start)));
      let cursor = segment.virtual_address;
      for (const piece of pieces) {
        assert.equal(Number(BigInt(piece.start)), cursor);
        assert.equal(
          piece.file_offset,
          segment.elf_file_offset + cursor - segment.virtual_address,
        );
        const expectedBytes = bytes.subarray(
          segment.original_file_offset + cursor - segment.virtual_address,
          segment.original_file_offset +
            cursor -
            segment.virtual_address +
            piece.length,
        );
        assert.equal(piece.sha256, hash(expectedBytes));
        cursor += piece.length;
      }
      assert.equal(
        cursor,
        segment.virtual_address + segment.length,
        `Incomplete original-byte coverage for segment ${segment.index}`,
      );
    }
    report.original_image_status = "pass";
    report.original_sha256 = expected;
    await call("close_binary");
    opened = false;
  }
} catch (error) {
  report.failure = error.stack ?? String(error);
  throw error;
} finally {
  if (opened)
    try {
      await call("close_binary");
    } catch (error) {
      report.cleanup_failure = String(error);
    }
  await client.close();
  report.stderr = stderr;
  const path = join(workspace, "report.json");
  await writeFile(path, JSON.stringify(report, null, 2) + "\n");
  console.error(`Xtensa report: ${path}`);
}
