import { describe, expect, it } from "vitest";
import type {
  BinaryTarget,
  XtensaElfMetadata,
} from "../domain/binaryTargetTypes.js";
import {
  ghidraXtensaProfileParameters,
  ghidraXtensaUnsupportedReason,
} from "./GhidraXtensaProfile.js";
import { ghidraHeadlessArguments } from "./GhidraLauncher.js";
import { HopperProvider } from "../hopper/HopperProvider.js";
import { IdaProvider } from "../ida/IdaProvider.js";
import { GhidraProvider } from "./GhidraProvider.js";
import { silentLogger } from "../logger.js";
import { parseConfig } from "../config/parseConfig.js";
import type { GhidraClientOptions } from "./GhidraClientTypes.js";
import {
  parseGhidraSessionInfo,
  GHIDRA_SESSION_CAPABILITIES,
} from "./GhidraSessionValues.js";

const target = (change: Partial<XtensaElfMetadata> = {}): BinaryTarget => ({
  kind: "executable",
  format: "elf",
  architecture: "xtensa",
  availableArchitectures: ["xtensa"],
  path: "/fixture.elf",
  sha256: "a".repeat(64),
  xtensa: {
    elfClass: 32,
    byteOrder: "little",
    type: 2,
    flags: 0x300,
    ...change,
  },
});
const config = parseConfig({ GHIDRA_INSTALL_DIR: "/ghidra" });
if (!config.ok) throw config.error;

describe("Xtensa handshake commitment", () => {
  it("binds the production handshake to the committed Xtensa load specification", async () => {
    let captured: GhidraClientOptions | undefined;
    const host = {
      platform: "linux" as const,
      architecture: "x64" as const,
      readText: () => "application.version=12.1.4\n",
      executable: () => true,
      probeJava: () => ({
        version: "21",
        major: 21,
        home: "/jdk",
        bits: 64 as const,
        runtime: "jdk" as const,
      }),
    };
    const provider = new GhidraProvider(
      config.value,
      silentLogger,
      {},
      host,
      (options) => {
        captured = options;
        throw new Error("captured client boundary");
      },
    );
    const profile = await provider.resolveAnalysisProfile(target());
    if (!profile.ok || profile.value.profile === null)
      throw new Error("Missing profile");
    const commitment = profile.value.profile;
    expect(() => provider.createClient(target(), commitment)).toThrow(
      "captured client boundary",
    );
    if (captured === undefined) throw new Error("Missing client options");
    expect(captured).toMatchObject({
      expectedLanguageId: "Xtensa:LE:32:default",
      expectedCompilerSpecId: "default",
    });
    if (
      captured.expectedLanguageId === undefined ||
      captured.expectedCompilerSpecId === undefined
    )
      throw new Error("Missing handshake commitment");
    const expected = {
      runId: "11111111-1111-4111-8111-111111111111",
      providerVersion: "12.1.4",
      profileDigest: "b".repeat(64),
      targetSha256: target().sha256,
      expectedLanguageId: captured.expectedLanguageId,
      expectedCompilerSpecId: captured.expectedCompilerSpecId,
    };
    const session = {
      name: "REA Ghidra bridge",
      run_id: expected.runId,
      profile_digest: expected.profileDigest,
      provider: { id: "ghidra", version: "12.1.4" },
      read_only: false,
      analysis_complete: true,
      analysis_timed_out: false,
      capabilities: [...GHIDRA_SESSION_CAPABILITIES],
      target: {
        name: "fixture.elf",
        language_id: "Xtensa:LE:32:default",
        compiler_spec_id: "default",
        image_base: "0x0",
        default_address_space: "ram",
        sha256: expected.targetSha256,
      },
    };
    expect(parseGhidraSessionInfo(session, expected).ok).toBe(true);
    expect(
      parseGhidraSessionInfo(
        {
          ...session,
          target: { ...session.target, language_id: "x86:LE:32:default" },
        },
        expected,
      ).ok,
    ).toBe(false);
    expect(
      parseGhidraSessionInfo(
        {
          ...session,
          target: { ...session.target, compiler_spec_id: "windows" },
        },
        expected,
      ).ok,
    ).toBe(false);
  });
});

describe("Xtensa lane admission and interpretation", () => {
  it("commits metadata and explicit loader/language", () => {
    expect(ghidraXtensaUnsupportedReason(target())).toBeNull();
    expect(ghidraXtensaProfileParameters(target())).toMatchObject({
      language_id: "Xtensa:LE:32:default",
      loader: "ElfLoader",
      xtensa_elf: { flags: 0x300 },
    });
    expect(
      ghidraHeadlessArguments({
        projectRoot: "/p",
        targetPath: "/fixture.elf",
        bridgeScriptPath: "/b/ReaGhidraBridge.java",
        descriptorPath: "/d",
        ghidraLogPath: "/g",
        scriptLogPath: "/s",
        xtensa: true,
      }),
    ).toEqual(expect.arrayContaining(["ElfLoader", "Xtensa:LE:32:default"]));
  });
  it.each([
    { elfClass: 64 },
    { byteOrder: "big" },
    { type: 1 },
    { type: 3 },
    { flags: 0x400 },
  ] as const)("refuses unsupported declarations %j", (change) => {
    expect(ghidraXtensaUnsupportedReason(target(change))).not.toBeNull();
  });
  it("does not broaden Hopper, IDA or Windows", () => {
    expect(
      new HopperProvider(
        config.value,
        silentLogger,
        {},
        "linux",
      ).inspectTargetSupport(target()).status,
    ).toBe("unsupported");
    expect(
      new IdaProvider(config.value, {}).inspectTargetSupport(target()).status,
    ).toBe("unsupported");
    const host = {
      platform: "win32" as const,
      architecture: "x64" as const,
      readText: () => "application.version=12.1.4\n",
      executable: () => true,
      probeJava: () => ({
        version: "21",
        major: 21,
        home: "/jdk",
        bits: 64 as const,
        runtime: "jdk" as const,
      }),
    };
    expect(
      new GhidraProvider(
        config.value,
        silentLogger,
        {},
        host,
      ).inspectTargetSupport(target()).status,
    ).toBe("unsupported");
  });
});
