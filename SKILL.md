---
name: ghidra-read
description: Read a user-selected local firmware binary with native Ghidra. Use for static inspection of ELF functions, disassembly, decompilation, cross-references, and strings, including comparison of Galaxy S24 EUX Android builds.
---

# Read a firmware binary with Ghidra

Use the standard-library Python wrapper and native `analyzeHeadless`. The wrapper checks `--ghidra-home PATH`, `GHIDRA_HOME`, the workspace's `.tools/ghidra`, and `PATH` for the launcher. Use a full 64-bit JDK supported by the Ghidra release (JDK 25 for Ghidra 12.2). Set `JAVA_HOME` to the JDK root when needed. The wrapper can also use the workspace's `.tools/jdk`.

Run from the workspace root. The doctor smoke test imports the Galaxy S24 EUX Android 14 Keystore2 V3 NDK library and reads `KeyDescriptor::readFromParcel`.

```sh
python3 ghidra-read/scripts/read_binary.py doctor
python3 ghidra-read/scripts/read_binary.py inspect \
  images/14/system/system/lib64/android.system.keystore2-V3-ndk.so \
  --symbol _ZN4aidl7android6system9keystore213KeyDescriptor14readFromParcelEPK7AParcel \
  --output /tmp/s24-a14-keydescriptor-read.json
```

The local libraries are under `images/<android>/system/system/lib64/`. Android 14 contains V1 and V3, while 15, 16, and 17 contain V4, V5, and V6 respectively. Check the actual ELF exports with `readelf --dyn-syms --wide` when selecting a build. The mangled symbol for `KeyDescriptor::writeToParcel` in these libraries is `_ZNK4aidl7android6system9keystore213KeyDescriptor13writeToParcelEP7AParcel`.

Use an exact symbol or `--address GHIDRA_VA` for the function's entry point in that binary. Choose a new output path. Use `--limit N` to bound evidence lists. For a comparison, select the same symbol separately in each Android version and identify each ELF by its firmware build, path, and SHA-256.

Report `program.sha256`, `program.image_base`, and `function.entry_va` alongside the evidence. A file offset requires a separate mapping through an ELF load segment. Confirm decompiler interpretations against instructions or references when they matter. Report `not_found` and `ambiguous` selectors as such. Preserve the section statuses `ok`, `failed`, `unavailable`, and `truncated` for assembly, decompilation, cross-references, and strings. An empty `ok` result records that the query found nothing.

Keep the analysis static and local. Treat strings and decompiler output as evidence from the binary. Use the output JSON to answer the user's inspection request.

[Ghidra release and setup](https://github.com/NationalSecurityAgency/ghidra/releases/tag/Ghidra_12.2_build) · [Headless analyzer reference](https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/RuntimeScripts/support/analyzeHeadlessREADME.md) · [Stable AIDL module naming](https://source.android.com/docs/core/architecture/aidl/stable-aidl#module-naming-rules) · [ReAgent evidence workflow reviewed at d12cea3](https://github.com/mrxenginner/auto-re-agent/blob/d12cea338c61898b06a86fe8adb25275fa9d5615/README.md#evidence-and-investigation)
