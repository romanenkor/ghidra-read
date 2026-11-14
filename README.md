# ghidra-read

Read a selected local ELF function with native Ghidra and save its assembly,
decompilation, cross-references, and strings as bounded JSON evidence.

The reader consists of a standard-library Python wrapper and a Ghidra Java
script. Install Python 3.11 or newer, native Ghidra, and a full JDK supported by
that Ghidra release. Set `GHIDRA_HOME` and `JAVA_HOME` when needed; the wrapper
also discovers workspace-local installations under `.tools/ghidra` and
`.tools/jdk`.

Clone this repository as `ghidra-read` inside your analysis workspace. Run from
that workspace:

```sh
python3 ghidra-read/scripts/read_binary.py inspect /path/to/library.so \
  --symbol exact_exported_symbol --output /tmp/function-evidence.json
```

Use `--address` for a Ghidra virtual address instead of a symbol. Choose a new
output path; existing output is preserved. See [SKILL.md](SKILL.md) for the
selection rules and evidence interpretation.

The saved examples cover Galaxy S24 EUX Keystore2 libraries for Android 14–17.
The firmware files and Ghidra/JDK installations stay outside this repository.
The evidence tests and `doctor` command require the matching local firmware
layout documented in the skill:

```sh
python3 -B ghidra-read/test_keystore2_evidence.py -v
python3 ghidra-read/scripts/read_binary.py doctor
```

This fork's slim reader follows the original ReAgent implementation in Git
history. The previous tree is available at commit
`d12cea338c61898b06a86fe8adb25275fa9d5615`. The original
[MIT license](LICENSE) is retained.
