#!/usr/bin/env python3
"""Read one function from a local ELF with Ghidra's headless analyzer."""

import argparse
import hashlib
import json
import os
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent
WORKSPACE = SCRIPTS.parents[1]
DOCTOR_BINARY = (WORKSPACE / "images/14/system/system/lib64/"
                 "android.system.keystore2-V3-ndk.so")
DOCTOR_SYMBOL = "_ZN4aidl7android6system9keystore213KeyDescriptor14readFromParcelEPK7AParcel"
SECTION_NAMES = ("decompile", "assembly", "xrefs", "strings")
SECTION_STATUSES = {"ok", "failed", "unavailable", "truncated"}


def ghidra_launcher(explicit):
    home = explicit or os.environ.get("GHIDRA_HOME")
    if home:
        path = Path(home).expanduser().resolve() / "support" / "analyzeHeadless"
    else:
        local = WORKSPACE / ".tools/ghidra/support/analyzeHeadless"
        path = local if local.is_file() else Path(shutil.which("analyzeHeadless") or local)
    if not path.is_file() or not os.access(path, os.X_OK):
        raise ValueError(f"Ghidra launcher unavailable at {path}. Set --ghidra-home or GHIDRA_HOME.")
    return path.resolve()


def java_environment():
    env = os.environ.copy()
    home = env.get("JAVA_HOME")
    if not home:
        local = WORKSPACE / ".tools/jdk"
        javac = shutil.which("javac")
        if (local / "bin/javac").is_file():
            home = str(local)
        elif javac:
            home = str(Path(javac).resolve().parent.parent)
        else:
            raise ValueError("A full JDK is required. Set JAVA_HOME to a JDK supported by Ghidra.")
    jdk = Path(home).expanduser().resolve()
    if not all(os.access(jdk / "bin" / name, os.X_OK) for name in ("java", "javac")):
        raise ValueError(f"Java or javac is missing under {jdk}")
    env["JAVA_HOME"] = str(jdk)
    env["PATH"] = str(jdk / "bin") + os.pathsep + env.get("PATH", os.defpath)
    java = subprocess.run([jdk / "bin/java", "-version"], capture_output=True, text=True,
                          timeout=15, check=True)
    version = (java.stderr or java.stdout).strip().splitlines()
    if not version:
        raise ValueError(f"Unable to determine Java version under {jdk}")
    return env, version[0]


def input_identity(path):
    path = path.expanduser().resolve(strict=True)
    if not stat.S_ISREG(path.stat().st_mode):
        raise ValueError(f"Expected a regular ELF file at {path}")
    with path.open("rb") as stream:
        if stream.read(4) != b"\x7fELF":
            raise ValueError(f"Expected an ELF file at {path}")
        stream.seek(0)
        return path, hashlib.file_digest(stream, "sha256").hexdigest()


def run_headless(launcher, env, binary, scratch, selector, limit, timeout):
    report = scratch / "function.json"
    log = scratch / "headless.log"
    kind, value = selector
    command = [
        str(launcher), str(scratch), "inspect", "-import", str(binary), "-readOnly",
        "-scriptPath", str(SCRIPTS), "-postScript", "ReadFunction.java",
        str(report), kind, value, str(limit),
    ]
    with log.open("wb") as stream:
        with subprocess.Popen(command, cwd=scratch, env=env, stdin=subprocess.DEVNULL,
                              stdout=stream, stderr=subprocess.STDOUT, start_new_session=True) as process:
            try:
                process.wait(timeout=timeout)
            except (subprocess.TimeoutExpired, KeyboardInterrupt):
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait()
                raise
    if process.returncode or not report.is_file():
        with log.open("rb") as stream:
            stream.seek(max(0, log.stat().st_size - 6000))
            detail = stream.read().decode("utf-8", errors="replace").strip()
        raise ValueError(f"Ghidra did not produce a report (exit {process.returncode}).\n{detail}")
    return json.loads(report.read_text(encoding="utf-8"))


def validate(report, selector, digest):
    kind, value = selector
    if (
        report.get("schema_version") != 1
        or report.get("status") not in {"ok", "not_found", "ambiguous"}
        or report.get("selector") != {"kind": kind, "value": value}
    ):
        raise ValueError("Ghidra returned an unexpected evidence record")
    if report.get("program", {}).get("sha256", "").lower() != digest:
        raise ValueError("Ghidra's imported binary SHA-256 differs from the selected ELF")
    if report["status"] == "ok":
        function = report.get("function", {})
        sections = report.get("sections", {})
        if not function.get("address") or not all(
            sections.get(name, {}).get("status") in SECTION_STATUSES for name in SECTION_NAMES
        ):
            raise ValueError("Ghidra returned incomplete function evidence")


def publish(report, destination):
    destination = destination.expanduser().absolute()
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".ghidra-read-", dir=destination.parent) as temporary:
        staging = Path(temporary) / "evidence.json"
        staging.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        try:
            os.link(staging, destination)
        except FileExistsError as exc:
            raise ValueError(f"Output already exists: {destination}") from exc
    return destination


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    doctor = commands.add_parser("doctor", help="Import the local Galaxy S24 Keystore2 NDK ELF")
    inspect = commands.add_parser("inspect", help="Save one function evidence record")
    inspect.add_argument("binary", type=Path)
    target = inspect.add_mutually_exclusive_group(required=True)
    target.add_argument("--symbol", help="Exact ELF symbol or Ghidra function name")
    target.add_argument("--address", help="Ghidra virtual address in hexadecimal")
    inspect.add_argument("--output", type=Path, required=True)
    inspect.add_argument("--limit", type=int, default=100, help="Maximum items per evidence list")
    for command in (doctor, inspect):
        command.add_argument("--ghidra-home", type=Path)
        command.add_argument("--timeout", type=int, default=240, help="Headless timeout in seconds")
    args = parser.parse_args()

    if args.command == "doctor":
        binary, selector, limit = DOCTOR_BINARY, ("symbol", DOCTOR_SYMBOL), 40
    else:
        binary, limit = args.binary, args.limit
        if args.output.expanduser().exists() or args.output.expanduser().is_symlink():
            parser.error(f"output already exists: {args.output}")
        if args.symbol is not None:
            if not args.symbol.strip() or args.symbol.startswith("-"):
                parser.error("--symbol must be a nonempty name that does not start with '-'")
            selector = "symbol", args.symbol
        else:
            if not re.fullmatch(r"(?:0[xX])?[0-9a-fA-F]{1,16}", args.address):
                parser.error("--address must be a hexadecimal Ghidra virtual address")
            selector = "address", args.address
    if not 1 <= limit <= 1000 or args.timeout < 1:
        parser.error("--limit must be between 1 and 1000 and --timeout must be positive")

    try:
        binary, digest = input_identity(binary)
        launcher = ghidra_launcher(args.ghidra_home)
        env, java = java_environment()
        with tempfile.TemporaryDirectory(prefix="ghidra-read-") as temporary:
            report = run_headless(launcher, env, binary, Path(temporary), selector, limit, args.timeout)
        validate(report, selector, digest)
        report["program"]["input_path"] = str(binary)
        report["program"]["sha256"] = digest
        if args.command == "doctor":
            if (
                report["status"] != "ok"
                or not report["program"]["language_id"].startswith("AARCH64:LE:64:")
                or report["sections"]["decompile"]["status"] != "ok"
                or not report["sections"]["decompile"]["data"]
                or report["sections"]["assembly"]["status"] not in {"ok", "truncated"}
                or not report["sections"]["assembly"]["data"]
            ):
                raise ValueError(f"Keystore2 import or function evidence check failed: {report['status']}")
            print(java)
            print(f"Ghidra {report['program']['ghidra_version']} ({launcher})")
            function = report["function"]
            print(f"{binary.name}: {function['qualified_name']} at {function['address']} (VA {function['entry_va']})")
            print(f"SHA-256 {digest}")
            return 0
        destination = publish(report, args.output)
        print(f"{report['status']} {destination}")
        return 0 if report["status"] == "ok" else 2
    except subprocess.TimeoutExpired as exc:
        print(f"Process timed out after {exc.timeout} seconds", file=sys.stderr)
        return 1
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        print(exc, file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
