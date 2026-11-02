"""Safe per-launch staging for LeviLamina's early Windows loader.

This module deliberately does not use the normal post-start injector.  Its
output is an opt-in ``BOL_EARLY_DLL`` environment variable for a WineGDK build
which implements the corresponding pre-entry-point hook.
"""
# SPDX-License-Identifier: MIT

import hashlib
import json
import os
import shutil
import tempfile
from pathlib import Path

from .config import DATA, LOGS
from .games import mc_version_str
from .log import BolError


SUPPORTED_VERSION = "1.26.51.1"
_STATE_FILE = DATA / "levilamina-staging.json"
_LOG_FILE = LOGS / "levilamina-early-load.log"
_FILES = ("PreLoader.dll", "PreLoaderConfig.json",
          "mods/LeviLamina/LeviLamina.dll", "mods/LeviLamina/manifest.json")
_ENGINE_MARKER = ".bol-early-loader"


def require_engine_support(engine_path) -> None:
    """Refuse a launch when WineGDK cannot consume ``BOL_EARLY_DLL``.

    An unknown Wine build silently ignores environment variables.  Failing
    before staging is preferable to looking successful while starting
    Minecraft without LeviLamina.
    """
    marker = Path(engine_path) / "files" / _ENGINE_MARKER
    if not marker.is_file():
        raise BolError(
            "This WineGDK engine does not include the LeviLamina early-loader "
            "patch. Install an engine build marked .bol-early-loader before "
            "enabling this feature.")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _require_amd64_dll(path: Path, label: str) -> None:
    """Reject non-PE, x86, executable, and malformed DLLs without Wine."""
    try:
        with path.open("rb") as stream:
            header = stream.read(0x1000)
    except OSError as exc:
        raise BolError(f"Could not read {label}: {exc}") from exc
    if len(header) < 0x40 or header[:2] != b"MZ":
        raise BolError(f"{label} is not a PE DLL.")
    offset = int.from_bytes(header[0x3C:0x40], "little")
    if offset + 24 > len(header) or header[offset:offset + 4] != b"PE\0\0":
        raise BolError(f"{label} has an invalid PE header.")
    machine = int.from_bytes(header[offset + 4:offset + 6], "little")
    characteristics = int.from_bytes(header[offset + 22:offset + 24], "little")
    if machine != 0x8664:
        raise BolError(f"{label} must be a Windows x64 DLL.")
    if not characteristics & 0x2000:
        raise BolError(f"{label} is a PE executable, not a DLL.")


def _package_files(package: Path) -> dict[str, Path]:
    files = {
        "PreLoader.dll": package / "PreLoader.dll",
        "LeviLamina.dll": package / "mods" / "LeviLamina" / "LeviLamina.dll",
        "manifest.json": package / "mods" / "LeviLamina" / "manifest.json",
    }
    missing = [name for name, path in files.items() if not path.is_file()]
    if missing:
        raise BolError("LeviLamina package is missing: " + ", ".join(missing))
    return files


def validate_package(package_path, game_dir) -> dict[str, str]:
    """Validate the supported game and an unpacked LeviLamina package."""
    package = Path(package_path).expanduser().resolve()
    game = Path(game_dir).expanduser().resolve()
    if mc_version_str(game) != SUPPORTED_VERSION:
        actual = mc_version_str(game) or "unknown"
        raise BolError("LeviLamina early loading supports Minecraft "
                       f"{SUPPORTED_VERSION} only (selected: {actual}).")
    files = _package_files(package)
    _require_amd64_dll(files["PreLoader.dll"], "PreLoader.dll")
    _require_amd64_dll(files["LeviLamina.dll"], "LeviLamina.dll")
    try:
        manifest = json.loads(files["manifest.json"].read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BolError(f"LeviLamina manifest.json is invalid: {exc}") from exc
    if manifest.get("type") != "preload-native":
        raise BolError("LeviLamina manifest type must be 'preload-native'.")
    entry = str(manifest.get("entry") or manifest.get("entrypoint") or "")
    if Path(entry).name != "LeviLamina.dll" or Path(entry).is_absolute() or ".." in Path(entry).parts:
        raise BolError("LeviLamina manifest entry must name LeviLamina.dll inside its mod directory.")
    return {name: _sha256(path) for name, path in files.items()}


def _write_atomic(path: Path, payload: bytes) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=".levilamina-", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _log(message: str) -> None:
    LOGS.mkdir(mode=0o700, parents=True, exist_ok=True)
    with _LOG_FILE.open("a", encoding="utf-8") as stream:
        stream.write(message + "\n")


def stage(package_path, content_dir, game_dir) -> Path:
    """Copy validated loader files into the launch content directory.

    Existing files not recorded as ours are never overwritten.  The state file
    stores hashes, which makes cleanup reject modified files.
    """
    validate_package(package_path, game_dir)
    package = Path(package_path).expanduser().resolve()
    content = Path(content_dir).resolve()
    targets = {"PreLoader.dll": content / "PreLoader.dll",
               "PreLoaderConfig.json": content / "PreLoaderConfig.json",
               "mods/LeviLamina/LeviLamina.dll": content / "mods/LeviLamina/LeviLamina.dll",
               "mods/LeviLamina/manifest.json": content / "mods/LeviLamina/manifest.json"}
    if any(path.exists() for path in targets.values()):
        raise BolError("LeviLamina staging files already exist in the game content directory. "
                       "Remove a previous verified stage before continuing.")
    config = {"version": 1, "colorLog": True, "logLevel": 4,
              "logPath": "./logs/preloader.log", "modsPath": "./mods/"}
    source = {"PreLoader.dll": package / "PreLoader.dll",
              "mods/LeviLamina/LeviLamina.dll": package / "mods" / "LeviLamina" / "LeviLamina.dll",
              "mods/LeviLamina/manifest.json": package / "mods" / "LeviLamina" / "manifest.json"}
    written = []
    try:
        for relative, destination in targets.items():
            destination.parent.mkdir(parents=True, exist_ok=True)
            if relative == "PreLoaderConfig.json":
                _write_atomic(destination, (json.dumps(config, indent=2) + "\n").encode())
            else:
                temporary = destination.with_name("." + destination.name + ".levilamina")
                shutil.copyfile(source[relative], temporary)
                os.chmod(temporary, 0o600)
                os.replace(temporary, destination)
            written.append(relative)
        state = {"content": str(content), "files": {rel: _sha256(targets[rel]) for rel in targets}}
        _write_atomic(_STATE_FILE, (json.dumps(state, indent=2) + "\n").encode())
    except Exception:
        for relative in written:
            targets[relative].unlink(missing_ok=True)
        raise
    _log("LeviLamina staging verified")
    return targets["PreLoader.dll"]


def cleanup() -> None:
    """Remove only stage files whose paths and hashes still match our state."""
    try:
        state = json.loads(_STATE_FILE.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return
    except (OSError, json.JSONDecodeError) as exc:
        raise BolError(f"Cannot safely read LeviLamina staging state: {exc}") from exc
    content = Path(state.get("content", ""))
    for relative, expected in state.get("files", {}).items():
        target = content / relative
        try:
            if target.is_file() and _sha256(target) == expected:
                target.unlink()
        except OSError as exc:
            raise BolError(f"Could not clean staged LeviLamina file {target}: {exc}") from exc
    _STATE_FILE.unlink(missing_ok=True)
    _log("LeviLamina staging cleaned")
