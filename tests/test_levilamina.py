"""LeviLamina staging is deliberately independent of Wine and Xodus."""

import json
from pathlib import Path

import pytest

from bol import levilamina
from bol.log import BolError


def _dll(path: Path, *, amd64=True, dll=True):
    image = bytearray(0x200)
    image[:2] = b"MZ"
    image[0x3C:0x40] = (0x80).to_bytes(4, "little")
    image[0x80:0x84] = b"PE\0\0"
    image[0x84:0x86] = (0x8664 if amd64 else 0x14C).to_bytes(2, "little")
    image[0x96:0x98] = (0x2000 if dll else 0).to_bytes(2, "little")
    path.write_bytes(image)


def _package(root: Path):
    mod = root / "mods" / "LeviLamina"
    mod.mkdir(parents=True)
    _dll(root / "PreLoader.dll")
    _dll(mod / "LeviLamina.dll")
    (mod / "manifest.json").write_text(
        json.dumps({"type": "preload-native", "entry": "LeviLamina.dll"}))


def test_validate_rejects_wrong_game_version(tmp_path, monkeypatch):
    package = tmp_path / "package"
    package.mkdir()
    _package(package)
    monkeypatch.setattr(levilamina, "mc_version_str", lambda _game: "1.26.52.1")
    with pytest.raises(BolError, match="1.26.51.1"):
        levilamina.validate_package(package, tmp_path / "game")


def test_early_loader_requires_marked_engine(tmp_path):
    with pytest.raises(BolError, match="does not include"):
        levilamina.require_engine_support(tmp_path / "engine")
    marker = tmp_path / "engine/files/.bol-early-loader"
    marker.parent.mkdir(parents=True)
    marker.write_text("BOL_EARLY_DLL v1\n")
    levilamina.require_engine_support(tmp_path / "engine")


def test_stage_and_cleanup_only_own_hashed_files(tmp_path, monkeypatch):
    package = tmp_path / "package"
    package.mkdir()
    _package(package)
    content = tmp_path / "content"
    content.mkdir()
    data = tmp_path / "data"
    logs = tmp_path / "logs"
    monkeypatch.setattr(levilamina, "DATA", data)
    monkeypatch.setattr(levilamina, "LOGS", logs)
    monkeypatch.setattr(levilamina, "_STATE_FILE", data / "levilamina-staging.json")
    monkeypatch.setattr(levilamina, "_LOG_FILE", logs / "levilamina-early-load.log")
    monkeypatch.setattr(levilamina, "mc_version_str", lambda _game: "1.26.51.1")

    loader = levilamina.stage(package, content, tmp_path / "game")
    assert loader == content / "PreLoader.dll"
    assert (content / "mods/LeviLamina/LeviLamina.dll").is_file()
    assert (content / "PreLoaderConfig.json").is_file()
    levilamina.cleanup()
    assert not loader.exists()
    assert not (content / "mods/LeviLamina/LeviLamina.dll").exists()


def test_cleanup_keeps_file_changed_after_staging(tmp_path, monkeypatch):
    package = tmp_path / "package"
    package.mkdir()
    _package(package)
    content = tmp_path / "content"
    content.mkdir()
    data = tmp_path / "data"
    monkeypatch.setattr(levilamina, "DATA", data)
    monkeypatch.setattr(levilamina, "LOGS", tmp_path / "logs")
    monkeypatch.setattr(levilamina, "_STATE_FILE", data / "levilamina-staging.json")
    monkeypatch.setattr(levilamina, "_LOG_FILE", tmp_path / "logs/early.log")
    monkeypatch.setattr(levilamina, "mc_version_str", lambda _game: "1.26.51.1")
    loader = levilamina.stage(package, content, tmp_path / "game")
    loader.write_bytes(b"user-owned replacement")
    levilamina.cleanup()
    assert loader.read_bytes() == b"user-owned replacement"
