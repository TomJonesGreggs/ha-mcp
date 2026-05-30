"""HA MCP Tools - Custom component for ha-mcp server.

PHASE 2 widening (2026-05-01) — adds safety machinery on top of the existing
file-management services. New behaviours:

- ALLOWED_WRITE_FILES (from const.py) — exact-filename allowlist for raw
  ha_write_file writes to config-root files (CLAUDE.md, README.md, etc.)
- WRITE_TIER_2_FILES (from const.py) — paths that trigger pre-write text
  backup + post-write check_config validation + auto-revert on failure.
- Size-delta guard on overwrites — refuses writes where the new content is
  <50% of the old size, unless force_shrink=true is passed. Catches the
  runaway-truncation class of bug.
- dry_run parameter on both ha_write_file and ha_config_set_yaml — returns
  a preview (size delta, parse status for YAML) without writing.
- auto_revert parameter (default True) on Tier 2 raw writes and on YAML
  config edits — restores from in-memory snapshot if validation fails.
- Atomic writes everywhere (tmp file + os.replace).
- Audit log at AUDIT_LOG_PATH (JSONL, rotates at AUDIT_LOG_MAX_BYTES).

Existing callers continue to work without changes — all new parameters have
safe defaults.
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import logging
import os
import re
from datetime import datetime
from io import StringIO
from pathlib import Path
from typing import Any

import voluptuous as vol
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import (
    HomeAssistant,
    ServiceCall,
    ServiceResponse,
    SupportsResponse,
)
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers.check_config import async_check_ha_config_file
from ruamel.yaml import YAMLError

from .const import (
    ALLOWED_READ_DIRS,
    ALLOWED_READ_PATTERNS,
    ALLOWED_WRITE_DIRS,
    ALLOWED_WRITE_FILES,
    ALLOWED_WRITE_PATTERNS,
    ALLOWED_YAML_CONFIG_FILES,
    ALLOWED_YAML_KEYS,
    AUDIT_LOG_MAX_BYTES,
    AUDIT_LOG_PATH,
    DOMAIN,
    WRITE_TIER_2_FILES,
    YAML_KEY_DEFAULT_POST_ACTION,
    YAML_KEY_POST_ACTIONS,
)
from .yaml_rt import make_yaml, yaml_dumps

_LOGGER = logging.getLogger(__name__)

# Service names
SERVICE_LIST_FILES = "list_files"
SERVICE_READ_FILE = "read_file"
SERVICE_WRITE_FILE = "write_file"
SERVICE_DELETE_FILE = "delete_file"
SERVICE_EDIT_YAML_CONFIG = "edit_yaml_config"
SERVICE_APPEND_FILE = "append_file"

# Service schemas
SERVICE_EDIT_YAML_CONFIG_SCHEMA = vol.Schema(
    {
        vol.Required("file"): cv.string,
        vol.Required("action"): vol.In(["add", "replace", "remove"]),
        vol.Required("yaml_path"): cv.string,
        vol.Optional("content"): cv.string,
        vol.Optional("backup", default=True): cv.boolean,
        # Phase 2 additions:
        vol.Optional("dry_run", default=False): cv.boolean,
        vol.Optional("auto_revert", default=True): cv.boolean,
    }
)

SERVICE_LIST_FILES_SCHEMA = vol.Schema(
    {
        vol.Required("path"): cv.string,
        vol.Optional("pattern"): cv.string,
    }
)

SERVICE_READ_FILE_SCHEMA = vol.Schema(
    {
        vol.Required("path"): cv.string,
        vol.Optional("tail_lines"): vol.Coerce(int),
    }
)

SERVICE_WRITE_FILE_SCHEMA = vol.Schema(
    {
        vol.Required("path"): cv.string,
        vol.Required("content"): cv.string,
        vol.Optional("overwrite", default=False): cv.boolean,
        vol.Optional("create_dirs", default=True): cv.boolean,
        # Phase 2 additions:
        vol.Optional("dry_run", default=False): cv.boolean,
        vol.Optional("force_shrink", default=False): cv.boolean,
        vol.Optional("auto_revert", default=True): cv.boolean,
    }
)

SERVICE_DELETE_FILE_SCHEMA = vol.Schema(
    {
        vol.Required("path"): cv.string,
    }
)

SERVICE_APPEND_FILE_SCHEMA = vol.Schema(
    {
        vol.Required("path"): cv.string,
        vol.Required("content"): cv.string,
        vol.Optional("start_new", default=False): cv.boolean,
        vol.Optional("create_dirs", default=True): cv.boolean,
        vol.Optional("expected_sha256"): cv.string,
    }
)

# Files that are allowed to be read (even if not in ALLOWED_READ_DIRS)
ALLOWED_READ_FILES = [
    "configuration.yaml",
    "automations.yaml",
    "scripts.yaml",
    "scenes.yaml",
    "secrets.yaml",
    "home-assistant.log",
]

# Default tail lines for log files
DEFAULT_LOG_TAIL_LINES = 1000

# Phase 2: size-delta guard threshold. Overwrites where new size is below
# this fraction of old size are rejected unless force_shrink=true.
SIZE_DELTA_GUARD_THRESHOLD = 0.5


def _path_within_pattern_coverage(rel_path: str, pattern: str) -> bool:
    """Check if rel_path is covered by an fnmatch pattern.

    Returns True if either:
    - rel_path matches the pattern directly (file case), or
    - rel_path is the literal directory prefix of the pattern, or sits
      inside that prefix (i.e. listing a directory containing pattern matches).
    """
    if fnmatch.fnmatch(rel_path, pattern):
        return True
    # Treat everything before the first wildcard as a literal directory prefix
    literal_prefix = pattern.split("*", 1)[0].rstrip("/")
    if not literal_prefix:
        return False
    return rel_path == literal_prefix or rel_path.startswith(literal_prefix + "/")


def _is_path_allowed_for_dir(
    config_dir: Path,
    rel_path: str,
    allowed_dirs: list[str],
    allowed_patterns: list[str] | None = None,
) -> bool:
    """Check if a path is within allowed directories or matches an allowed pattern."""
    # Normalize the path
    normalized = os.path.normpath(rel_path)

    # Check for path traversal attempts
    if normalized.startswith("..") or normalized.startswith("/"):
        return False

    # Resolve full path and verify it's still under config_dir
    full_path = config_dir / normalized
    try:
        resolved = full_path.resolve()
        config_resolved = config_dir.resolve()
        if not str(resolved).startswith(str(config_resolved)):
            return False
    except (OSError, ValueError):
        return False

    # Check if path starts with an allowed top-level directory
    parts = normalized.split(os.sep)
    if parts and parts[0] in allowed_dirs:
        return True

    # Check if path is covered by any allowed pattern (file match or parent dir)
    if allowed_patterns:
        for pattern in allowed_patterns:
            if _path_within_pattern_coverage(normalized, pattern):
                return True

    return False


def _is_path_allowed_for_write(config_dir: Path, rel_path: str) -> bool:
    """Phase 2: combined write allowlist check.

    Allows:
    - Files in ALLOWED_WRITE_DIRS (www/, themes/, custom_templates/)
    - Files matching ALLOWED_WRITE_PATTERNS (scripts/*, packages/*, etc.)
    - Individual files in ALLOWED_WRITE_FILES (CLAUDE.md, README.md, etc.)

    Path traversal is blocked. Files must resolve under config_dir even if
    they reach via a symlink that points elsewhere.
    """
    # Existing dir + pattern coverage
    if _is_path_allowed_for_dir(
        config_dir, rel_path, ALLOWED_WRITE_DIRS, ALLOWED_WRITE_PATTERNS
    ):
        return True

    # Phase 2: explicit file allowlist
    normalized = os.path.normpath(rel_path)
    if normalized.startswith("..") or normalized.startswith("/"):
        return False

    full_path = config_dir / normalized
    try:
        resolved = full_path.resolve()
        config_resolved = config_dir.resolve()
        if not str(resolved).startswith(str(config_resolved)):
            return False
    except (OSError, ValueError):
        return False

    return normalized in ALLOWED_WRITE_FILES


def _is_tier_2(rel_path: str) -> bool:
    """Phase 2: check if a path requires Tier 2 safety machinery."""
    normalized = os.path.normpath(rel_path)
    return normalized in WRITE_TIER_2_FILES


def _is_path_allowed_for_read(config_dir: Path, rel_path: str) -> bool:
    """Check if a path is allowed for reading.

    Allowed:
    - Files directly in config dir: configuration.yaml, automations.yaml, etc.
    - Files in allowed directories: www/, themes/, custom_templates/
    - Files matching patterns: packages/*.yaml, custom_components/**/*.py
    - Files matching local-fork patterns in ALLOWED_READ_PATTERNS
    - Audit log at AUDIT_LOG_PATH (Phase 2)
    """
    normalized = os.path.normpath(rel_path)

    # Check for path traversal attempts
    if normalized.startswith("..") or normalized.startswith("/"):
        return False

    # Resolve full path and verify it's still under config_dir
    full_path = config_dir / normalized
    try:
        resolved = full_path.resolve()
        config_resolved = config_dir.resolve()
        if not str(resolved).startswith(str(config_resolved)):
            return False
    except (OSError, ValueError):
        return False

    # Check if it's one of the explicitly allowed files in config root
    if normalized in ALLOWED_READ_FILES:
        return True

    # Phase 2: audit log readable so operators can review write history
    if normalized == os.path.normpath(AUDIT_LOG_PATH):
        return True
    # Also allow rotated audit log
    if normalized == os.path.normpath(AUDIT_LOG_PATH + ".1"):
        return True

    # Check if path starts with an allowed directory
    parts = normalized.split(os.sep)
    if parts and parts[0] in ALLOWED_READ_DIRS:
        return True

    # Check for packages/*.yaml pattern
    if fnmatch.fnmatch(normalized, "packages/*.yaml"):
        return True
    if fnmatch.fnmatch(normalized, "packages/**/*.yaml"):
        return True

    # Check for any local-fork allowed read pattern
    for pattern in ALLOWED_READ_PATTERNS:
        if fnmatch.fnmatch(normalized, pattern):
            return True

    # Check for custom_components/**/*.py pattern
    return fnmatch.fnmatch(normalized, "custom_components/**/*.py")


def _mask_secrets_content(content: str) -> str:
    """Mask secret values in secrets.yaml content."""
    lines = content.split("\n")
    masked_lines = []

    for line in lines:
        stripped = line.strip()
        if stripped.startswith("#") or not stripped:
            masked_lines.append(line)
            continue

        match = re.match(r"^(\s*)([^:\s]+)(\s*:\s*)(.+)$", line)
        if match:
            indent, key, separator, _value = match.groups()
            masked_lines.append(f"{indent}{key}{separator}[MASKED]")
        else:
            masked_lines.append(line)

    return "\n".join(masked_lines)


async def _audit_write(
    hass: HomeAssistant,
    config_dir: Path,
    *,
    service: str,
    path: str,
    old_size: int | None,
    new_size: int | None,
    success: bool,
    is_tier_2: bool,
    dry_run: bool,
    error: str | None = None,
    extra: dict[str, Any] | None = None,
) -> None:
    """Phase 2: append a JSONL audit entry. Best-effort, never raises.

    Audit log lives at config_dir / AUDIT_LOG_PATH (relative path defined
    in const.py). Rotates to AUDIT_LOG_PATH + '.1' when crossing
    AUDIT_LOG_MAX_BYTES (single-generation rotation).
    """
    audit_path = config_dir / AUDIT_LOG_PATH

    def _write_entry() -> None:
        entry: dict[str, Any] = {
            "ts": datetime.now().isoformat(),
            "service": service,
            "path": path,
            "old_size": old_size,
            "new_size": new_size,
            "delta": (
                (new_size - old_size)
                if (new_size is not None and old_size is not None)
                else None
            ),
            "success": success,
            "tier_2": is_tier_2,
            "dry_run": dry_run,
            "error": error,
        }
        if extra:
            entry.update(extra)
        try:
            audit_path.parent.mkdir(parents=True, exist_ok=True)
            # Rotate at threshold
            if (
                audit_path.exists()
                and audit_path.stat().st_size > AUDIT_LOG_MAX_BYTES
            ):
                rotated = audit_path.with_suffix(audit_path.suffix + ".1")
                if rotated.exists():
                    rotated.unlink()
                audit_path.rename(rotated)
            with audit_path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry, default=str) + "\n")
        except Exception as exc:  # noqa: BLE001 — audit log is best-effort
            _LOGGER.debug("Audit log write failed (non-fatal): %s", exc)

    try:
        await hass.async_add_executor_job(_write_entry)
    except Exception as exc:  # noqa: BLE001
        _LOGGER.debug("Audit log scheduling failed (non-fatal): %s", exc)


async def _atomic_write_text(
    hass: HomeAssistant, target_file: Path, content: str
) -> None:
    """Phase 2: atomic write via tmp file + os.replace.

    Avoids the partial-write window that direct write_text has if the process
    is killed mid-write. Tmp file lives next to the target so the rename is
    cross-rename-safe (same filesystem).
    """
    tmp_file = target_file.parent / (target_file.name + ".tmp")

    def _do_write() -> None:
        tmp_file.write_text(content, encoding="utf-8")
        os.replace(str(tmp_file), str(target_file))

    await hass.async_add_executor_job(_do_write)


def _integrity_mismatch(content: str, expected_sha256: str | None) -> str | None:
    """Return the actual sha256 hex if it does NOT match expected, else None.

    The hash is computed by the caller over the *full intended* content. Because
    it is a tiny 64-char field it survives the per-call argument-size limit even
    when `content` itself is clipped in transit — so a truncated payload yields a
    hash mismatch (a loud, catchable error) instead of a silently short file.
    """
    if not expected_sha256:
        return None
    actual = hashlib.sha256(content.encode("utf-8")).hexdigest()
    return None if actual == expected_sha256.strip().lower() else actual


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up HA MCP Tools from a config entry."""
    config_dir = Path(hass.config.config_dir)

    async def handle_list_files(call: ServiceCall) -> ServiceResponse:
        """Handle the list_files service call."""
        rel_path = call.data["path"]
        pattern = call.data.get("pattern")

        if not _is_path_allowed_for_dir(
            config_dir, rel_path, ALLOWED_READ_DIRS, ALLOWED_READ_PATTERNS
        ):
            _LOGGER.warning("Attempted to list files in disallowed path: %s", rel_path)
            return {
                "success": False,
                "error": (
                    f"Path not allowed. Must be in: {', '.join(ALLOWED_READ_DIRS)}"
                    f" or match: {', '.join(ALLOWED_READ_PATTERNS)}"
                ),
                "files": [],
            }

        target_dir = config_dir / rel_path

        if not target_dir.exists():
            return {
                "success": False,
                "error": f"Directory does not exist: {rel_path}",
                "files": [],
            }

        if not target_dir.is_dir():
            return {
                "success": False,
                "error": f"Path is not a directory: {rel_path}",
                "files": [],
            }

        try:
            files = []
            for item in target_dir.iterdir():
                if pattern and not fnmatch.fnmatch(item.name, pattern):
                    continue

                stat = item.stat()
                files.append(
                    {
                        "name": item.name,
                        "path": str(item.relative_to(config_dir)),
                        "is_dir": item.is_dir(),
                        "size": stat.st_size if item.is_file() else 0,
                        "modified": stat.st_mtime,
                    }
                )

            files.sort(key=lambda x: (not x["is_dir"], x["name"].lower()))

            return {
                "success": True,
                "path": rel_path,
                "pattern": pattern,
                "files": files,
                "count": len(files),
            }

        except PermissionError:
            _LOGGER.error("Permission denied accessing: %s", rel_path)
            return {
                "success": False,
                "error": f"Permission denied: {rel_path}",
                "files": [],
            }
        except OSError as err:
            _LOGGER.error("Error listing files in %s: %s", rel_path, err)
            return {
                "success": False,
                "error": str(err),
                "files": [],
            }

    async def handle_read_file(call: ServiceCall) -> ServiceResponse:
        """Handle the read_file service call."""
        rel_path = call.data["path"]
        tail_lines = call.data.get("tail_lines")

        if not _is_path_allowed_for_read(config_dir, rel_path):
            _LOGGER.warning("Attempted to read disallowed path: %s", rel_path)
            allowed_patterns = (
                ALLOWED_READ_FILES
                + [f"{d}/**" for d in ALLOWED_READ_DIRS]
                + ["packages/*.yaml", "custom_components/**/*.py"]
            )
            return {
                "success": False,
                "error": f"Path not allowed. Allowed patterns: {', '.join(allowed_patterns)}",
            }

        target_file = config_dir / rel_path

        if not target_file.exists():
            return {
                "success": False,
                "error": f"File does not exist: {rel_path}",
            }

        if not target_file.is_file():
            return {
                "success": False,
                "error": f"Path is not a file: {rel_path}",
            }

        try:
            stat = target_file.stat()
            modified_dt = datetime.fromtimestamp(stat.st_mtime)

            content = await hass.async_add_executor_job(target_file.read_text)

            normalized = os.path.normpath(rel_path)  # noqa: ASYNC240

            if normalized == "secrets.yaml":
                content = _mask_secrets_content(content)

            if normalized == "home-assistant.log":
                lines = content.split("\n")
                limit = tail_lines if tail_lines else DEFAULT_LOG_TAIL_LINES
                if len(lines) > limit:
                    content = "\n".join(lines[-limit:])
                    truncated = True
                else:
                    truncated = False

                return {
                    "success": True,
                    "path": rel_path,
                    "content": content,
                    "size": stat.st_size,
                    "modified": modified_dt.isoformat(),
                    "lines_returned": min(len(lines), limit),
                    "total_lines": len(lines),
                    "truncated": truncated,
                }

            if tail_lines:
                lines = content.split("\n")
                if len(lines) > tail_lines:
                    content = "\n".join(lines[-tail_lines:])

            return {
                "success": True,
                "path": rel_path,
                "content": content,
                "size": stat.st_size,
                "modified": modified_dt.isoformat(),
            }

        except PermissionError:
            _LOGGER.error("Permission denied reading: %s", rel_path)
            return {
                "success": False,
                "error": f"Permission denied: {rel_path}",
            }
        except UnicodeDecodeError:
            _LOGGER.error("Cannot read binary file: %s", rel_path)
            return {
                "success": False,
                "error": f"Cannot read binary file: {rel_path}. Only text files are supported.",
            }
        except OSError as err:
            _LOGGER.error("Error reading file %s: %s", rel_path, err)
            return {
                "success": False,
                "error": str(err),
            }

    async def handle_write_file(call: ServiceCall) -> ServiceResponse:
        """Handle the write_file service call.

        Phase 2 enhancements:
        - ALLOWED_WRITE_FILES check (e.g. CLAUDE.md, .gitignore)
        - Tier 2 safety machinery for paths in WRITE_TIER_2_FILES
        - Size-delta guard (>50% shrink rejected unless force_shrink=true)
        - dry_run mode returns preview without writing
        - Atomic write (tmp file + os.replace)
        - YAML files: post-write parse validation + auto-revert on parse error
        - Tier 2 paths: post-write check_config + auto-revert on errors
        - JSONL audit log entry per write
        """
        rel_path = call.data["path"]
        content = call.data["content"]
        overwrite = call.data.get("overwrite", False)
        create_dirs = call.data.get("create_dirs", True)
        # Phase 2 parameters:
        dry_run = call.data.get("dry_run", False)
        force_shrink = call.data.get("force_shrink", False)
        auto_revert = call.data.get("auto_revert", True)

        normalized = os.path.normpath(rel_path)  # noqa: ASYNC240
        is_tier_2 = _is_tier_2(normalized)
        is_yaml = normalized.endswith((".yaml", ".yml"))

        # Security check
        if not _is_path_allowed_for_write(config_dir, rel_path):
            _LOGGER.warning("Attempted to write to disallowed path: %s", rel_path)
            error_msg = (
                f"Write not allowed. Must be in: {', '.join(ALLOWED_WRITE_DIRS)}"
                f", match: {', '.join(ALLOWED_WRITE_PATTERNS)}"
                f", or be one of: {', '.join(ALLOWED_WRITE_FILES)}"
            )
            await _audit_write(
                hass, config_dir,
                service="write_file", path=rel_path,
                old_size=None, new_size=None,
                success=False, is_tier_2=is_tier_2, dry_run=dry_run,
                error="path_not_allowed",
            )
            return {"success": False, "error": error_msg}

        target_file = config_dir / rel_path

        # Capture existing-file state
        file_exists = target_file.exists()
        old_size = target_file.stat().st_size if file_exists else 0
        new_size = len(content.encode("utf-8"))

        # Capture old content for in-memory revert (Tier 2 + YAML files only)
        old_content: str | None = None
        if file_exists and (is_tier_2 or is_yaml):
            try:
                old_content = await hass.async_add_executor_job(target_file.read_text)
            except Exception as exc:  # noqa: BLE001
                _LOGGER.warning(
                    "Could not read old content of %s for revert snapshot: %s",
                    rel_path, exc,
                )
                # Carry on without revert capability rather than blocking the write.

        # Overwrite gate
        if file_exists and not overwrite:
            await _audit_write(
                hass, config_dir,
                service="write_file", path=rel_path,
                old_size=old_size, new_size=new_size,
                success=False, is_tier_2=is_tier_2, dry_run=dry_run,
                error="overwrite_required",
            )
            return {
                "success": False,
                "error": f"File already exists: {rel_path}. Set overwrite=true to replace.",
            }

        # Phase 2: size-delta guard
        if (
            file_exists
            and old_size > 0
            and new_size < old_size * SIZE_DELTA_GUARD_THRESHOLD
            and not force_shrink
        ):
            await _audit_write(
                hass, config_dir,
                service="write_file", path=rel_path,
                old_size=old_size, new_size=new_size,
                success=False, is_tier_2=is_tier_2, dry_run=dry_run,
                error="size_delta_guard",
            )
            return {
                "success": False,
                "error": (
                    f"Size-delta guard: new size {new_size} is less than "
                    f"{int(SIZE_DELTA_GUARD_THRESHOLD * 100)}% of old size {old_size}. "
                    "Pass force_shrink=true to override (e.g. for legitimate "
                    "large deletions). This guard catches the runaway-truncation "
                    "class of bug."
                ),
                "old_size": old_size,
                "new_size": new_size,
                "size_delta_pct": ((new_size - old_size) / old_size) * 100,
            }

        # Phase 2: dry_run preview
        if dry_run:
            preview: dict[str, Any] = {
                "success": True,
                "dry_run": True,
                "would_write": rel_path,
                "would_create": not file_exists,
                "would_overwrite": file_exists,
                "old_size": old_size,
                "new_size": new_size,
                "size_delta": new_size - old_size,
                "size_delta_pct": (
                    ((new_size - old_size) / old_size) * 100
                    if old_size > 0
                    else None
                ),
                "is_tier_2": is_tier_2,
            }
            if is_yaml:
                ry = make_yaml()
                try:
                    ry.load(StringIO(content))
                    preview["yaml_parse"] = "ok"
                except YAMLError as err:
                    preview["yaml_parse"] = "error"
                    preview["yaml_parse_error"] = str(err)
            await _audit_write(
                hass, config_dir,
                service="write_file", path=rel_path,
                old_size=old_size, new_size=new_size,
                success=True, is_tier_2=is_tier_2, dry_run=True,
            )
            return preview

        try:
            if create_dirs:
                await hass.async_add_executor_job(
                    lambda: target_file.parent.mkdir(parents=True, exist_ok=True)
                )

            if not target_file.parent.exists():
                await _audit_write(
                    hass, config_dir,
                    service="write_file", path=rel_path,
                    old_size=old_size, new_size=new_size,
                    success=False, is_tier_2=is_tier_2, dry_run=False,
                    error="parent_missing",
                )
                return {
                    "success": False,
                    "error": (
                        f"Parent directory does not exist: "
                        f"{target_file.parent.relative_to(config_dir)}"
                    ),
                }

            # Phase 2: text backup for Tier 2 paths (matches edit_yaml_config pattern)
            backup_path_str: str | None = None
            if is_tier_2 and old_content is not None:
                backup_dir = config_dir / "www" / "yaml_backups"
                await hass.async_add_executor_job(
                    lambda: backup_dir.mkdir(parents=True, exist_ok=True)
                )
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                safe_name = normalized.replace(os.sep, "_")
                backup_file = backup_dir / f"{safe_name}.{timestamp}.bak"
                await hass.async_add_executor_job(backup_file.write_text, old_content)
                backup_path_str = str(backup_file.relative_to(config_dir))
                _LOGGER.info("Pre-write text backup created: %s", backup_path_str)

            is_new = not file_exists

            # Phase 2: atomic write (was direct write_text)
            await _atomic_write_text(hass, target_file, content)

            stat = target_file.stat()
            modified_dt = datetime.fromtimestamp(stat.st_mtime)

            result: dict[str, Any] = {
                "success": True,
                "path": rel_path,
                "size": stat.st_size,
                "modified": modified_dt.isoformat(),
                "created": is_new,
                "is_tier_2": is_tier_2,
                "message": f"File {'created' if is_new else 'updated'} successfully",
            }
            if backup_path_str:
                result["backup_path"] = backup_path_str

            # Phase 2: YAML post-write parse validation
            if is_yaml:
                ry = make_yaml()
                try:
                    ry.load(StringIO(content))
                    result["yaml_parse"] = "ok"
                except YAMLError as err:
                    result["yaml_parse"] = "error"
                    result["yaml_parse_error"] = str(err)
                    if auto_revert and old_content is not None:
                        await _atomic_write_text(hass, target_file, old_content)
                        result["auto_reverted"] = True
                        result["success"] = False
                        result["error"] = (
                            f"YAML parse failed after write; auto-reverted from "
                            f"in-memory snapshot. Pre-revert error: {err}"
                        )
                        _LOGGER.warning(
                            "Auto-reverted %s: YAML parse error: %s", rel_path, err,
                        )

            # Phase 2: Tier 2 post-write check_config
            if is_tier_2 and result.get("success"):
                try:
                    check_result = await hass.services.async_call(
                        "homeassistant", "check_config", {},
                        blocking=True, return_response=True,
                    )
                    if isinstance(check_result, dict):
                        errors = check_result.get("errors")
                        if errors:
                            result["config_check"] = "errors"
                            result["config_check_errors"] = errors
                            if auto_revert and old_content is not None:
                                await _atomic_write_text(
                                    hass, target_file, old_content,
                                )
                                result["auto_reverted"] = True
                                result["success"] = False
                                result["error"] = (
                                    f"check_config failed after write; "
                                    f"auto-reverted from in-memory snapshot. "
                                    f"Errors: {errors}"
                                )
                                _LOGGER.warning(
                                    "Auto-reverted %s: check_config errors: %s",
                                    rel_path, errors,
                                )
                        else:
                            result["config_check"] = "ok"
                except Exception as check_err:  # noqa: BLE001
                    result["config_check"] = "unavailable"
                    result["config_check_error"] = str(check_err)
                    _LOGGER.debug("Config check unavailable: %s", check_err)

            _LOGGER.info(
                "Wrote file: %s (%d bytes, tier_2=%s, success=%s)",
                rel_path, stat.st_size, is_tier_2, result["success"],
            )

            await _audit_write(
                hass, config_dir,
                service="write_file", path=rel_path,
                old_size=old_size, new_size=new_size,
                success=result["success"], is_tier_2=is_tier_2, dry_run=False,
                error=result.get("error"),
                extra={
                    "auto_reverted": result.get("auto_reverted", False),
                    "yaml_parse": result.get("yaml_parse"),
                    "config_check": result.get("config_check"),
                },
            )

            return result

        except PermissionError:
            _LOGGER.error("Permission denied writing: %s", rel_path)
            await _audit_write(
                hass, config_dir,
                service="write_file", path=rel_path,
                old_size=old_size, new_size=new_size,
                success=False, is_tier_2=is_tier_2, dry_run=False,
                error="permission_denied",
            )
            return {
                "success": False,
                "error": f"Permission denied: {rel_path}",
            }
        except OSError as err:
            _LOGGER.error("Error writing file %s: %s", rel_path, err)
            await _audit_write(
                hass, config_dir,
                service="write_file", path=rel_path,
                old_size=old_size, new_size=new_size,
                success=False, is_tier_2=is_tier_2, dry_run=False,
                error=str(err),
            )
            return {
                "success": False,
                "error": str(err),
            }

    async def handle_append_file(call: ServiceCall) -> ServiceResponse:
        """Append a text chunk to a file, for building documents larger than a
        single MCP call can carry (~55KB content ceiling per call).

        First chunk: start_new=True (creates/overwrites). Later chunks:
        start_new=False (appends). Atomic per call (read existing + concat +
        os.replace), so a killed process never leaves a half-written file.
        Tier 2 config files are rejected — they're small and need whole-file
        validation, so use write_file for those.
        """
        rel_path = call.data["path"]
        content = call.data["content"]
        start_new = call.data.get("start_new", False)
        create_dirs = call.data.get("create_dirs", True)
        expected_sha256 = call.data.get("expected_sha256")

        normalized = os.path.normpath(rel_path)  # noqa: ASYNC240
        chunk_bytes = len(content.encode("utf-8"))

        # Config files must be written whole, not appended.
        if _is_tier_2(normalized):
            return {
                "success": False,
                "error": (
                    "append_file is not allowed for Tier 2 config files "
                    f"({', '.join(sorted(WRITE_TIER_2_FILES))}). Use write_file."
                ),
            }

        if not _is_path_allowed_for_write(config_dir, rel_path):
            _LOGGER.warning("Attempted to append to disallowed path: %s", rel_path)
            await _audit_write(
                hass, config_dir,
                service="append_file", path=rel_path,
                old_size=None, new_size=None,
                success=False, is_tier_2=False, dry_run=False,
                error="path_not_allowed",
            )
            return {
                "success": False,
                "error": (
                    f"Write not allowed. Must be in: {', '.join(ALLOWED_WRITE_DIRS)}"
                    f", match: {', '.join(ALLOWED_WRITE_PATTERNS)}"
                    f", or be one of: {', '.join(ALLOWED_WRITE_FILES)}"
                ),
            }

        # Content-integrity guard: rejects a chunk that arrived truncated/altered.
        actual_sha = _integrity_mismatch(content, expected_sha256)
        if actual_sha is not None:
            await _audit_write(
                hass, config_dir,
                service="append_file", path=rel_path,
                old_size=None, new_size=chunk_bytes,
                success=False, is_tier_2=False, dry_run=False,
                error="content_integrity_mismatch",
            )
            return {
                "success": False,
                "error": (
                    "Chunk integrity check failed: received content does not match "
                    "expected_sha256 (likely truncated in transit). Nothing appended."
                ),
                "expected_sha256": expected_sha256,
                "actual_sha256": actual_sha,
                "received_bytes": chunk_bytes,
            }

        target_file = config_dir / normalized
        file_exists = target_file.exists()
        old_size = target_file.stat().st_size if file_exists else 0

        try:
            if create_dirs:
                await hass.async_add_executor_job(
                    lambda: target_file.parent.mkdir(parents=True, exist_ok=True)
                )
            if not target_file.parent.exists():
                return {
                    "success": False,
                    "error": (
                        f"Parent directory does not exist: "
                        f"{target_file.parent.relative_to(config_dir)}"
                    ),
                }

            if start_new or not file_exists:
                existing = ""
            else:
                existing = await hass.async_add_executor_job(target_file.read_text)
            await _atomic_write_text(hass, target_file, existing + content)

            stat = target_file.stat()
            modified_dt = datetime.fromtimestamp(stat.st_mtime)
            mode = "create" if (start_new or not file_exists) else "append"

            await _audit_write(
                hass, config_dir,
                service="append_file", path=rel_path,
                old_size=old_size, new_size=stat.st_size,
                success=True, is_tier_2=False, dry_run=False,
                extra={"mode": mode, "chunk_bytes": chunk_bytes},
            )
            _LOGGER.info(
                "Appended to %s (chunk %d B, total %d B, mode=%s)",
                rel_path, chunk_bytes, stat.st_size, mode,
            )
            return {
                "success": True,
                "path": rel_path,
                "mode": mode,
                "appended_bytes": chunk_bytes,
                "size": stat.st_size,
                "modified": modified_dt.isoformat(),
            }

        except PermissionError:
            return {"success": False, "error": f"Permission denied: {rel_path}"}
        except UnicodeDecodeError:
            return {
                "success": False,
                "error": f"Existing file is not valid UTF-8 text: {rel_path}.",
            }
        except OSError as err:
            _LOGGER.error("Error appending to %s: %s", rel_path, err)
            return {"success": False, "error": str(err)}

    async def handle_delete_file(call: ServiceCall) -> ServiceResponse:
        """Handle the delete_file service call."""
        rel_path = call.data["path"]

        if not _is_path_allowed_for_write(config_dir, rel_path):
            _LOGGER.warning("Attempted to delete from disallowed path: %s", rel_path)
            return {
                "success": False,
                "error": (
                    f"Delete not allowed. Must be in: {', '.join(ALLOWED_WRITE_DIRS)}"
                    f", match: {', '.join(ALLOWED_WRITE_PATTERNS)}"
                    f", or be one of: {', '.join(ALLOWED_WRITE_FILES)}"
                ),
            }

        target_file = config_dir / rel_path

        if not target_file.exists():
            return {
                "success": False,
                "error": f"File does not exist: {rel_path}",
            }

        if not target_file.is_file():
            return {
                "success": False,
                "error": f"Path is not a file (cannot delete directories): {rel_path}",
            }

        try:
            stat = target_file.stat()
            await hass.async_add_executor_job(target_file.unlink)

            _LOGGER.info("Deleted file: %s (%d bytes)", rel_path, stat.st_size)

            await _audit_write(
                hass, config_dir,
                service="delete_file", path=rel_path,
                old_size=stat.st_size, new_size=0,
                success=True, is_tier_2=_is_tier_2(rel_path), dry_run=False,
            )

            return {
                "success": True,
                "path": rel_path,
                "deleted_size": stat.st_size,
                "message": f"File deleted successfully: {rel_path}",
            }

        except PermissionError:
            _LOGGER.error("Permission denied deleting: %s", rel_path)
            return {
                "success": False,
                "error": f"Permission denied: {rel_path}",
            }
        except OSError as err:
            _LOGGER.error("Error deleting file %s: %s", rel_path, err)
            return {
                "success": False,
                "error": str(err),
            }

    async def handle_edit_yaml_config(call: ServiceCall) -> ServiceResponse:
        """Handle the edit_yaml_config service call.

        Phase 2 enhancements:
        - dry_run mode: parse, apply transform, validate output, return preview
          including before/after top-level keys without writing.
        - auto_revert (default True): on check_config errors, restore the
          original content from the in-memory raw_content snapshot via
          atomic write. No HA restart, no backup-restore race conditions.
        - JSONL audit log entry per call.
        """
        ry = make_yaml()
        rel_path = call.data["file"]
        action = call.data["action"]
        yaml_path = call.data["yaml_path"]
        content = call.data.get("content")
        do_backup = call.data.get("backup", True)
        # Phase 2 parameters:
        dry_run = call.data.get("dry_run", False)
        auto_revert = call.data.get("auto_revert", True)

        normalized = os.path.normpath(rel_path)  # noqa: ASYNC240
        is_tier_2 = _is_tier_2(normalized)

        if normalized.startswith("..") or normalized.startswith("/"):
            return {
                "success": False,
                "error": "Path traversal is not allowed.",
            }

        is_config_yaml = normalized in ALLOWED_YAML_CONFIG_FILES
        is_package = fnmatch.fnmatch(normalized, "packages/*.yaml") or fnmatch.fnmatch(
            normalized, "packages/**/*.yaml"
        )
        if not is_config_yaml and not is_package:
            return {
                "success": False,
                "error": (
                    f"File '{rel_path}' is not allowed. "
                    f"Only {', '.join(ALLOWED_YAML_CONFIG_FILES)} and "
                    f"packages/*.yaml are supported."
                ),
            }

        if yaml_path not in ALLOWED_YAML_KEYS:
            return {
                "success": False,
                "error": (
                    f"Key '{yaml_path}' is not in the allowed list. "
                    f"Allowed keys: {', '.join(sorted(ALLOWED_YAML_KEYS))}"
                ),
            }

        parsed_content: Any = None
        if action in ("add", "replace"):
            if not content:
                return {
                    "success": False,
                    "error": f"'content' is required for action '{action}'.",
                }
            try:
                parsed_content = ry.load(StringIO(content))
            except YAMLError as err:
                return {
                    "success": False,
                    "error": f"Invalid YAML content: {err}",
                }
            if parsed_content is None:
                return {
                    "success": False,
                    "error": "Content parsed as null/empty. Provide non-empty YAML.",
                }

        target_file = config_dir / normalized
        backup_path_str: str | None = None
        raw_content = ""

        try:
            # Read existing content
            if target_file.exists():
                raw_content = await hass.async_add_executor_job(target_file.read_text)
                try:
                    data = ry.load(StringIO(raw_content)) or {}
                except YAMLError as err:
                    return {
                        "success": False,
                        "error": f"Cannot parse existing file '{rel_path}': {err}",
                    }
                if not isinstance(data, dict):
                    return {
                        "success": False,
                        "error": f"File '{rel_path}' root is not a YAML mapping.",
                    }
            else:
                if action == "remove":
                    return {
                        "success": False,
                        "error": f"File does not exist: {rel_path}",
                    }
                data = {}
                raw_content = ""

            # Capture pre-edit top-level keys for dry_run reporting
            keys_before = sorted(data.keys()) if data else []

            # Apply the action (in-memory)
            if action == "add":
                if yaml_path in data:
                    existing = data[yaml_path]
                    if isinstance(existing, list) and isinstance(parsed_content, list):
                        data[yaml_path] = existing + parsed_content
                    elif isinstance(existing, dict) and isinstance(
                        parsed_content, dict
                    ):
                        existing.update(parsed_content)
                    else:
                        return {
                            "success": False,
                            "error": (
                                f"Type mismatch for key '{yaml_path}': "
                                f"existing is {type(existing).__name__}, "
                                f"new content is {type(parsed_content).__name__}. "
                                "Use action='replace' to overwrite."
                            ),
                        }
                else:
                    data[yaml_path] = parsed_content
            elif action == "replace":
                data[yaml_path] = parsed_content
            elif action == "remove":
                if yaml_path not in data:
                    return {
                        "success": False,
                        "error": f"Key '{yaml_path}' not found in '{rel_path}'.",
                    }
                del data[yaml_path]

            keys_after = sorted(data.keys()) if data else []

            # Serialize back to YAML
            try:
                new_content = yaml_dumps(ry, data)
            except YAMLError as err:
                return {
                    "success": False,
                    "error": f"Failed to serialize YAML: {err}",
                }

            # Validate the result parses cleanly
            try:
                ry.load(StringIO(new_content))
            except YAMLError as err:
                return {
                    "success": False,
                    "error": f"Generated YAML failed validation: {err}",
                }

            # Phase 2: dry_run preview
            if dry_run:
                preview: dict[str, Any] = {
                    "success": True,
                    "dry_run": True,
                    "file": rel_path,
                    "action": action,
                    "yaml_path": yaml_path,
                    "old_size": len(raw_content.encode("utf-8")),
                    "new_size": len(new_content.encode("utf-8")),
                    "keys_before": keys_before,
                    "keys_after": keys_after,
                    "keys_added": sorted(set(keys_after) - set(keys_before)),
                    "keys_removed": sorted(set(keys_before) - set(keys_after)),
                    "is_tier_2": is_tier_2,
                }
                preview.update(
                    YAML_KEY_POST_ACTIONS.get(yaml_path, YAML_KEY_DEFAULT_POST_ACTION)
                )
                await _audit_write(
                    hass, config_dir,
                    service="edit_yaml_config", path=rel_path,
                    old_size=preview["old_size"], new_size=preview["new_size"],
                    success=True, is_tier_2=is_tier_2, dry_run=True,
                    extra={"action": action, "yaml_path": yaml_path},
                )
                return preview

            # Pre-write text backup
            if do_backup and raw_content:
                backup_dir = config_dir / "www" / "yaml_backups"
                await hass.async_add_executor_job(
                    lambda: backup_dir.mkdir(parents=True, exist_ok=True)
                )
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                safe_name = normalized.replace(os.sep, "_")
                backup_file = backup_dir / f"{safe_name}.{timestamp}.bak"
                await hass.async_add_executor_job(
                    backup_file.write_text, raw_content
                )
                backup_path_str = str(backup_file.relative_to(config_dir))
                _LOGGER.info("Backup created: %s", backup_path_str)

            # Create parent dirs for new package files
            if not target_file.parent.exists():
                await hass.async_add_executor_job(
                    lambda: target_file.parent.mkdir(parents=True, exist_ok=True)
                )

            # Atomic write
            await _atomic_write_text(hass, target_file, new_content)

            stat = target_file.stat()
            modified_dt = datetime.fromtimestamp(stat.st_mtime)

            _LOGGER.info(
                "YAML config edited: %s (action=%s, key=%s)",
                rel_path, action, yaml_path,
            )

            result: dict[str, Any] = {
                "success": True,
                "file": rel_path,
                "action": action,
                "yaml_path": yaml_path,
                "size": stat.st_size,
                "modified": modified_dt.isoformat(),
                "is_tier_2": is_tier_2,
            }
            if backup_path_str:
                result["backup_path"] = backup_path_str

            post_info = YAML_KEY_POST_ACTIONS.get(
                yaml_path, YAML_KEY_DEFAULT_POST_ACTION
            )
            result.update(post_info)

            # Run HA config check
            try:
                check_result = await hass.services.async_call(
                    "homeassistant", "check_config", {},
                    blocking=True, return_response=True,
                )
                if isinstance(check_result, dict):
                    errors = check_result.get("errors")
                    if errors:
                        result["config_check"] = "errors"
                        result["config_check_errors"] = errors
                        # Phase 2: auto-revert from raw_content snapshot
                        if auto_revert and raw_content:
                            await _atomic_write_text(
                                hass, target_file, raw_content,
                            )
                            result["auto_reverted"] = True
                            result["success"] = False
                            result["error"] = (
                                f"check_config failed after edit; auto-reverted "
                                f"from in-memory snapshot. Errors: {errors}"
                            )
                            _LOGGER.warning(
                                "Auto-reverted %s: check_config errors: %s",
                                rel_path, errors,
                            )
                        else:
                            _LOGGER.warning(
                                "Config check found errors after editing %s "
                                "(auto_revert=%s): %s",
                                rel_path, auto_revert, errors,
                            )
                    else:
                        result["config_check"] = "ok"
            except Exception as check_err:  # noqa: BLE001
                result["config_check"] = "unavailable"
                result["config_check_error"] = str(check_err)
                _LOGGER.debug("Config check unavailable: %s", check_err)

            await _audit_write(
                hass, config_dir,
                service="edit_yaml_config", path=rel_path,
                old_size=len(raw_content.encode("utf-8")),
                new_size=stat.st_size,
                success=result["success"], is_tier_2=is_tier_2, dry_run=False,
                error=result.get("error"),
                extra={
                    "action": action,
                    "yaml_path": yaml_path,
                    "auto_reverted": result.get("auto_reverted", False),
                    "config_check": result.get("config_check"),
                },
            )

            return result

        except PermissionError:
            _LOGGER.error("Permission denied editing: %s", rel_path)
            await _audit_write(
                hass, config_dir,
                service="edit_yaml_config", path=rel_path,
                old_size=len(raw_content.encode("utf-8")) if raw_content else 0,
                new_size=None,
                success=False, is_tier_2=is_tier_2, dry_run=False,
                error="permission_denied",
            )
            return {
                "success": False,
                "error": f"Permission denied: {rel_path}",
            }
        except OSError as err:
            _LOGGER.error("Error editing YAML config %s: %s", rel_path, err)
            await _audit_write(
                hass, config_dir,
                service="edit_yaml_config", path=rel_path,
                old_size=len(raw_content.encode("utf-8")) if raw_content else 0,
                new_size=None,
                success=False, is_tier_2=is_tier_2, dry_run=False,
                error=str(err),
            )
            return {
                "success": False,
                "error": str(err),
            }

    # Register all services with response support
    hass.services.async_register(
        DOMAIN,
        SERVICE_EDIT_YAML_CONFIG,
        handle_edit_yaml_config,
        schema=SERVICE_EDIT_YAML_CONFIG_SCHEMA,
        supports_response=SupportsResponse.ONLY,
    )

    hass.services.async_register(
        DOMAIN,
        SERVICE_LIST_FILES,
        handle_list_files,
        schema=SERVICE_LIST_FILES_SCHEMA,
        supports_response=SupportsResponse.ONLY,
    )

    hass.services.async_register(
        DOMAIN,
        SERVICE_READ_FILE,
        handle_read_file,
        schema=SERVICE_READ_FILE_SCHEMA,
        supports_response=SupportsResponse.ONLY,
    )

    hass.services.async_register(
        DOMAIN,
        SERVICE_WRITE_FILE,
        handle_write_file,
        schema=SERVICE_WRITE_FILE_SCHEMA,
        supports_response=SupportsResponse.ONLY,
    )

    hass.services.async_register(
        DOMAIN,
        SERVICE_DELETE_FILE,
        handle_delete_file,
        schema=SERVICE_DELETE_FILE_SCHEMA,
        supports_response=SupportsResponse.ONLY,
    )

    hass.services.async_register(
        DOMAIN,
        SERVICE_APPEND_FILE,
        handle_append_file,
        schema=SERVICE_APPEND_FILE_SCHEMA,
        supports_response=SupportsResponse.ONLY,
    )

    _LOGGER.info("HA MCP Tools initialized with file management services (Phase 2)")
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    hass.services.async_remove(DOMAIN, SERVICE_EDIT_YAML_CONFIG)
    hass.services.async_remove(DOMAIN, SERVICE_LIST_FILES)
    hass.services.async_remove(DOMAIN, SERVICE_READ_FILE)
    hass.services.async_remove(DOMAIN, SERVICE_WRITE_FILE)
    hass.services.async_remove(DOMAIN, SERVICE_DELETE_FILE)
    hass.services.async_remove(DOMAIN, SERVICE_APPEND_FILE)
    return True
