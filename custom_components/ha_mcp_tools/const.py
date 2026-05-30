"""Constants for HA MCP Tools integration.

PHASE 2 widening (2026-05-01) — Phase 1 additions PLUS new constructs that
the matching __init__.py uses to drive safety machinery.

New in Phase 2 vs Phase 1:
- ALLOWED_WRITE_FILES: exact-filename allowlist for raw ha_write_file writes
  to repo-root files (CLAUDE.md, README.md, .gitignore, etc.). Implemented
  in __init__.py via the new _is_path_allowed_for_write helper.
- WRITE_TIER_2_FILES: paths that trigger pre-write text backup, post-write
  check_config validation, and auto-revert on failure.
- AUDIT_LOG_PATH: relative path (from config_dir) where ha_write_file and
  ha_config_set_yaml append JSONL audit entries.

If you only want Phase 1's behaviour, use phase_1_const.py instead — that
version has just the additive YAML allowlist widening with no new machinery.
"""

DOMAIN = "ha_mcp_tools"

# Allowed directories for file operations (relative to config dir)
ALLOWED_READ_DIRS = ["www", "themes", "custom_templates"]
ALLOWED_WRITE_DIRS = ["www", "themes", "custom_templates"]

# Additional fnmatch patterns for paths allowed beyond the directory-level
# allowlist. See phase_1_const.py for the path layout rationale.
ALLOWED_READ_PATTERNS = [
    "scripts/*",
    "config/scripts/*",
    "config/www/*",
    "blueprints/*",
    "packages/*",
]

ALLOWED_WRITE_PATTERNS = [
    "scripts/*",
    "config/scripts/*",
    "config/www/*",
    "blueprints/*",
    "packages/*",
]

# Phase 2 (2026-05-01): exact filenames in the config root that ha_write_file
# can touch. Matched against the normalized relative path. This is checked
# in addition to ALLOWED_WRITE_DIRS / ALLOWED_WRITE_PATTERNS via the new
# _is_path_allowed_for_write helper in __init__.py.
#
# Use for repo-hygiene files that don't naturally live in any subdirectory.
# DO NOT add secrets.yaml here — its content is masked on read for a reason;
# allowing write would silently bypass that protection.
ALLOWED_WRITE_FILES = [
    "CLAUDE.md",
    "README.md",
    "CHANGELOG.md",
    ".gitignore",
    # Phase 2 follow-up (2026-05-02 evening): mirror WRITE_TIER_2_FILES so
    # the path-allowlist gate doesn't fire before the Tier 2 safety machinery.
    # Without these, ha_write_file to configuration.yaml et al returns
    # path_not_allowed even though the auto-revert / check_config / pre-write
    # backup machinery is fully wired up.
    "configuration.yaml",
    "customize.yaml",
    "groups.yaml",
]

# Phase 2 (2026-05-01): paths that trigger Tier 2 safety machinery on write.
# When ha_write_file targets one of these paths, the handler will:
#   1. Capture an in-memory snapshot of the existing content (if any)
#   2. Write a text backup to www/yaml_backups/<file>.<timestamp>.bak
#   3. After the write, run homeassistant.check_config
#   4. If check_config reports errors AND auto_revert is True (default),
#      restore the original content via atomic write from the snapshot
#
# These are paths where a bad write would leave HA broken until the
# operator intervenes manually. Auto-revert uses an in-memory text snapshot,
# NOT backup.restore — no HA restart needed.
WRITE_TIER_2_FILES = frozenset({
    "configuration.yaml",
    "customize.yaml",
    "groups.yaml",
})

# Phase 2 (2026-05-01): JSONL audit log location for write operations.
# Path is RELATIVE to config_dir. On Tom's install (double-config quirk),
# this resolves to /config/config/scripts/.mcp_write_audit.log — alongside
# CLAUDE.md and other Claude-managed artifacts.
#
# For installs without the double-config quirk, change the value to
# "scripts/.mcp_write_audit.log" so it resolves to /config/scripts/.
AUDIT_LOG_PATH = "config/scripts/.mcp_write_audit.log"
# Rotate the audit log when it crosses this size, moving the current log to
# AUDIT_LOG_PATH + ".1" (single-generation rotation).
AUDIT_LOG_MAX_BYTES = 1_000_000

# Files allowed for managed YAML editing (handle_edit_yaml_config).
ALLOWED_YAML_CONFIG_FILES = [
    "configuration.yaml",
    "customize.yaml",
    "groups.yaml",
]

# Top-level YAML keys allowed for editing. See phase_1_const.py for full
# rationale. Phase 2 keeps the same set as Phase 1.
ALLOWED_YAML_KEYS = frozenset(
    {
        "template",
        "sensor",
        "binary_sensor",
        "command_line",
        "rest",
        "mqtt",
        "shell_command",
        "switch",
        "light",
        "fan",
        "cover",
        "climate",
        "notify",
        "group",
        "utility_meter",
        "homeassistant",
        "frontend",
        "recorder",
        "logger",
    }
)

YAML_KEY_POST_ACTIONS: dict[str, dict[str, str]] = {
    "template": {
        "post_action": "reload_available",
        "reload_service": "homeassistant.reload_custom_templates",
    },
    "mqtt": {
        "post_action": "reload_available",
        "reload_service": "mqtt.reload",
    },
    "group": {
        "post_action": "reload_available",
        "reload_service": "group.reload",
    },
}
YAML_KEY_DEFAULT_POST_ACTION = {"post_action": "restart_required"}
