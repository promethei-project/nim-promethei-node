# Standalone tool: needs the repository root on the path for `pkg/promethei/...`
# imports, and threads for Taskpool. Mirrors the relevant parts of
# tests/config.nims without the test-only defines.
--path:
  "../.."
--threads:
  on
