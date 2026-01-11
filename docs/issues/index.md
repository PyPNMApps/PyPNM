# Reporting Issues

If you encounter a bug or unexpected behavior while using PyPNM, please report it
so we can investigate and resolve the issue. This document outlines the steps to
create a support bundle that captures the necessary data for debugging.

[REPORTING ISSUES](reporting-issues.md)

## Support Bundle Script

PyPNM includes a support bundle script that collects relevant logs, database
entries, and configuration files related to your issue. This script helps
sanitize sensitive information before sharing it with the PyPNM support team.

[Support Bundle Builder](support-bundle.md)

## FAQ

### Multi-capture results return 404 with legacy operation_capture.json

The canonical key is `capture_group_id`, but `capture_group` is still accepted
as a fallback for existing persisted JSON during this transition. If multi-
capture result endpoints return 404 while `operation_capture.json` stores the
legacy key, upgrade to a build that accepts it and backfills the mapping into
the DB.
