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

If multi-capture result endpoints return 404 while `operation_capture.json`
stores `capture_group` instead of `capture_group_id`, upgrade to a build that
accepts the legacy key and backfills the operation-to-capture-group mapping
into the DB.
