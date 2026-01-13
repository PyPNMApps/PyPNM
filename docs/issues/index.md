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

Runtime no longer reads `operation_capture.json` after the DB cutover, so legacy
keys are not accepted by live endpoints. Use the offline migrator or re-run the
capture workflow on a DB-backed build to populate the operation-to-group
mapping in the database.

### Session group mappings missing after upgrade

Runtime no longer reads `session_group.json`; session groups are DB-backed. Use
the offline migrator (`python -m pypnm.tools.migrate_session_groups --input
PATH`) or re-run the session workflow to repopulate the DB.

### Transaction records store an unexpected MAC address value

The canonical MAC address stored in `transaction_records` is a lowercase string.
Earlier builds could persist a non-string value when `PnmFileTransaction.insert`
was passed a callable. Upgrade to a build with the fix and re-run captures to
refresh affected entries.
