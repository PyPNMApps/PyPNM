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

Q: Why is extension data missing after processing a PNM transaction record?  
A: Ensure the transaction record includes an `extension` mapping and that the update helper merges the extension into the PNM data before returning the result.

Q: Why does US PreEq SNMP retrieval log validation errors about missing fields?  
A: Some modems return sparse or empty entries for certain indices. Ensure the device supports the table and that the entry is populated; missing required fields will cause the entry to be skipped.

Q: Why do multi US OFDMA Pre-Equalization plots show a Channel Estimation title?  
A: Update to a build that includes the plot title fix; the title now reflects the PNM file type as US PreEqualization (PNN6) or US Last PreEqualization (PNN7).

Q: Why do US OFDMA Pre-Equalization analysis examples reject uppercase analysis types?  
A: The multi-capture analysis endpoints accept the string enum values (`min-avg-max`, `group-delay`, `echo-detection-ifft`) along with the standard analysis output structure.

Q: Why do multi US OFDMA Pre-Equalization plots only show Pre-Equalization data?  
A: Ensure both Pre-Equalization (PNN6) and Last Pre-Equalization (PNN7) files are present; the multi-capture plots now emit both sets when available.

## TODO

- Add or update a FAQ entry whenever an error is fixed so the resolution is documented.
- Add FAQ entries when SNMP validation errors are addressed to capture the resolution.
- Track FAQ updates for the US OFDMA Pre-Equalization plot title fix.
- Track FAQ updates for the US OFDMA Pre-Equalization analysis request format.
- Track FAQ updates for the US OFDMA Pre-Equalization dual plot output.
