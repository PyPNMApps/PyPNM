# Local PNM File Retrieval Setup (Config Menu)

This example shows how to configure **local PNM file retrieval** using the interactive
`pypnm config-menu` helper. The `local.src_dir` setting must point to the directory
where PNM files are written and where PyPNM should look for them (for example,
your TFTP root such as `/srv/tftp`).

```shell
(.env) PyPNM$ pypnm config-menu

PyPNM System Configuration Menu
================================
Select an option:
  1) Edit FastApiRequestDefault
  2) Edit SNMP
  3) Edit PnmBulkDataTransfer
  4) Edit PnmFileRetrieval (retrieval_method only)
  5) Edit Logging
  6) Edit TestMode
  7) Run PnmFileRetrieval Setup (directory initialization)
  q) Quit
Enter selection: 7

Running: PyPNM/tools/pnm/pnm_file_retrieval_setup.py

INFO PnmFileRetrievalConfigurator: Using configuration file: PyPNM/src/pypnm/settings/system.json
INFO PnmFileRetrievalConfigurator: Created backup: PyPNM/src/pypnm/settings/system.bak.1765154728.json

Select PNM File Retrieval Method:
  1) local  - Copy from local src_dir
  2) tftp   - Download from TFTP server
  3) sftp   - Download from SFTP server
  q) Quit   - Exit without changes

Enter choice [1-4 or q to quit]: 1
INFO PnmFileRetrievalConfigurator: Selected retrieval method: local
Enter local src_dir [/srv/tftp]:
INFO PnmFileRetrievalConfigurator: Configured local.src_dir = /srv/tftp
INFO PnmFileRetrievalConfigurator: PNM file retrieval configuration complete.

Script completed successfully.


PyPNM System Configuration Menu
================================
Select an option:
  1) Edit FastApiRequestDefault
  2) Edit SNMP
  3) Edit PnmBulkDataTransfer
  4) Edit PnmFileRetrieval (retrieval_method only)
  5) Edit Logging
  6) Edit TestMode
  7) Run PnmFileRetrieval Setup (directory initialization)
  q) Quit
Enter selection: q
Exiting System Configuration Menu.
(.env) PyPNM$
```

In the example above, `local.src_dir` is set to `/srv/tftp`. This is the directory
where the cable modem places PNM files and where PyPNM will look for them when
`PnmFileRetrieval.retrieval_method.method` is set to `local`.
