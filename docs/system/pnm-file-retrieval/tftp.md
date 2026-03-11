# TFTP PNM File Retrieval Setup (Config Menu)

This example shows how to configure **TFTP-based PNM file retrieval** using the
interactive `pypnm config-menu` helper. In this scenario, `localhost` is selected as
the TFTP host, which means the TFTP server and PyPNM are running on the same box.
PyPNM will still use the TFTP protocol to download PNM files for analysis.

The `remote_dir` is the directory on the TFTP server where PNM files are stored
and served. Leaving it empty (`""`) uses the TFTP server's default root
(often something like `/srv/tftp`, depending on your server configuration).

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
INFO PnmFileRetrievalConfigurator: Created backup: PyPNM/src/pypnm/settings/system.bak.1765155200.json

Select PNM File Retrieval Method:
  1) local  - Copy from local src_dir
  2) tftp   - Download from TFTP server
  3) sftp   - Download from SFTP server
  q) Quit   - Exit without changes

Enter choice [1-4 or q to quit]: 2
INFO PnmFileRetrievalConfigurator: Selected retrieval method: tftp
Enter TFTP host [localhost]:
Enter TFTP port for localhost [69]:
Enter TFTP timeout seconds [5]:
Enter TFTP remote_dir []:
INFO PnmFileRetrievalConfigurator: Configured TFTP host=localhost port=69 remote_dir=
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

If PNM file retrieval fails with TFTP errors (for example,
`TFTP_PNM_FILE_FETCH_ERROR` in the logs), verify:

1. The TFTP service is running on `localhost` and listening on UDP port 69.

Note: macOS includes a TFTP client but does not ship a native TFTP server. Use a
third-party daemon if you need a local TFTP server on macOS.
2. The TFTP server is allowed to **serve** files (download) as well as accept
   uploads from the cable modem. Some configurations are upload-only.
3. The TFTP root or `remote_dir` actually contains the PNM files that the CM
   is writing.
4. Local firewall rules (or SELinux/AppArmor) are not blocking TFTP traffic
   between the CM and the PyPNM host, or between PyPNM and `localhost` itself.

## Quick TFTP Health Check On Ubuntu (localhost)

The following steps assume a typical Ubuntu environment where `tftpd-hpa` is
used and the TFTP root is `/srv/tftp`. Adjust paths if your configuration
differs.

1. Install the TFTP server (if not already installed):

   ```bash
   sudo apt update
   sudo apt install -y tftpd-hpa
   ```

2. Check that the TFTP service is running:

   ```bash
   systemctl status tftpd-hpa
   ```

   Look for `active (running)`. If it is not running, start it:

   ```bash
   sudo systemctl start tftpd-hpa
   sudo systemctl enable tftpd-hpa
   ```

3. Confirm the TFTP root directory:

   ```bash
   sudo cat /etc/default/tftpd-hpa
   ```

   ```shell

    (.env) PyPNM$ sudo cat /etc/default/tftpd-hpa
    [sudo] password for dev01: 
    # /etc/default/tftpd-hpa

    TFTP_USERNAME="tftp"
    TFTP_DIRECTORY="/srv/tftp"
    TFTP_ADDRESS=":69"
    TFTP_OPTIONS="--secure --create"

   ```

   Check the `TFTP_DIRECTORY` line. This directory must match what you expect
   for `remote_dir` (or be consistent with leaving `remote_dir` empty when it
   points to the server root). This is where the CM will write PNM files and
   where PyPNM will try to download them from.

4. Create a small test file in the TFTP directory (example assumes `/srv/tftp`):

   ```bash
   echo "pypnm-tftp-test" | sudo tee /srv/tftp/pypnm-test.txt
   sudo chmod 644 /srv/tftp/pypnm-test.txt
   ```

5. Install a TFTP client and test a download from `localhost`:

   ```bash
   sudo apt install -y tftp
   cd /tmp
   
   tftp localhost
   get pypnm-test.txt
   quit
   ```

   After the command, verify the file:

   ```bash
   cat /tmp/pypnm-test.txt
   ```

   You should see the contents `pypnm-tftp-test`. If this works, the TFTP
   server is able to **serve** files on `localhost`, which is the same path
   PyPNM will use when `host=localhost` and `method=tftp` are configured.

6. If the test fails, re-check:

   - TFTP service status (`systemctl status tftpd-hpa`)
   - The configured `TFTP_DIRECTORY` vs the directory where you put the file
   - Local firewall rules (for example, with UFW):

     ```bash
     sudo ufw status
     sudo ufw allow 69/udp
     ```

   Once the manual TFTP test succeeds, PyPNM should be able to retrieve PNM
   files from the same TFTP root/`remote_dir`.
