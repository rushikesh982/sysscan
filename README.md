# TargetScan for Kali
Python target assessment: discovery -> TCP/optional UDP ports -> versions -> targeted enumeration -> PDF/JSON/XML.

## Install and run
```bash
sudo apt update
sudo apt install nmap python3-venv unzip
unzip targetscan.zip
cd targetscan
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python targetscan.py
```
Enter one lab IP or authorized hostname when prompted. Example lab command:
```bash
.venv/bin/python targetscan.py 192.168.56.101
```
Default scans Nmap's top 1000 TCP ports. Full TCP ports, UDP top 20 and OS estimate:
```bash
sudo .venv/bin/python targetscan.py 192.168.56.101 --all-ports --udp --os
```
If discovery is blocked:
```bash
.venv/bin/python targetscan.py 192.168.56.101 --skip-discovery
```
Selected website ports (replace hostname with your authorized site; no URL prefix):
```bash
.venv/bin/python targetscan.py your-authorized-host.example --ports 80,443 --skip-discovery
```
`--address IP` selects one IP from DNS results. Each run pins one address and records all resolved addresses. It never scans all CDN nodes or seeks an origin IP. Hostname scans set HTTP Host and TLS SNI. HTTP title scripts can follow redirects; obtain permission for redirected destinations as well. Nmap scripts may make protocol connections and an anonymous FTP login attempt.

## Enumeration
Only discovered open services get matching scripts: HTTP titles/headers/server hints; FTP system and anonymous access; SSH keys/algorithms; SMB protocols/signing/OS hints; DNS recursion; SMTP commands; MySQL greeting; RDP NTLM information; TLS certificate.
Version detection is limited (`--version-light`). HTTP server banners are hints, not comprehensive technology detection. No credentials, brute force, exploit scripts, directory fuzzing or CVE claims. All script names are explicitly allowlisted. Nmap's script portrules may skip checks or emit no output; that is inconclusive, not a pass.

## Reports and scope
Look in `reports/<timestamp>/report.pdf`. JSON contains structured evidence, XML/logs preserve each stage. Rule-based findings currently cover anonymous FTP, SMBv1, optional SMB signing and observed DNS recursion. Other enumeration results are evidence for manual review.
No overall security score; version banners and OS matches cannot establish vulnerability. Root is required only for UDP and OS probes. Discovery failure stops scanning unless --skip-discovery is selected. UDP open|filtered results stay ambiguous and are version-probed, not called open. Each stage has a 30-minute timeout; --timeout changes seconds. There may be many enumeration stages, so full scans can take time. Interrupted runs keep completed stage evidence. Scan operations can affect service logs/load; keep permission and scope appropriate.

## Preview and tests
```bash
.venv/bin/python targetscan.py --demo
.venv/bin/python -m unittest discover -s tests -v
```
Sample report is explicitly synthetic. Tests use fixtures/mocks; no public host was scanned during development. Nmap is an external dependency, and live Kali integration should be verified in your lab.

Documentation: https://nmap.org/book/man.html and https://nmap.org/nsedoc/
"# sysscan" 
