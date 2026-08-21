# Greppable Formats
The following script can be used to sort out file outputs more easily so they are ready to use for the pentest

## Setup
 
1. Save the script somewhere permanent, e.g.:
```
   mkdir -p ~/tools
   mv greppable_toolkit.py ~/tools/greppable_toolkit.py
   chmod +x ~/tools/greppable_toolkit.py
```

2. (Optional) Add a shell alias so you can launch it with a short command
   instead of typing the full path every time.
   Add this line to `~/.bashrc` (bash) or `~/.zshrc` (zsh):
```
   alias g='python3 ~/tools/greppable_toolkit.py'
```
Then reload your shell config:
```bash
   source ~/.bashrc   # or: source ~/.zshrc
```
 
   From then on, typing `g` and pressing Enter launches the menu.
 
   > Note: `g` is a short, common alias — if you already use it for something
   > else (e.g. `git`), pick a different name like `greps`


## Running It
 
```
python3 greppable_toolkit.py
```
or, if you set up the alias:
```bash
g
```
 
You'll see:
 
```
Select an option:
1. Extract /24 subnets from Masscan output
2. Extract IPs from a file
3. Share table for Dradis import
4. Extract NetBIOS/LLMNR hosts from Responder logs
5. Extract SMB signing:False hosts from NetExec output
6. Extract usernames from Responder captured hashes
0. Exit
Pick an option (0-6):
```
 
Type a number and press Enter. Each option will prompt you for the input
file (or directory) it needs, then ask for an output file name (press
Enter to accept the default shown in brackets).
 
## Menu Options
 
### 1. Extract /24 subnets from Masscan output
Pulls every IP out of a Masscan results file, truncates each to its first
three octets, dedupes, and appends `.0/24` — useful for feeding a smaller
set of subnets into Nessus or similar scanners.
 
Equivalent to:
```
grep -E -o "([0-9]{1,3}[.]){3}[0-9]{1,3}" file | \
    cut -d. -f1-3 | sort | uniq | sed 's/$/.0\/24/'
```
 
- **Input:** any file containing IPs (Masscan greppable output works well)
- **Output default:** `subnets_for_Nessus.txt`

### 2. Extract IPs from a file
Pulls every IP-shaped match out of a file, in the order it finds them,
duplicates included — no sorting, deduping, or validation.
 
Equivalent to:
```
grep -E -o "([0-9]{1,3}[.]){3}[0-9]{1,3}" file
```
 
- **Input:** any text file
- **Output default:** `ips.txt`

### 3. Share table for Dradis import
Reads a line-based share listing (e.g. from `nxc smb ... --shares`) and
converts it into a Markdown table you can paste directly into a Dradis
page.
 
- **Input:** a file with lines like `HOST   SHARE   PERMISSIONS`
  (columns separated by 2+ spaces or a tab)
- **Output default:** `shares_wiki.txt`
- **Output format:**
- ** It is important to note that this may not always print a clear table if there are extra spaces between the share name and and permissions. You will need to double check this as you go.

```
  | Host | Share | Permissions |
  |------|-------|-------------|
  | 10.10.10.5 | C$ | READ,WRITE |
```
 
### 4. Extract NetBIOS/LLMNR hosts from Responder logs
Pulls every IP out of a Responder log, then mimics `sort -n | uniq` to
produce a deduped list of hosts.
 
Equivalent to:
```
grep -oP '(\d{1,3}\.){3}\d{1,3}' filename.txt | sort -n | uniq
```
 
- **Input:** a Responder log file
- **Output default:** `netbios_llmnr_hosts.txt`

### 5. Extract SMB signing:False hosts from NetExec output
Scans NetExec (`nxc`) SMB output for hosts reporting `signing:False` —
these are potentially relayable targets (e.g. for NTLM relay attacks).
 
- **Input:** saved `nxc smb ...` output
- **Output default:** `smb_signing_false.txt`

### 6. Extract usernames from Responder captured hashes
Responder saves one file per source host, named like
`SMB-NTLMv2-SSP-<ip>.txt`, with lines formatted like:
```
DOMAIN\username::WORKSTATION:1122...:...
```
This option scans a directory for all `SMB-NTLMv2-SSP-*.txt` files, takes
just the first line of each, splits on `::`, and keeps the first field —
giving you one username per host across the whole capture set.
 
Equivalent to, run per file:
```
awk -F'::' '{print $1}' SMB-NTLMv2-SSP-<ip>.txt | head -1
```
 
- **Input:** a directory containing `SMB-NTLMv2-SSP-*.txt` files
- **Output default:** `usernames.txt`

## Notes
 
- All options write output to the current working directory by default —
  run the script from the folder where you want results saved, or supply
  a full path when prompted for the output file name.
- If a parser comes back empty, your tool's output format may differ
  slightly by version. Paste a sample line or two and the matching regex
  can be adjusted.
