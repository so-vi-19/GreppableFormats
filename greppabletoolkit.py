#!/usr/bin/env python3
# Script to be used for Grepping through various outputs and creating a new file with the results.

import re
import os


def get_input_path(prompt="Enter path to input file: "):
    path = input(prompt).strip().strip('"').strip("'")
    while not os.path.isfile(path):
        print(f"File not found: {path}")
        path = input(prompt).strip().strip('"').strip("'")
    return path


def get_output_path(default_name):
    path = input(f"Enter output file name [{default_name}]: ").strip()
    return path if path else default_name


def write_lines(path, lines):
    with open(path, "w") as f:
        for line in lines:
            f.write(line.rstrip("\n") + "\n")
    print(f"[+] Wrote {len(lines)} lines to {path}")


### Masscan to smaller ranges for nessus, prints into /24s.
def subnets_from_masscan():
    """
    Equivalent to:
        grep -E -o "([0-9]{1,3}[\\.]){3}[0-9]{1,3}" file | \
            cut -d. -f1-3 | sort | uniq | sed 's/$/.0\\/24/'

    Extracts all IPv4 addresses, truncates to the first 3 octets, dedupes,
    and appends '.0/24' to produce a unique list of /24 subnets.
    """
    infile = get_input_path()
    ip_pattern = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

    subnets = set()
    with open(infile) as f:
        for line in f:
            for match in ip_pattern.findall(line):
                octets = match.split(".")
                if all(0 <= int(o) <= 255 for o in octets):
                    subnets.add(".".join(octets[:3]) + ".0/24")

    outfile = get_output_path("subnets_for_Nessus.txt")
    write_lines(outfile, sorted(subnets, key=lambda s: tuple(map(int, s.split("/")[0].split(".")))))


## Extracting IPs from a file and creating a new file with the results.
def extract_ips():
    """
    Equivalent to:
        grep -E -o "([0-9]{1,3}[\\.]){3}[0-9]{1,3}" file

    Pulls every IPv4-shaped match out of the file, in the order found,
    duplicates included (no sorting/deduping/range-validation, just like
    the raw grep command).
    """
    infile = get_input_path()
    ip_pattern = re.compile(r"([0-9]{1,3}\.){3}[0-9]{1,3}")

    ips = []
    with open(infile) as f:
        for line in f:
            for match in ip_pattern.finditer(line):
                ips.append(match.group(0))

    outfile = get_output_path("ips.txt")
    write_lines(outfile, ips)


## Share table for dradis import
def share_wiki_style_for_dradis():
    """
    Takes the faculty level or student level share access and prints the nxc
    output into a table that can be pasted into dradis, like:
        | Host | Share | Permissions |
    """
    infile = get_input_path()
    lines_out = ["| Host | Share | Permissions |", "|------|-------|-------------|"]

    with open(infile) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            parts = re.split(r"\s{2,}|\t", line)
            if len(parts) >= 2:
                host = parts[0]
                share = parts[1]
                perms = parts[2] if len(parts) > 2 else ""
                lines_out.append(f"| {host} | {share} | {perms} |")

    outfile = get_output_path("shares_wiki.txt")
    write_lines(outfile, lines_out)


def netbios_llmnr_hosts():
    """
    Equivalent to:
        grep -oP '(\\d{1,3}\\.){3}\\d{1,3}' filename.txt | sort -n | uniq

    Extracts all IP-shaped matches, then mimics `sort -n | uniq`:
    GNU sort -n compares the leading numeric prefix of each line first,
    falling back to full-line string comparison for ties, then uniq
    collapses adjacent duplicates.
    """
    infile = get_input_path()
    ip_pattern = re.compile(r"(\d{1,3}\.){3}\d{1,3}")

    ips = []
    with open(infile) as f:
        for line in f:
            for match in ip_pattern.finditer(line):
                ips.append(match.group(0))

    def leading_int(s):
        m = re.match(r"\d+", s)
        return int(m.group(0)) if m else 0

    ips.sort(key=lambda ip: (leading_int(ip), ip))

    deduped = []
    for ip in ips:
        if not deduped or deduped[-1] != ip:
            deduped.append(ip)

    outfile = get_output_path("netbios_llmnr_hosts.txt")
    write_lines(outfile, deduped)


## Signing false hosts for relayable targets
def smb_signing_false_hosts():
    """
    Expects NetExec (nxc) smb output, e.g.:
        SMB  10.10.10.5   445    DC01   [*] Windows 10 (signing:False) ...
    Produces a list of hosts where signing is disabled (signing:False),
    which are relayable targets.
    """
    infile = get_input_path()
    pattern = re.compile(r"^\S+\s+([\d.]+)\s+\d+\s+\S+.*signing:\s*False", re.IGNORECASE)

    hosts = set()
    with open(infile) as f:
        for line in f:
            m = pattern.search(line)
            if m:
                hosts.add(m.group(1))

    outfile = get_output_path("smb_signing_false.txt")
    write_lines(outfile, sorted(hosts, key=lambda ip: tuple(map(int, ip.split(".")))))


def usernames_from_responder():
    """
    Equivalent to, run per captured hash file:
        awk -F'::' '{print $1}' SMB-NTLMv2-SSP-<ip>.txt | head -1

    Responder saves one file per source host, named like
    'SMB-NTLMv2-SSP-<ip>.txt', where each line looks like:
        DOMAIN\\username::WORKSTATION:1122...:...
    This splits each file on '::' and takes the first field (domain\\user)
    of just the first line, then does that across every matching file in
    a directory to build one username per host.
    """
    directory = input("Enter directory containing SMB-NTLMv2-SSP-*.txt files: ").strip().strip('"').strip("'")
    while not os.path.isdir(directory):
        print(f"Directory not found: {directory}")
        directory = input("Enter directory containing SMB-NTLMv2-SSP-*.txt files: ").strip().strip('"').strip("'")

    pattern = re.compile(r"^SMB-NTLMv2-SSP-.*\.txt$", re.IGNORECASE)
    matching_files = sorted(f for f in os.listdir(directory) if pattern.match(f))

    if not matching_files:
        print("[!] No SMB-NTLMv2-SSP-*.txt files found in that directory.")
        return

    usernames = []
    for fname in matching_files:
        fpath = os.path.join(directory, fname)
        with open(fpath) as f:
            first_line = f.readline().strip()
        if first_line:
            username = first_line.split("::")[0]
            usernames.append(username)

    outfile = get_output_path("usernames.txt")
    write_lines(outfile, usernames)


# Main menu for the script, allowing the user to select which function to run.
def show_menu():
    print("\nSelect an option:")
    print("1. Extract /24 subnets from Masscan output")
    print("2. Extract IPs from a file")
    print("3. Share table for Dradis import")
    print("4. Extract NetBIOS/LLMNR hosts from Responder logs")
    print("5. Extract SMB signing:False hosts from NetExec output")
    print("6. Extract usernames from Responder captured hashes")
    print("0. Exit")


ACTIONS = {
    "1": subnets_from_masscan,
    "2": extract_ips,
    "3": share_wiki_style_for_dradis,
    "4": netbios_llmnr_hosts,
    "5": smb_signing_false_hosts,
    "6": usernames_from_responder,
}


def main():
    while True:
        show_menu()
        choice = input("Pick an option (0-6): ").strip()

        if choice == "0":
            print("Goodbye!")
            break
        elif choice in ACTIONS:
            try:
                ACTIONS[choice]()
            except Exception as e:
                print(f"[!] Error: {e}")
        else:
            print("Invalid choice, please try again.")


if __name__ == "__main__":
    main()
