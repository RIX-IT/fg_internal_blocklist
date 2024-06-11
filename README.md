# Internal IP Address Blacklist

## Description

This repository contains two lists of IP addresses for internal use within our organization. Users should add IP addresses to the `internal_ip_address_blacklist_raw.txt` file. The `internal_ip_address_blacklist_cleaned.txt` file is the cleaned version of the raw list and should be used for firewall configuration.

## Files

- `internal_ip_address_blacklist_raw.txt`: The raw list of IP addresses and subnets. Users should add new entries to this file.
- `internal_ip_address_blacklist_cleaned.txt`: The cleaned and processed list of IP addresses and subnets. This file should be used for firewall configuration.
- `clean_ip_list.ps1`: A PowerShell script to clean and process the raw list.

## PowerShell Script

The `clean_ip_list.ps1` script performs the following tasks:

1. **Parse the File**: Reads the `internal_ip_address_blacklist_raw.txt` file and trims any unnecessary whitespace.
2. **Validate Entries**: Checks each entry to ensure it is a valid IP address or subnet. If any invalid entries are found, the script will throw an error and provide details of the invalid entries.
3. **Combine Subnets**: If more than a specified number (default is 5) of IP addresses share the same first three octets, they are combined into a /24 subnet.
4. **Remove Duplicates**: Removes any duplicate entries from the list.
5. **Order Entries**: Orders the entries by subnet size and IP address.
6. **Write Output**: Writes the cleaned and processed list to `internal_ip_address_blacklist_cleaned.txt`.

---

## Disclaimer

- This blacklist of IP addresses is intended solely for internal use.
- Unauthorized access, distribution, or usage of this list by any external parties is strictly prohibited.
- This list is provided "as is" without any warranties or guarantees of any kind.
- We are not responsible for any consequences resulting from the use or misuse of this list.
