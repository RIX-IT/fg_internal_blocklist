# Internal IP Address Blacklist

## Description

This repository is intended for internal use only. Use `internal_ip_address_blacklist_cleaned.txt` as a threat feed for your Firewall and incorporate it into your Firewall policies.

---

## Usage

- **`internal_ip_address_blacklist_raw.txt`**

  - Add new addresses to block in CIDR notation. For single IPs, use "/32".

- **`threat_feed_generator.exe`**

  - Run the generator tool; see features below.

- **`internal_ip_address_blacklist_cleaned.txt`**
  - A cleaned and processed list of IP addresses and subnets. Use this file for firewall configuration.

---

## Generator Tool Features

The `threat_feed_generator.exe` tool performs the following tasks:

1. **Parse the Input File**: Automatically selects `internal_ip_address_blacklist_raw.txt` if found in the tool's directory. Otherwise, use the file dialog to specify its location.

2. **Validate Entries**: Checks each entry for valid IP addresses/subnets.

3. **Remove Duplicates**: Ensures each entry is unique.

4. **Order Entries**: Organizes entries by subnet size and IP address.

5. **Combine Addresses into Subnets (Optional)**: Groups IPs into subnets based on a specified threshold. IPs sharing the same first three octets and exceeding the threshold are combined into a /24 subnet.

6. **WhoIs Lookup (Optional)**: Provides additional context like country, region, and ISP through optional WhoIs lookup, added as comments.

7. **Write Output**: Saves the processed list to `internal_ip_address_blacklist_cleaned.txt`.

**Source Code:** [`src\threat_feed_generator.py`](src/threat_feed_generator.py)

---

## Disclaimer

- This IP address blacklist is strictly for internal use.
- Unauthorized access, distribution, or use by external parties is prohibited.
- Provided "as is" without warranties or guarantees.
- We are not liable for any consequences resulting from its use or misuse.
