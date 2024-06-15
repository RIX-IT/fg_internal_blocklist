import os
import re
import requests
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
from typing import List, Tuple, Dict, Set, Any

THRESHOLD_COMBINE_INTO_SUBNET = 5
WHOIS_LOOKUP_API_URL = "http://ipwho.is"


class App:
    def __init__(self, root: tk.Tk):
        """
        Initialize the app with GUI components.
        """
        self.root = root
        self.root.title("FortiGate Threat Feed Generator")

        self.input_file_path = tk.StringVar()
        self.threshold = tk.IntVar(value=THRESHOLD_COMBINE_INTO_SUBNET)
        self.add_comments = tk.BooleanVar(value=True)
        self.group_addresses = tk.BooleanVar(value=True)

        self.check_default_input_file()

        tk.Label(root, text="Input File:").grid(row=0, column=0, sticky=tk.W)
        tk.Entry(root, textvariable=self.input_file_path).grid(
            row=0, column=1, sticky=tk.EW
        )
        tk.Button(root, text="Browse", command=self.browse_input_file).grid(
            row=0, column=2
        )

        tk.Label(root, text="Group IPs after:").grid(row=1, column=0, sticky=tk.W)
        tk.Entry(root, textvariable=self.threshold).grid(row=1, column=1, sticky=tk.W)

        tk.Checkbutton(root, text="Check WhoIs", variable=self.add_comments).grid(
            row=2, column=0, sticky=tk.W
        )
        tk.Checkbutton(
            root, text="Group Addresses", variable=self.group_addresses
        ).grid(row=2, column=1, sticky=tk.W)

        tk.Button(root, text="Run", command=self.run).grid(
            row=3, column=0, columnspan=3
        )

        self.console_output = scrolledtext.ScrolledText(
            root, state="disabled", width=60, height=20
        )
        self.console_output.grid(row=4, column=0, columnspan=3, sticky=tk.NSEW)

        root.grid_columnconfigure(1, weight=1)
        root.grid_rowconfigure(4, weight=1)

    def check_default_input_file(self) -> None:
        """
        Check for the default input file and set it if found.
        """
        default_file = os.path.join(
            os.getcwd(), "internal_ip_address_blacklist_raw.txt"
        )
        if os.path.isfile(default_file):
            self.input_file_path.set(default_file)

    def browse_input_file(self) -> None:
        """
        Open a file dialog to browse for the input file.
        """
        initial_dir = (
            os.path.dirname(self.input_file_path.get())
            if self.input_file_path.get()
            else os.getcwd()
        )
        file_path = filedialog.askopenfilename(initialdir=initial_dir)
        if file_path:
            self.input_file_path.set(file_path)

    def run(self) -> None:
        """
        Run the process of reading, validating, and processing IP entries.
        """
        input_file_path = self.input_file_path.get()
        threshold = self.threshold.get()
        add_comments = self.add_comments.get()
        group_addresses = self.group_addresses.get()

        if not input_file_path:
            messagebox.showerror("Error", "Please select an input file.")
            return

        try:
            output_file_path = os.path.join(
                os.path.dirname(input_file_path),
                "internal_ip_address_blacklist_cleaned.txt",
            )

            with open(input_file_path, "r") as file:
                raw_entries = [line.strip() for line in file]

            valid_entries, invalid_entries = self.validate_entries(raw_entries)
            if invalid_entries:
                self.log_to_console(
                    f"Invalid entries found: {', '.join(invalid_entries)}"
                )

            if group_addresses:
                valid_entries = self.group_into_subnets(valid_entries, threshold)

            unique_entries = self.remove_duplicates(valid_entries)
            ordered_entries = self.order_output(unique_entries)

            checked_entries = (
                self.check_whois_info(ordered_entries)
                if add_comments
                else {entry: {} for entry in ordered_entries}
            )

            self.write_output_to_file(checked_entries, output_file_path)

            self.log_to_console("Processing completed successfully.")
        except Exception as e:
            self.log_to_console(f"Error: {e}")

    def validate_entries(self, entries: List[str]) -> Tuple[List[str], List[str]]:
        """
        Validate the list of IP entries.

        Args:
            entries: List of raw IP entries.

        Returns:
            A tuple containing two lists - valid entries and invalid entries.
        """
        valid_entries, invalid_entries = [], []
        for entry in entries:
            (valid_entries if self.is_valid_subnet(entry) else invalid_entries).append(
                entry
            )
        return valid_entries, invalid_entries

    def is_valid_subnet(self, entry: str) -> bool:
        """
        Check if the given entry is a valid subnet.

        Args:
            entry: The IP entry to validate.

        Returns:
            True if the entry is a valid subnet, otherwise False.
        """
        if not re.match(r"^\d{1,3}(\.\d{1,3}){3}(\/\d{1,2})?$", entry):
            return False

        parts = entry.split("/")
        if len(parts) == 2 and not (0 <= int(parts[1]) <= 32):
            return False

        return all(0 <= int(octet) <= 255 for octet in parts[0].split("."))

    def group_into_subnets(self, entries: List[str], threshold: int) -> List[str]:
        """
        Group IP addresses into subnets if they exceed the specified threshold.

        Args:
            entries: List of valid IP entries.
            threshold: The threshold for grouping IPs into subnets.

        Returns:
            A list of grouped IP entries.
        """
        grouped: Dict[str, Any] = {}
        for entry in entries:
            if entry.endswith("/32"):
                prefix = ".".join(entry.split(".")[:3])
                grouped.setdefault(prefix, []).append(entry)
            else:
                grouped[entry] = entry

        result = []
        for key, value in grouped.items():
            if isinstance(value, list) and len(value) >= threshold:
                result.append(f"{key}.0/24")
            else:
                result.extend(value if isinstance(value, list) else [value])
        return result

    def remove_duplicates(self, entries: List[str]) -> Set[str]:
        """
        Remove duplicate entries.

        Args:
            entries: List of valid IP entries.

        Returns:
            A set of unique IP entries.
        """
        return sorted(set(entries))

    def check_whois_info(self, entries: List[str]) -> Dict[str, Dict[str, str]]:
        """
        Check Whois information for each entry.

        Args:
            entries: List of valid IP entries.

        Returns:
            A dictionary with IP entries as keys and Whois information as values.
        """
        info_dict = {}
        for entry in entries:
            try:
                response = requests.get(
                    f"{WHOIS_LOOKUP_API_URL}/{entry.split('/')[0]}?fields=country,region,connection.isp"
                )
                response_json = response.json()
                info_dict[entry] = {
                    "country": response_json.get("country"),
                    "region": response_json.get("region"),
                    "isp": response_json.get("connection", {}).get("isp"),
                }
            except Exception as e:
                self.log_to_console(f"Error processing {entry}: {e}")
        return info_dict

    def order_output(self, entries: List[str]) -> List[str]:
        """
        Order the IP entries.

        Args:
            entries: List of valid IP entries.

        Returns:
            A sorted list of IP entries.
        """

        def sort_key(entry: str) -> Tuple[int, List[int]]:
            subnet = int(entry.split("/")[1]) if "/" in entry else 32
            ip_bytes = list(map(int, entry.split("/")[0].split(".")))
            return (subnet, ip_bytes)

        return sorted(entries, key=sort_key)

    def write_output_to_file(
        self, info_dict: Dict[str, Dict[str, str]], output_file_path: str
    ) -> None:
        """
        Write the processed IP entries and Whois information to the output file.

        Args:
            info_dict: Dictionary of IP entries and their Whois information.
            output_file_path: Path to the output file.
        """
        # FortiGate Restriction - Threat Feeds can only include a max of 131072 items
        if len(info_dict) >= 131072:
            self.log_to_console(
                "Error: The number of entries exceeds the limit of 131072"
            )
            return

        with open(output_file_path, "w") as file:
            for entry, info in info_dict.items():
                comment = " | ".join(
                    filter(
                        None, [info.get("country"), info.get("region"), info.get("isp")]
                    )
                )
                # FortiGate Restriction - Comments can have a max length of 63 chars
                comment = (
                    (
                        f"# {comment[:60]}...\n"
                        if len(comment) > 63
                        else f"# {comment}\n"
                    )
                    if comment
                    else ""
                )
                file.write(f"{entry} {comment}" if comment else f"{entry}\n")

    def log_to_console(self, message: str) -> None:
        """
        Log messages to the console.

        Args:
            message: The message to log.
        """
        self.console_output.configure(state="normal")
        self.console_output.insert(tk.END, message + "\n")
        self.console_output.configure(state="disabled")


if __name__ == "__main__":
    root = tk.Tk()
    app = App(root)
    root.mainloop()
