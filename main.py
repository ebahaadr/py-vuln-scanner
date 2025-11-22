from scanner.core import PortScanner


def main():
    print("DEBUG: main() started")

    print(r"""
   ____        __      __      _   _                 _               
  / __ \____  / /___  / /_    | | | | ___  _ __ ___ | |__   ___ _ __ 
 / /_/ / __ \/ / __ \/ __ \   | |_| |/ _ \| '_ ` _ \| '_ \ / _ \ '__|
/ ____/ /_/ / / /_/ / / / /   |  _  | (_) | | | | | | |_) |  __/ |   
/_/    \____/_/\____/_/ /_/    |_| |_|\___/|_| |_| |_|_.__/ \___|_|   

    Simple Python Vulnerability & Port Scanner
    """)

    target = input("Target IP / domain: ").strip()
    print(f"DEBUG: target = {target!r}")

    port_range = input("Port range (default 1-1024, e.g. 1-65535): ").strip()
    print(f"DEBUG: port_range input = {port_range!r}")

    if "-" in port_range:
        start_port_str, end_port_str = port_range.split("-", 1)
        start_port = int(start_port_str)
        end_port = int(end_port_str)
    else:
        start_port, end_port = 1, 1024

    print(f"DEBUG: will scan {target} ports {start_port}-{end_port}")

    scanner = PortScanner(target=target, start_port=start_port, end_port=end_port, threads=50)
    print("DEBUG: PortScanner created, starting scan...")
    scanner.run()
    print("DEBUG: scan finished")


if __name__ == "__main__":
    main()