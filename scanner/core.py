import socket
import threading
from queue import Queue
from typing import Optional

from colorama import Fore, Style, init

from scanner.services import COMMON_PORTS
from scanner.vulndb import VULN_SIGNATURES

init(autoreset=True)


class PortScanner:
    def __init__(self, target: str, start_port: int = 1, end_port: int = 1024, threads: int = 100):
        self.target = target
        self.start_port = start_port
        self.end_port = end_port
        self.threads = threads
        self.queue = Queue()
        self.open_ports = []

    def _scan_port(self, port: int):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.0)
            result = sock.connect_ex((self.target, port))  # 0 ise açık
            if result == 0:
                banner = self._grab_banner(sock)
                service = COMMON_PORTS.get(port, "Unknown")

                print(f"{Fore.GREEN}[+] Port {port}/tcp OPEN ({service}){Style.RESET_ALL}")
                if banner:
                    print(f"    Banner: {banner.strip()}")

                vulns = self._check_vulnerabilities(service, banner)
                for v in vulns:
                    print(f"    {Fore.RED}[!] Possible vuln ({v['risk']}): {v['description']}{Style.RESET_ALL}")

                self.open_ports.append((port, service, banner))

            sock.close()
        except Exception as e:
            print(f"{Fore.YELLOW}[DEBUG] Error scanning port {port}: {e}{Style.RESET_ALL}")

    def _grab_banner(self, sock: socket.socket) -> Optional[str]:
        """Basit banner grabbing."""
        try:
            sock.settimeout(1.0)
            data = sock.recv(1024)
            if data:
                return data.decode(errors="ignore")
        except Exception:
            return None
        return None

    def _check_vulnerabilities(self, service: str, banner: Optional[str]):
        if not banner:
            return []
        matches = []
        for sig in VULN_SIGNATURES:
            if sig["service"].lower() == service.lower() and sig["banner_contains"].lower() in banner.lower():
                matches.append(sig)
        return matches

    def _worker(self):
        while True:
            try:
                port = self.queue.get_nowait()
            except Exception:
                break

            self._scan_port(port)
            self.queue.task_done()

    def run(self):
        print(f"{Fore.CYAN}[*] Scanning {self.target} ports {self.start_port}-{self.end_port}...{Style.RESET_ALL}")

        for port in range(self.start_port, self.end_port + 1):
            self.queue.put(port)

        for _ in range(self.threads):
            t = threading.Thread(target=self._worker)
            t.daemon = True
            t.start()

        self.queue.join()
        print(f"{Fore.CYAN}[*] Scan completed. Open ports found: {len(self.open_ports)}{Style.RESET_ALL}")