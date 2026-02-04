GREEN = "\033[32m"
RED = "\033[31m"
RESET = "\033[0m"


def info(message: str) -> None:
    """Print info message with [*] marker."""
    print(f"[*] {message}")


def success(message: str, colored: bool = False) -> None:
    """Print success message with [+] marker. Use colored output only when requested."""
    if colored:
        print(f"{GREEN}[+] {message}{RESET}")
    else:
        print(f"[+] {message}")


def error(message: str, colored: bool = False) -> None:
    """Print error message with [-] marker. Use colored output only when requested."""
    if colored:
        print(f"{RED}[-] {message}{RESET}")
    else:
        print(f"[-] {message}")
