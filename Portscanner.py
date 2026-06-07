import socket
import sys
import time


def validate_input(ip_string, ports_string):
    """
    Validate the target IP address and port list.

    Args:
        ip_string: str
        ports_string: str

    Returns:
        (ip, ports) on success
        (None, None) on failure
    """

    # Validate IP address
    try:
        socket.inet_aton(ip_string)

    except socket.error:
        print(f"Invalid IP address: {ip_string}")
        return (None, None)

    # Validate ports
    try:
        ports = []

        for port_str in ports_string.split(","):

            port = int(port_str.strip())

            if port < 1 or port > 65535:
                print(f"Invalid port number: {port}")
                return (None, None)

            ports.append(port)

    except ValueError:
        print(f"Non-numeric port value detected.")
        return (None, None)

    return (ip_string, ports)


def scan_port(ip, port, timeout=1.0):
    """
    Attempt a TCP connection to a single port on the target IP.

    Args:
        ip     : str, validated target IP address
        port   : int, validated port number to probe (1–65535)
        timeout: float, seconds to wait before giving up (default 1.0)

    Returns:
        bool: True if port is open, False if closed or unreachable
    """

    sock = None

    try:
        # Create TCP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Prevent hanging on filtered ports
        sock.settimeout(timeout)

        # Attempt connection
        result = sock.connect_ex((ip, port))

        # Open port
        if result == 0:
            return True

        # Closed/refused/filtered port
        return False

    except Exception as e:
        print(f"Error scanning {ip}:{port}: {e}")
        return False

    finally:
        if sock is not None:
            sock.close()


def run_scan(ip, ports):
    """
    Scan a list of ports on the target IP and print a formatted report.

    Args:
        ip   : str
        ports: list[int]

    Returns:
        dict
    """

    print(f"Starting scan")
    print(f"Target IP: {ip}")
    print(f"Ports: {ports}")

    open_ports = []
    closed_ports = []

    start_time = time.time()

    for port in ports:

        is_open = scan_port(ip, port)

        if is_open:
            print(f"Port {port:<5} OPEN")
            open_ports.append(port)

        else:
            print(f"Port {port:<5} CLOSED")
            closed_ports.append(port)

    end_time = time.time()

    elapsed = end_time - start_time

    print(
        f"Scan complete in "
        f"{elapsed:.2f}s | "
        f"Open: {len(open_ports)} | "
        f"Closed: {len(closed_ports)}"
    )

    return {
        "open": open_ports,
        "closed": closed_ports
    }


def main():
    """
    Entry point: prompt the user, validate input,
    and run the scan.
    """

    print(f"TCP Port Scanner")
    print("----------------")

    ip_input = input("Enter target IP address: ")

    ports_input = input(
        "Enter ports to scan (comma-separated, e.g. 22,80,443): "
    )

    validated_ip, validated_ports = validate_input(
        ip_input,
        ports_input
    )

    if validated_ip is None and validated_ports is None:
        print(f"Scan aborted due to invalid input.")
        sys.exit(1)

    run_scan(validated_ip, validated_ports)


if __name__ == "__main__":
    main()