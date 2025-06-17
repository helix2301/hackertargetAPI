import urllib.request
import subprocess
import platform
import socket
import ipaddress
import threading
import random
import string
import secrets
import ssl
from datetime import datetime, UTC
import smtplib

# ----------- Menu Display -----------
print('1 - DNS Lookup - URL')
print('2 - Reverse DNS Lookup - IP Address')
print('3 - GeoIP Lookup API - IP Address')
print('4 - Reverse IP Lookup - IP Address')
print('5 - HTTP Headers - URL')
print('6 - Page Links - URL')
print('7 - AS Lookup - IP Address')
print('8 - Traceroute - Host/IP')
print('9 - Port Scanner - Host/IP')
print('10 - Ping - Host/IP')
print('11 - Banner Grab - Host/IP and Port')
print('12 - OS Detection - Host/IP')
print('13 - Network Scanner (Local Subnet)')
print('14 - Service Check (SMB/Telnet/FTP/SFTP/SSH) - Host/IP')
print('15 - Generate Hard Password')
print('16 - SSL Certificate Check - URL')
print('17 - SMTP Server Check - Host/IP and Port')
print('18 - IP Calculator - CIDR/IP Info')

# ----------- Functions -----------

def main(url):
    try:
        with urllib.request.urlopen(url) as response:
            result = response.read().decode('utf-8')
            print(result)
    except Exception as e:
        print(f"Request failed: {e}")

def traceroute(host):
    system = platform.system()
    if system == "Windows":
        cmd = ["tracert", host]
    else:
        cmd = ["traceroute", host]
    try:
        print(f"Running traceroute for {host}...\n")
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        print(result.stdout)
    except Exception as e:
        print(f"Traceroute failed: {e}")

def port_scanner(host, start_port=1, end_port=1024):
    print(f"Starting port scan on {host} from port {start_port} to {end_port}...")
    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror:
        print("Hostname could not be resolved.")
        return

    open_ports = []
    for port in range(start_port, end_port + 1):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        result = sock.connect_ex((ip, port))
        sock.close()
        if result == 0:
            print(f"Port {port} is open")
            open_ports.append(port)

    if not open_ports:
        print("No open ports found.")
    else:
        print(f"Open ports: {open_ports}")

def ping(host):
    system = platform.system()
    param = '-n' if system == 'Windows' else '-c'
    command = ['ping', param, '1', host]
    try:
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return result.returncode == 0
    except Exception:
        return False

def banner_grab(host, port):
    print(f"Grabbing banner from {host}:{port}...")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        sock.connect((host, port))
        sock.send(b'\r\n')
        banner = sock.recv(1024).decode(errors='ignore').strip()
        print(f"Banner:\n{banner}")
        sock.close()
    except Exception as e:
        print(f"Banner grab failed: {e}")

def os_detection(host):
    print(f"Attempting OS detection for {host}...")
    system = platform.system()
    try:
        if system == "Windows":
            cmd = ['ping', '-n', '1', host]
        else:
            cmd = ['ping', '-c', '1', host]
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        output = result.stdout.lower()
        if 'ttl=' in output:
            ttl_line = [line for line in output.split('\n') if 'ttl=' in line]
            if ttl_line:
                ttl_value = int(ttl_line[0].split('ttl=')[1].split()[0])
                if ttl_value >= 128:
                    print("Likely Windows OS (TTL >= 128)")
                elif ttl_value >= 64:
                    print("Likely Linux/Unix OS (TTL >= 64)")
                else:
                    print("OS could not be confidently determined from TTL")
            else:
                print("TTL info not found in ping response.")
        else:
            print("TTL info not found in ping response.")
    except Exception as e:
        print(f"OS detection failed: {e}")

def check_services(host):
    services = {
        21: "FTP",
        22: "SSH/SFTP",
        23: "Telnet",
        445: "SMB"
    }

    print(f"\nChecking common services on {host}...\n")

    for port, name in services.items():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((host, port))
            if result == 0:
                print(f"[+] {name} ({port}) is OPEN")
                try:
                    sock.send(b'\r\n')
                    banner = sock.recv(1024).decode(errors='ignore').strip()
                    if banner:
                        print(f"    ↳ Banner: {banner}")
                except:
                    print("    ↳ No banner received.")
            else:
                print(f"[-] {name} ({port}) is CLOSED or FILTERED")
            sock.close()
        except Exception as e:
            print(f"[!] Error checking {name} ({port}): {e}")

def network_scanner():
    base_ip = input("Enter subnet (e.g., 192.168.1): ")
    print(f"Scanning {base_ip}.1 to {base_ip}.254...")

    def scan(ip):
        if ping(ip):
            print(f"[+] Active: {ip}")

    threads = []
    for i in range(1, 255):
        ip = f"{base_ip}.{i}"
        t = threading.Thread(target=scan, args=(ip,))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

def generate_strong_password(length=16):
    if length < 12:
        print("Warning: Length is short; consider 12+ for better security.")
    lower = string.ascii_lowercase
    upper = string.ascii_uppercase
    digits = string.digits
    symbols = string.punctuation
    all_chars = lower + upper + digits + symbols
    password = [
        secrets.choice(lower),
        secrets.choice(upper),
        secrets.choice(digits),
        secrets.choice(symbols)
    ]
    password += [secrets.choice(all_chars) for _ in range(length - 4)]
    random.shuffle(password)
    return ''.join(password)

def check_ssl_cert(hostname):
    port = 443
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                print("\n🔒 SSL Certificate Info:")
                print(f"  - Common Name (CN): {cert['subject'][0][0][1]}")
                print(f"  - Issuer: {cert['issuer'][0][0][1]}")
                print(f"  - Valid From: {cert['notBefore']}")
                print(f"  - Valid Until: {cert['notAfter']}")
                expiry_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z').replace(tzinfo=UTC)
                if expiry_date < datetime.now(UTC):
                    print("  - ⚠️ Certificate has EXPIRED!")
                else:
                    print("  - ✅ Certificate is valid.")
    except Exception as e:
        print(f"[!] SSL certificate check failed: {e}")

def check_smtp_server(host, port=25, use_tls=False):
    try:
        print(f"Connecting to SMTP server {host}:{port} {'with TLS' if use_tls else ''}...")
        server = smtplib.SMTP(host, port, timeout=5)
        server.ehlo()
        if use_tls:
            server.starttls()
            server.ehlo()
        banner = server.noop()  # Basic command to keep it alive
        print(f"SMTP connection successful, NOOP response: {banner}")
        server.quit()
    except Exception as e:
        print(f"[!] SMTP check failed: {e}")

def ip_calculator():
    try:
        cidr_input = input("Enter IP address with CIDR (e.g., 192.168.1.10/24): ").strip()
        network = ipaddress.ip_network(cidr_input, strict=False)

        print("\n📡 IP Calculator Results:")
        print(f"  ➤ Network Address : {network.network_address}")
        print(f"  ➤ Broadcast Address: {network.broadcast_address}")
        print(f"  ➤ Subnet Mask     : {network.netmask}")
        print(f"  ➤ Wildcard Mask   : {ipaddress.IPv4Address(int(network.hostmask))}")
        print(f"  ➤ Total Hosts     : {network.num_addresses - 2 if network.prefixlen < 31 else network.num_addresses}")
        print(f"  ➤ First Usable IP : {list(network.hosts())[0] if network.prefixlen < 31 else 'N/A'}")
        print(f"  ➤ Last Usable IP  : {list(network.hosts())[-1] if network.prefixlen < 31 else 'N/A'}")
        print(f"  ➤ Prefix Length   : /{network.prefixlen}")
    except ValueError as e:
        print(f"[!] Invalid input: {e}")

# ----------- User Input -----------
tool = int(input('Pick your tool (1-18): '))

# ----------- Logic -----------
if tool in [1, 2, 3, 4, 5, 6, 7]:
    target = input('Enter URL/IP: ')
    url_map = {
        1: "dnslookup",
        2: "reversedns",
        3: "geoip",
        4: "reverseiplookup",
        5: "httpheaders",
        6: "pagelinks",
        7: "aslookup"
    }
    url = f"https://api.hackertarget.com/{url_map[tool]}/?q={target}"
    main(url)
elif tool in [8, 9, 10, 11, 12, 14]:
    target = input('Enter Host/IP: ')
    if tool == 8:
        traceroute(target)
    elif tool == 9:
        port_scanner(target)
    elif tool == 10:
        if ping(target):
            print(f"{target} is reachable.")
        else:
            print(f"{target} is not responding.")
    elif tool == 11:
        port = int(input("Enter port to grab banner from: "))
        banner_grab(target, port)
    elif tool == 12:
        os_detection(target)
    elif tool == 14:
        check_services(target)
elif tool == 13:
    network_scanner()
elif tool == 15:
    length = int(input("Enter password length (min 12): "))
    password = generate_strong_password(length)
    print("Generated Password:", password)
elif tool == 16:
    target = input('Enter domain (e.g., example.com): ')
    check_ssl_cert(target)
elif tool == 17:
    host = input("Enter SMTP Host/IP: ")
    port = int(input("Enter SMTP Port (e.g., 25, 465, 587): "))
    tls = input("Use TLS? (yes/no): ").strip().lower() == 'yes'
    check_smtp_server(host, port, use_tls=tls)
elif tool == 18:
    ip_calculator()
else:
    print("Invalid tool number.")
