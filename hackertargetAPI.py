import urllib.request
import subprocess
import platform
import socket
import ipaddress
import threading

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

# ----------- User Input -----------
tool = int(input('Pick your tool (1-14): '))

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
else:
    print("Invalid tool number.")
