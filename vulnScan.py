import socket
import requests
import ssl
from OpenSSL import crypto
from argparse import ArgumentParser


def scan_ports(target, ports):
    open_ports = []
    for port in ports:
        try:
            sock = socket.create_connection((target, port), timeout=3) 
            open_ports.append(port)
            sock.close()
        except:
            continue
    return open_ports


def check_http_status(url):
    try:
        response = requests.get(url)
        return response.status_code
    except requests.exceptions.RequestException as e:
        print(f"Error with URL {url}: {e}")
        return None


def banner_grabbing(target, ports):
    banner_info = {}
    for port in ports:
        try:
            # Try banner grabbing with HTTP (GET request)
            if port == 80 or port == 443:
                url = f"http://{target}:{port}" if port == 80 else f"https://{target}:{port}"
                response = requests.get(url, timeout=3)
                banner_info[port] = {
                    'Server': response.headers.get('Server', 'N/A'),
                    'Date': response.headers.get('Date', 'N/A'),
                    'Content-Type': response.headers.get('Content-Type', 'N/A'),
                    'X-Powered-By': response.headers.get('X-Powered-By', 'N/A')
                }
            else:
                # For non-HTTP ports, use socket to grab banners
                sock = socket.create_connection((target, port), timeout=3)
                banner = sock.recv(1024).decode('utf-8', errors='ignore')
                banner_info[port] = banner.strip()
                sock.close()
        except:
            continue
    return banner_info


def ssl_certificate_check(url):
    # Remove 'https://' or 'http://' prefix from the URL
    if url.startswith('https://'):
        url = url[8:]  # Remove 'https://'
    elif url.startswith('http://'):
        url = url[7:]  # Remove 'http://'

    try:
        context = ssl.create_default_context()
        with context.wrap_socket(socket.socket(), server_hostname=url) as s:
            s.connect((url, 443))
            cert = s.getpeercert()
            if cert:
                return cert
            else:
                return None
    except Exception as e:
        print(f"Error with SSL certificate for {url}: {e}")
        return None


def scan_vulnerabilities(target):

    common_ports = [21, 22, 23, 25, 53, 80, 443, 8080, 3306, 3389]

    print(f"Scanning {target}...\n")

    open_ports = scan_ports(target, common_ports)
    if open_ports:
        print(f"Open ports on {target}: {open_ports}")
    else:
        print(f"No open ports found on {target}.")


    if target.startswith('http'):
        status_code = check_http_status(target)
        if status_code:
            print(f"HTTP Status Code for {target}: {status_code}")
        else:
            print(f"Could not fetch status code for {target}.")


    banners = banner_grabbing(target, open_ports)
    if banners:
        print("Banner Information:")
        for port, banner in banners.items():
            print(f"Port {port}: {banner}")


    if target.startswith('https'):
        cert = ssl_certificate_check(target)
        if cert:
            print("SSL Certificate Details:")
            print(cert)
        else:
            print(f"SSL Certificate check failed for {target}.")


if __name__ == "__main__":
   
    parser = ArgumentParser(description="Basic Vulnerability Scanner")
    parser.add_argument("target", help="Target URL or IP address to scan")
    args = parser.parse_args()


    scan_vulnerabilities(args.target)