'''
Initial Code : K.A.Draziotis (Nov.2024)
Licence : GPL v3
'''
import sys
import socket
import ssl
import subprocess
import certifi
import http.client
from urllib.parse import urlparse
import subprocess
import platform

def is_port_open(host, port, timeout=5):
    """Returns True if the specified port is open, False otherwise."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return 1 # true
    except (socket.timeout, socket.error):
        return 0 # false

def get_headers_info(url,port):
    """
    Retrieves and prints header information from a given URL.

    Args:
        url (str): The URL to connect to, including the port if necessary (e.g., 'commodore.csd.auth.gr:8888').

    Returns:
        None
    """
    # Ensure the URL has a scheme
    if not url.startswith(('http://', 'https://')):
        url = "https://" + url + ":" + str(port) # Default to HTTPS
    print(url,"\n")
    print("Header Information")
    print("===================")

    parsed_url = urlparse(url)
    hostname = parsed_url.hostname
    port = parsed_url.port if parsed_url.port else (443 if parsed_url.scheme == "https" else 80)
    path = parsed_url.path if parsed_url.path else '/'
    timeout = 2 
    try:
        if parsed_url.scheme == "https":
            # Create an SSL context using certifi for certificate verification
            context = ssl.create_default_context(cafile=certifi.where())

            # Establish HTTPS connection with the specified port
            conn = http.client.HTTPSConnection(hostname, port=port, context=context)
        else:
            # Establish HTTP connection with the specified port
            conn = http.client.HTTPConnection(hostname, port=port)

        # Connect to the server

        conn.connect()
        print(f"Connected to {hostname}:{port}")
    
        if parsed_url.scheme == "https":
            # Access the underlying SSL socket to get SSL details
            sock = conn.sock
            ssl_version = sock.version()
            cipher = sock.cipher()
            print(f"SSL Version: {ssl_version}")
            print(f"Cipher Suite: {cipher}")

        # Send HEAD request
        conn.request("HEAD", path)
        response = conn.getresponse()

        # Print response headers
        headers = response.getheaders()
        for header, value in headers:
            if header.lower() == 'expires':
                value = ''  # Optionally hide the 'Expires' header
            print(f"{header}: {value}")

    except ssl.SSLError as e:
        print(f"SSL error occurred: {e}")
    except socket.error as e:
        print(f"Socket error occurred: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

    except socket.timeout:
        print(f"Error: Connection to {hostname}:{port} timed out after {timeout} seconds.")
        return  # Exit function immediately

    except (socket.gaierror, socket.timeout):
        print(f"Error: Unable to reach {hostname}:{port}. The server may be down or unreachable.")
        return  # Exit function immediately

    finally:
        try:
            conn.close()
        except:
            pass

# if __name__ == "__main__":
#     # Replace with your server's hostname and port
#test_url,port = 'commodore.csd.auth.gr',8889  # Ensure the port is specified
#get_headers_info(test_url,port)


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: python3 heartbleed.py [ip_address] [port_number]")
        sys.exit(1)
    host = sys.argv[1]

    # If the port argument isn't provided, default to 443.
    if len(sys.argv) < 3 or not sys.argv[2]:
        port = 443
    else:
        port = int(sys.argv[2])
    #host, port = args.host, args.port
    open_port = is_port_open(host, port, timeout=3)
    if open_port==0:
        print(f"Can not connect to {host}:{port}")
        sys.exit(1)
    else:
        get_headers_info(host,port)
    
if __name__ == "__main__":
    main()

