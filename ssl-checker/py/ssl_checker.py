from __future__ import annotations

import sys
import socket
import argparse
import logging
import re
import subprocess
from pprint import pprint

from cryptography import x509

OPENSSL_PROTOCOL_FLAG_RE = re.compile(
    r"^\s*-(?P<protocol>(?:ssl|tls)[1-9_]+\b)", re.MULTILINE
)

def is_port_open(host, port, timeout=5):
    """Returns True if the specified port is open, False otherwise."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return 1 # true
    except (socket.timeout, socket.error):
        return 0 # false


def get_openssl_version() -> str:
    cmd = ["openssl", "version"]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    return proc.stdout.strip()


def get_available_protocols() -> list[str]:
    cmd = ["openssl", "s_client", "--help"]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    help_str = proc.stderr.strip()
    return OPENSSL_PROTOCOL_FLAG_RE.findall(help_str)


def get_certificate(
    host: str, port: int, cipher: str, protocol_version: str
) -> x509.Certificate | None:
    logging.debug(
        "Trying combination: addr=%s:%s protocol=%s cipher=%s",
        host,
        port,
        protocol_version,
        cipher,
    )
    #print(protocol_version)
    if protocol_version=='tls1_3':
        conn_cmd = [
        "openssl",
        "s_client",
        "-ciphersuites",
        cipher,
        f"-{protocol_version}",
        "-servername",
        host,
        "-connect",
        f"{host}:{port}",
    ]
    else:
        conn_cmd = [
        "openssl",
        "s_client",
        "-cipher",
        cipher,
        f"-{protocol_version}",
        "-servername",
        host,
        "-connect",
        f"{host}:{port}",
    ]

    conn_proc = subprocess.run(conn_cmd, stdin=subprocess.DEVNULL, capture_output=True)
    if conn_proc.returncode != 0:
        logging.debug(
            "Unsupported: addr=%s:%s protocol=%s cipher=%s",
            host,
            port,
            protocol_version,
            cipher,
        )
        return None

    logging.debug(
        "Supported: addr=%s:%s protocol=%s cipher=%s",
        host,
        port,
        protocol_version,
        cipher,
    )
    x509_cmd = ["openssl", "x509"]
    x509_proc = subprocess.run(x509_cmd, input=conn_proc.stdout, capture_output=True)
    if x509_proc.returncode != 0:
        logging.error(
            "Failed to extract the certificate: addr=%s:%s protocol=%s cipher=%s",
            host,
            port,
            protocol_version,
            cipher,
        )
        return None
    return x509.load_pem_x509_certificate(x509_proc.stdout)


def get_supported_protocol_cipher_combinations(
    host: str, port: int
) -> tuple[dict[tuple[str, str], x509.Certificate], list[tuple[str, str]]]:
    supported_ciphers = {}
    unsupported_ciphers = []

    cmd = ["openssl", "ciphers", "ALL:eNULL"]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    ciphers_str = proc.stdout.strip()
    ciphers = [cipher for cipher in ciphers_str.split(":")]

    available_protocols = get_available_protocols()
    for cipher in ciphers:
        for protocol_version in available_protocols:
            cert = get_certificate(host, port, cipher, protocol_version)
            if cert is not None:
                supported_ciphers[(protocol_version, cipher)] = cert
            else:
                unsupported_ciphers.append((protocol_version, cipher))
    return supported_ciphers, unsupported_ciphers


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
        # [1]
        import headers_info as hi
        hi.get_headers_info(host,port)

        # [2]
        print("\n")
        print("Certificate Metadata")
        print("===================")
        import certificate_metadata as cm
        cm.getCertificateDetails(str(host),port)


        # [3]
        print("\n")
        print("Supported Ciphers")
        print("===================")
        supported, unsupported = get_supported_protocol_cipher_combinations(host, port)
        print("Supported:")
        pprint(supported)

        # [4]
        print("\n")
        print("heartbleed check")
        print("===================")
        import heartbleed as heart
        sock = heart.connect(host, port)
        version = "TLSv1.3"
        ch = heart.constructClientHello(heart.versions.get(version))
        server_version, message_type = heart.sendClientHello(sock, ch)
        server_version_1 = heart.tls_version_from_number(server_version)
       
        # Keep reading the server's messages until it sends a ServerHelloDone message
        while True:
            t, v, p = heart.getResponse(sock)
            if t is None:
                print('Server closed connection without sending ServerHello.')
                sys.exit()
            if t == 22 and p[0] == 0x0E:    # ServerHelloDone message
                break


        # Create and send a Heartbeat message & then read the server's response
        hb = heart.constructHeartbeat(server_version & 0xFF)
        print('Heartbeat constructed.')
        #print(hb)
        #print()
        response = heart.sendHeartbeat(sock, hb)
     
    
if __name__ == "__main__":
    main()
