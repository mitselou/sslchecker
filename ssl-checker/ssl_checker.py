from __future__ import annotations

import argparse
import logging
import re
import subprocess
from pprint import pprint

from cryptography import x509

OPENSSL_PROTOCOL_FLAG_RE = re.compile(
    r"^\s*-(?P<protocol>(?:ssl|tls)[1-9_]+\b)", re.MULTILINE
)


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
    parser = argparse.ArgumentParser(
        description="Checks which of the installed SSL versions and which ciphers a server supports"
    )
    parser.add_argument("--host", required=True)
    parser.add_argument("-p", "--port", type=int, default=443)
    args = parser.parse_args()
    host, port = args.host, args.port
    supported, unsupported = get_supported_protocol_cipher_combinations(host, port)
    print("Supported:")
    pprint(supported)
    print("\n\nUnsupported:")
    pprint(unsupported)


if __name__ == "__main__":
    main()
