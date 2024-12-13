'''
Initial Code : K.A.Draziotis (Nov.2024)
Licence : GPL v3
'''
import socket
import ssl
import subprocess
from datetime import datetime, timezone
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, ec
import certifi


# Get details of the server's certificate
def getCertificateDetails(hostname, port):
    sock = None
    ssl_socket = None

    context = ssl.create_default_context(cafile=certifi.where())

    # Try and create a secure connection
    try:
        sock = socket.create_connection((hostname, port))
        ssl_socket = context.wrap_socket(sock, server_hostname=hostname)
        # Retrieve the binary DER-encoded form of the server's certificate
        bin_cert = ssl_socket.getpeercert(True)

        # Load a certificate from its binary DER format into a more usable Python object
        cert = x509.load_der_x509_certificate(bin_cert, default_backend())

        # Get the public key and check if it's an RSA key. If it is, print information.
        key = cert.public_key()
        if isinstance(key, rsa.RSAPublicKey):
            key_type = 'RSA'
        elif isinstance(key, ec.EllipticCurvePublicKey):
            key_type = 'EC'
        else:
            key_type = 'Unknown'

        print(f"Key type: {key_type}")
        print(f"Key size: {key.key_size}")
        print(f"Serial number: {cert.serial_number}")

        subject = cert.subject
        for component in subject:
            print(f"{component.oid._name}: {component.value}")

        issuer = cert.issuer
        cn_attributes = issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)  # the Common Name (CN) of the issuer

        # Technically, there can be multiple CN entries, thus iterate through them (usually there's just one)
        for attribute in cn_attributes:
            print(f"Issued by: {attribute.value}")

        # Expiration date details
        expire_date = cert.not_valid_after_utc
        print(f'Valid until (UTC time): {expire_date}')
        # The cert.not_valid_after_utc property from a certificate returns the expiration date and time in UTC.
        # The datetime.now() method returns the current local date and time without any timezone information.
        # To avoid any problems, use datetime.now(timezone.utc) to get the current date and time in UTC.
        expires_in = expire_date - datetime.now(timezone.utc)

        if expires_in.days >= 0:
            print(f'Expires in {expires_in.days} days')
        else:
            print('Certificate expired.')

        # Export the RSA modulus and public exponent (if RSA)
        if key_type == 'RSA':
            numbers = key.public_numbers()
            print(f"RSA modulus N: {numbers.n}")
            print(f"e: {numbers.e}")

    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        if ssl_socket:
            ssl_socket.close()  # It also closes the underlying sock.
        elif sock:
            # If ssl_socket was never created, just close sock.
            sock.close()
    return

test_url,port = 'commodore.csd.auth.gr',8889  # Ensure the port is specified
getCertificateDetails(test_url,port)