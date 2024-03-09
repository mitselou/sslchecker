## Installing Dependencies

To install the dependencies run `pip install -r requirements.txt`.

## ssl_checker.py

Example using the Command Line Interface (CLI) script `ssl_checker.py` :
```sh
$ python3 ssl_checker.py --help
usage: ssl_checker.py [-h] --host HOST [-p PORT]

Checks which of the installed SSL versions and which ciphers a server supports

options:
  -h, --help       show this help message and exit
  --host HOST
  -p, --port PORT
```
```sh
$ python3 ssl_checker.py --host www.csd.auth.gr
Supported:
{('tls1_2', 'ECDHE-RSA-AES128-GCM-SHA256'): <Certificate(subject=<Name(CN=www.csd.auth.gr)>, ...)>,
 ('tls1_2', 'ECDHE-RSA-AES256-GCM-SHA384'): <Certificate(subject=<Name(CN=www.csd.auth.gr)>, ...)>,
 ('tls1_2', 'ECDHE-RSA-CHACHA20-POLY1305'): <Certificate(subject=<Name(CN=www.csd.auth.gr)>, ...)>}


Unsupported:
[('tls1', 'TLS_AES_256_GCM_SHA384'),
 ('tls1_1', 'TLS_AES_256_GCM_SHA384'),
 ('tls1_2', 'TLS_AES_256_GCM_SHA384'),
...
```

## ssl_checker_gui.py

To run using the Graphical User Interface (GUI) script, `ssl_checker_gui.py`:
```sh
$ python3 ssl_checker_gui.py
```

![GUI](../examples/demo_google.png)

## Install an older OpenSSL version (optional)

```
⚠️⚠️⚠️
Note: Do not downgrade your OpenSSL installation outside of a temporary throwaway environment
⚠️⚠️⚠️
```

Most modern Operating Systems have an new versions of OpenSSL that no longer support SSLv2/SSLv3.

This is fine if we only are interested in only testing the newer protocols however it means we cannot test the older protocols.

To remedy this we can download and install an older version of OpenSSL by running `./downgrade_openssl.sh` but do be aware that installing older versions might mean you won't have access to the newer protocols.

## Sample list of hosts to test the SSL/TSL Checker with.

These servers were obtained with [shodan](https://www.shodan.io/), however there is **no guarantee that the information about them has not changed since they were added**.

Also, please keep in mind that the information on shodan _**may**_ be itself be outdated and should not be taken at face value, but should be cross referenced with other checkers.

- server8.ascat.de:443 - SSL2/SSL3/TLS1
