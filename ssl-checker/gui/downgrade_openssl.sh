#!/bin/bash

# This script was taken from https://gist.github.com/bmaupin/8caca3a1e8c3c5686141 and slightly modified

# Cache sudo password
sudo -v
# Get latest OpenSSL 1.0.2 version from https://openssl.org/source/
# v1.1.0 seems to have removed SSLv2/3 support
# Keep in mind this version does not have TLS 1.3 support
openssl_version=1.0.2u

# Install build dependencies
sudo apt -y install build-essential

# Download and build OpenSSL
wget --no-check-certificate "https://openssl.org/source/openssl-$openssl_version.tar.gz"
tar -xvf "openssl-$openssl_version.tar.gz"
cd "openssl-$openssl_version"
# --prefix will make sure that make install copies the files locally instead of system-wide
# --openssldir will make sure that the binary will look in the regular system location for openssl.cnf
# no-shared builds a mostly static binary
./config --prefix="$(pwd)/local" --openssldir=/usr/lib/ssl enable-ssl2 enable-ssl3 no-shared
make depend
make
sudo make install

# Install just the binary so we can use s_client -ssl2
mkdir -p "$HOME/bin"
sudo cp local/bin/openssl "$HOME/bin/"

# Cleanup
cd ..
rm -rf "openssl-$openssl_version"
rm "openssl-$openssl_version.tar.gz"

# (Optional) start a new login shell (to add $HOME/bin to the path, if necessary)
bash -l

# To test:
# $ openssl s_client -connect google.com:443 -ssl2 >/dev/null
# 139675635414688:error:1407F0E5:SSL routines:ssl2_write:ssl handshake failure:s2_pkt.c:412:
# $ openssl s_client -connect google.com:443 -ssl3 >/dev/null
# 140647504119456:error:1408F10B:SSL routines:SSL3_GET_RECORD:wrong version number:s3_pkt.c:365:
