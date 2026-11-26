#!/bin/sh
# GreenMail reads a PKCS #12 keystore; build one from the test CA's server certificate.
set -eu
openssl pkcs12 -export -in /certs/tls.crt -inkey /certs/tls.key -out /tmp/it.p12 \
  -passout pass:it-keystore -name greenmail
exec /home/greenmail/run_greenmail.sh
