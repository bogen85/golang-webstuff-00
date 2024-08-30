#!/usr/bin/env bash

set -euo pipefail

store=~/etc/cert-authority
cert=$store/zzz_teegra00_ca_cert.pem
key=$store/zzz_teegra00_ca_key.pem

set -x
openssl x509 -in $cert -text -noout
openssl ec -in $key -text -noout
