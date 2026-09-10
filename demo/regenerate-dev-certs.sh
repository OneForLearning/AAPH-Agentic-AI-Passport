#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
command -v openssl >/dev/null 2>&1 || { echo "OpenSSL is required." >&2; exit 1; }
config="demo/openssl-dev.cnf"
output="dev-certs"
temporary="$(mktemp -d)"
trap 'rm -rf "$temporary"' EXIT
mkdir -p "$output"
openssl req -x509 -newkey rsa:3072 -nodes -sha256 -days 30 -keyout "$temporary/ca.key" -out "$temporary/ca.crt" -config "$config" -extensions v3_ca
service="aaph-server"
openssl req -newkey rsa:3072 -nodes -sha256 -keyout "$temporary/$service.key" -out "$temporary/$service.csr" -subj "/CN=$service"
openssl x509 -req -sha256 -days 30 -in "$temporary/$service.csr" -CA "$temporary/ca.crt" -CAkey "$temporary/ca.key" -CAserial "$temporary/ca.srl" -CAcreateserial -out "$temporary/$service.crt" -extfile "$config" -extensions aaph_server
install -m 0644 "$temporary/ca.crt" "$output/ca.crt"
install -m 0600 "$temporary/ca.key" "$output/ca.key"
install -m 0644 "$temporary/$service.crt" "$output/$service.crt"
install -m 0600 "$temporary/$service.key" "$output/$service.key"
echo "NON_PRODUCTION_DEMO CA and aaph-server certificate regenerated."
