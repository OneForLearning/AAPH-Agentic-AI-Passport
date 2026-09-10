#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

for command in cargo openssl; do
  command -v "$command" >/dev/null 2>&1 || {
    echo "Required command not found: $command" >&2
    exit 1
  }
done

if [[ -e local-keys || -e dev-certs ]]; then
  echo "Refusing to overwrite local-keys or dev-certs." >&2
  echo "Remove only those demo directories after inspecting them, then rerun this script." >&2
  exit 1
fi

cargo run --locked -q -p aaph-core --bin aaph-keygen -- local-keys/authority
cargo run --locked -q -p aaph-core --bin aaph-keygen -- local-keys/agent
mkdir -p demo-data/output
bash demo/regenerate-dev-certs.sh
chmod 600 local-keys/authority/signing.key local-keys/agent/signing.key
echo "NON_PRODUCTION_DEMO Docker keys and certificates are ready."
