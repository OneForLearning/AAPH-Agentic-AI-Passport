"""One-shot internal recovery client for the non-production Docker demo."""
import json
import os
import ssl
from urllib.parse import urlsplit

import httpx

secret = os.environ.get("AAPH_ADMIN_SECRET")
if not secret:
    raise SystemExit("AAPH_ADMIN_SECRET is required")
admin_url = os.environ.get("AAPH_ADMIN_URL", "https://localhost:3002").rstrip("/")
ca_cert = os.environ.get("AAPH_TLS_CA_CERT", "/run/certs/ca.crt")
instance_id = os.environ.get("AAPH_INSTANCE_ID", "demo-instance")
parsed = urlsplit(admin_url)
if parsed.scheme != "https" or not parsed.netloc or parsed.path or parsed.query or parsed.fragment:
    raise SystemExit("AAPH_ADMIN_URL must be an HTTPS origin")

response = httpx.post(
    f"{admin_url}/v1/admin/instances/{instance_id}/recovery",
    headers={"x-aaph-admin-secret": secret},
    json={"validation": True},
    verify=ssl.create_default_context(cafile=ca_cert),
    timeout=5.0,
)
response.raise_for_status()
print(json.dumps(response.json(), sort_keys=True))
