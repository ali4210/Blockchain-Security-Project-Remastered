#!/usr/bin/env python3
import subprocess
import secrets
import hashlib
import os
import bcrypt

USER_EMAIL = "saleemali.mohammad@gmail.com"
USER_NAME = "Saleem Ali"
# Never a fixed, committed password: use LANGFUSE_ADMIN_PASSWORD if an operator
# set one, else generate a fresh random one each bootstrap, same as the
# PUBLIC_KEY/SECRET_KEY pair below -- written only to the untracked
# config/.langfuse.env, never to source.
RAW_PASSWORD = os.environ.get("LANGFUSE_ADMIN_PASSWORD") or secrets.token_urlsafe(16)
PROJECT_NAME = "blockchain-soc-swarm"
ORG_NAME = "Autonomous Blockchain SOC"

# Generate Langfuse API Key pair
PUBLIC_KEY = f"pk-lf-{secrets.token_hex(16)}"
SECRET_KEY = f"sk-lf-{secrets.token_hex(16)}"
HASHED_SK = hashlib.sha256(SECRET_KEY.encode()).hexdigest()

USER_ID = f"usr_{secrets.token_hex(12)}"
ORG_ID = f"org_{secrets.token_hex(12)}"
PROJECT_ID = f"prj_{secrets.token_hex(12)}"
API_KEY_ID = f"key_{secrets.token_hex(12)}"
PWD_HASH = bcrypt.hashpw(RAW_PASSWORD.encode(), bcrypt.gensalt()).decode()

sql_commands = f"""
INSERT INTO users (id, name, email, password, "createdAt", "updatedAt")
VALUES ('{USER_ID}', '{USER_NAME}', '{USER_EMAIL}', '{PWD_HASH}', NOW(), NOW())
ON CONFLICT (email) DO UPDATE SET password = '{PWD_HASH}'
RETURNING id;

INSERT INTO organizations (id, name, "createdAt", "updatedAt")
VALUES ('{ORG_ID}', '{ORG_NAME}', NOW(), NOW())
ON CONFLICT DO NOTHING;

INSERT INTO organization_memberships ("userId", "orgId", role, "createdAt", "updatedAt")
VALUES ('{USER_ID}', '{ORG_ID}', 'ADMIN', NOW(), NOW())
ON CONFLICT DO NOTHING;

INSERT INTO projects (id, name, "orgId", "createdAt", "updatedAt")
VALUES ('{PROJECT_ID}', '{PROJECT_NAME}', '{ORG_ID}', NOW(), NOW())
ON CONFLICT DO NOTHING;

INSERT INTO project_memberships ("userId", "projectId", role, "createdAt", "updatedAt")
VALUES ('{USER_ID}', '{PROJECT_ID}', 'ADMIN', NOW(), NOW())
ON CONFLICT DO NOTHING;

INSERT INTO api_keys (id, "publicKey", "hashedSecretKey", "projectId", "createdAt", "updatedAt")
VALUES ('{API_KEY_ID}', '{PUBLIC_KEY}', '{HASHED_SK}', '{PROJECT_ID}', NOW(), NOW())
ON CONFLICT DO NOTHING;
"""

print("[*] Bootstrapping Langfuse User & Swarm Project directly in Postgres...")
proc = subprocess.run(
    ["docker", "exec", "-i", "langfuse-postgres", "psql", "-U", "postgres", "-d", "langfuse"],
    input=sql_commands,
    text=True,
    capture_output=True
)

if proc.returncode != 0:
    print(f"[-] Postgres Error: {proc.stderr}")
else:
    print("[+] Langfuse DB seeded successfully!")
    
    os.makedirs("config", exist_ok=True)
    env_content = f"""# Autonomous Blockchain SOC - Langfuse Observability Config
LANGFUSE_PUBLIC_KEY="{PUBLIC_KEY}"
LANGFUSE_SECRET_KEY="{SECRET_KEY}"
LANGFUSE_HOST="http://127.0.0.1:3100"
LANGFUSE_USER_EMAIL="{USER_EMAIL}"
LANGFUSE_PASSWORD="{RAW_PASSWORD}"
"""
    with open("config/.langfuse.env", "w") as fp:
        fp.write(env_content)
    
    print("[+] Configuration saved to config/.langfuse.env:")
    print(f"    -> Public Key: {PUBLIC_KEY}")
    print(f"    -> Secret Key: {SECRET_KEY[:8]}************************")
    print(f"    -> Web UI Login: {USER_EMAIL} | {RAW_PASSWORD}")

if __name__ == "__main__":
    pass
