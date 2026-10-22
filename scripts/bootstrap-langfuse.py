#!/usr/bin/env python3
import subprocess
import secrets
import uuid
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

# Generate Langfuse API Key pair (langfuse's own generateKeySet() uses this
# same pk-lf-<uuid>/sk-lf-<uuid> shape).
PUBLIC_KEY = f"pk-lf-{uuid.uuid4()}"
SECRET_KEY = f"sk-lf-{uuid.uuid4()}"

# Langfuse verifies keys via fastHashedSecretKey = createShaHash(secretKey, SALT)
# (packages/shared/src/server/auth/apiKeys.ts): sha256(secretKey + sha256(SALT).hexdigest()).
# hashedSecretKey (legacy bcrypt column) only matters for pre-fast-hash keys;
# new keys get a non-matching placeholder there, per Langfuse's own
# createLegacySecretKeyPlaceholder(). Read SALT from the live container
# rather than hardcode it, so this still works if the deployment regenerates
# with a different salt.
_salt_proc = subprocess.run(["docker", "exec", "langfuse-server", "printenv", "SALT"],
                            capture_output=True, text=True)
LANGFUSE_SALT = _salt_proc.stdout.strip()
if not LANGFUSE_SALT:
    raise SystemExit("[-] Could not read SALT from the langfuse-server container; is it running?")
_salt_hash = hashlib.sha256(LANGFUSE_SALT.encode("utf-8")).hexdigest()
FAST_HASHED_SK = hashlib.sha256((SECRET_KEY + _salt_hash).encode("utf-8")).hexdigest()
LEGACY_HASHED_SK_PLACEHOLDER = f"unused:{uuid.uuid4()}"
DISPLAY_SK = SECRET_KEY[:6] + "..." + SECRET_KEY[-4:]

USER_ID = f"usr_{secrets.token_hex(12)}"
ORG_ID = f"org_{secrets.token_hex(12)}"
ORG_MEMBERSHIP_ID = f"orgmem_{secrets.token_hex(12)}"
PROJECT_ID = f"prj_{secrets.token_hex(12)}"
API_KEY_ID = f"key_{secrets.token_hex(12)}"
PWD_HASH = bcrypt.hashpw(RAW_PASSWORD.encode(), bcrypt.gensalt()).decode()

# Real snake_case columns (confirmed via \d against the live schema -- this
# Langfuse version is past the old Prisma camelCase column names the
# previous version of this script used, which meant every one of these
# INSERTs had been silently failing since this script's first commit).
sql_commands = f"""
INSERT INTO users (id, name, email, password, created_at, updated_at)
VALUES ('{USER_ID}', '{USER_NAME}', '{USER_EMAIL}', '{PWD_HASH}', NOW(), NOW())
ON CONFLICT (email) DO UPDATE SET password = '{PWD_HASH}'
RETURNING id;

INSERT INTO organizations (id, name, created_at, updated_at)
VALUES ('{ORG_ID}', '{ORG_NAME}', NOW(), NOW())
ON CONFLICT DO NOTHING;

-- user_id is looked up by email, not trusted from {USER_ID}: ON CONFLICT (email)
-- DO UPDATE above keeps the EXISTING row's id untouched when the user already
-- exists, so the freshly generated id would otherwise never match any real row.
INSERT INTO organization_memberships (id, org_id, user_id, role, created_at, updated_at)
SELECT '{ORG_MEMBERSHIP_ID}', '{ORG_ID}', u.id, 'ADMIN', NOW(), NOW()
FROM users u WHERE u.email = '{USER_EMAIL}'
ON CONFLICT (org_id, user_id) DO NOTHING;

INSERT INTO projects (id, name, org_id, created_at, updated_at)
VALUES ('{PROJECT_ID}', '{PROJECT_NAME}', '{ORG_ID}', NOW(), NOW())
ON CONFLICT DO NOTHING;

-- Same reasoning for org_membership_id: look it up by (org_id, user_id)
-- instead of trusting {ORG_MEMBERSHIP_ID}, which won't match an
-- already-existing membership row either.
INSERT INTO project_memberships (project_id, user_id, org_membership_id, role, created_at, updated_at)
SELECT '{PROJECT_ID}', u.id, om.id, 'ADMIN', NOW(), NOW()
FROM users u
JOIN organization_memberships om ON om.user_id = u.id AND om.org_id = '{ORG_ID}'
WHERE u.email = '{USER_EMAIL}'
ON CONFLICT (project_id, user_id) DO NOTHING;

INSERT INTO api_keys (id, public_key, hashed_secret_key, fast_hashed_secret_key, display_secret_key, project_id, created_at)
VALUES ('{API_KEY_ID}', '{PUBLIC_KEY}', '{LEGACY_HASHED_SK_PLACEHOLDER}', '{FAST_HASHED_SK}', '{DISPLAY_SK}', '{PROJECT_ID}', NOW())
ON CONFLICT DO NOTHING;
"""

print("[*] Bootstrapping Langfuse User & Swarm Project directly in Postgres...")
proc = subprocess.run(
    ["docker", "exec", "-i", "langfuse-postgres", "psql", "-v", "ON_ERROR_STOP=1",
     "-U", "postgres", "-d", "langfuse"],
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
