# syntax=docker/dockerfile:1
FROM mcr.microsoft.com/devcontainers/base:ubuntu

# 1. Install system dependencies
RUN apt-get update && apt-get install -y \
  python3 python3-pip curl git postgresql postgresql-contrib pgcli \
  && rm -rf /var/lib/apt/lists/*

# 1.2. Install ngrok
RUN curl -s https://ngrok-agent.s3.amazonaws.com/ngrok.asc | tee /etc/apt/trusted.gpg.d/ngrok.asc >/dev/null \
  && echo "deb https://ngrok-agent.s3.amazonaws.com buster main" | tee /etc/apt/sources.list.d/ngrok.list \
  && apt-get update \
  && apt-get install -y ngrok

# 1.5. Install Node.js, Vercel CLI, and Google Gemini CLI
# We use the NodeSource setup script to get a recent Node version (v20)
# which is required for the latest AI tools and Vercel.
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
  && apt-get install -y nodejs \
  && npm install -g vercel @google/gemini-cli

# --- FIX START ---
# Configure PostgreSQL as ROOT before switching users
# We perform the sed edits and service commands here.
RUN echo "Configuring PostgreSQL..." \
  # Note: Validate the version number '16' matches what apt-get installed.
  # On ubuntu base images it might be 14 or 16 depending on the distro version.
  # Using wildcard matches for version creates a robust path: /etc/postgresql/*/main/pg_hba.conf
  && sed -i 's/local.*all.*postgres.*peer/local all postgres trust/' /etc/postgresql/*/main/pg_hba.conf \
  && sed -i 's/local.*all.*all.*peer/local all all trust/' /etc/postgresql/*/main/pg_hba.conf \
  && service postgresql start \
  && su - postgres -c "psql -c \"CREATE USER vscode WITH SUPERUSER;\"" \
  && su - postgres -c "psql -c \"CREATE DATABASE vscode OWNER vscode;\""

# Now we can prepare the schema file (still as root is fine, just put it in tmp)
COPY <<EOF /tmp/schema.sql
-- Initial schema for Neon PostgreSQL
-- Run this in your Neon SQL editor or via psql

-- Signups table
CREATE TABLE IF NOT EXISTS signups (
  id SERIAL PRIMARY KEY,
  email TEXT UNIQUE NOT NULL,
  profession TEXT,
  referrer_id INTEGER REFERENCES signups(id),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_signups_email ON signups(email);
CREATE INDEX IF NOT EXISTS idx_signups_referrer_id ON signups(referrer_id);

CREATE TABLE IF NOT EXISTS uploads (
  id SERIAL PRIMARY KEY,
  signup_id INTEGER NOT NULL REFERENCES signups(id),
  filename TEXT NOT NULL,
  data TEXT NOT NULL,
  uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_uploads_signup_id ON uploads(signup_id);

CREATE TABLE IF NOT EXISTS invite_links (
  id SERIAL PRIMARY KEY,
  signup_id INTEGER NOT NULL REFERENCES signups(id),
  token TEXT UNIQUE NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_invite_links_token ON invite_links(token);
CREATE INDEX IF NOT EXISTS idx_invite_links_signup_id ON invite_links(signup_id);

CREATE TABLE IF NOT EXISTS invite_clicks (
  id SERIAL PRIMARY KEY,
  invite_id INTEGER NOT NULL REFERENCES invite_links(id),
  ip_address TEXT,
  user_agent TEXT,
  clicked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_invite_clicks_invite_id ON invite_clicks(invite_id);
EOF

# Apply the schema
RUN service postgresql start \
  && su - postgres -c "psql -d vscode -f /tmp/schema.sql" \
  && rm /tmp/schema.sql

# Apply migration 002: add expires_at column to invite_links
COPY <<EOF /tmp/migration_002.sql
-- Add expires_at column to invite_links
ALTER TABLE invite_links ADD COLUMN IF NOT EXISTS expires_at TIMESTAMP;

-- Set default expiration for existing links to 24 hours from creation
-- If created_at is older than 24h, they will be effectively expired
UPDATE invite_links
SET expires_at = created_at + INTERVAL '24 hours'
WHERE expires_at IS NULL;
EOF

RUN service postgresql start \
  && su - postgres -c "psql -d vscode -f /tmp/migration_002.sql" \
  && rm /tmp/migration_002.sql
# --- FIX END ---

# 2. NOW switch to the vscode user for user-specific tools
USER vscode
ENV HOME=/home/vscode

# 3. Install 'uv' and 'mistral-vibe' as the vscode user
RUN curl -LsSf https://astral.sh/uv/install.sh | sh
ENV PATH="/home/vscode/.local/bin:${PATH}"

RUN uv tool install mistral-vibe

# 4. Set up the Vibe configuration
RUN mkdir -p /home/vscode/.vibe
RUN cat <<EOF > /home/vscode/.vibe/config.toml
active_model = "kimi-openrouter"

[[providers]]
name = "openrouter"
api_base = "https://openrouter.ai/api/v1"
api_key_env_var = "OPENROUTER_API_KEY"
api_style = "openai"
backend = "generic"

[[models]]
name = "moonshotai/kimi-k2.5"
provider = "openrouter"
alias = "kimi-openrouter"
EOF

RUN curl -fsSL https://claude.ai/install.sh | bash
# Ensure the PATH is persisted for the shell
RUN echo 'export PATH="/home/vscode/.local/bin:$PATH"' >> /home/vscode/.bashrc