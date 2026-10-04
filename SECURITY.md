# Security policy

SolaHelm manages servers over SSH and stores credentials, so security reports are taken seriously.

## Reporting a vulnerability

**Please do not open a public issue for security problems.**
Use GitHub's private reporting: the repository's **Security** tab → **Report a vulnerability**.
Include what you found, how to reproduce it and the affected version (shown in the panel footer).

## Supported versions

Only the latest release receives fixes.

## Hardening checklist for operators

- Serve the panel over HTTPS only and restrict `/hy/admin/` by IP in nginx.
- Keep the panel host patched; the panel's SSH key can log in to all managed servers.
- Back up `data/` (contains `secret.key`, `panel.db`, the SSH key) and never publish or share it.
- Use strong, unique admin and client passwords.
