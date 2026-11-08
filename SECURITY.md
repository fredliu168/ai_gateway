# Security policy

## Reporting a vulnerability

Please do not report security vulnerabilities in public issues. Use GitHub's **Report a vulnerability** feature on this repository to send a private report to the maintainers. Include affected versions or commits, impact, reproduction steps, and any suggested mitigation. Do not include real credentials or personal data.

If private vulnerability reporting is unavailable, contact the repository owner through the contact information on their GitHub profile and ask for a private channel. Please allow maintainers reasonable time to investigate and prepare a fix before public disclosure.

## Deployment notes

- Put the application behind HTTPS and restrict access to administrative routes and the host.
- Treat Docker socket access as host-level privilege. The Agent sandbox requires this access in the provided Compose setup.
- Use strong, unique secrets and protect `.env`, database backups, and the credentials encryption key.
- Keep the host, Docker Engine, and base images updated.
