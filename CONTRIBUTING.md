# Contributing to LLMRoute

Thanks for considering a contribution. The project is evolving, so please keep changes focused and explain the user need they address.

## Before you start

- Search existing issues and pull requests to avoid duplicate work.
- For a substantial change, open an issue first to discuss scope and compatibility.
- Do not submit secrets, production data, credentials, or real user content.
- The project currently has no `LICENSE` file. Contributions do not grant permission to use or redistribute the project; please wait for the maintainers to publish a license before relying on it.

## Development setup

See the [README](README.md) for prerequisites and configuration. Copy `.env.example` to `.env` and use local-only credentials. Never point development work at a production database.

## Pull requests

- Keep each pull request focused and include the motivation and relevant context.
- Describe behavior changes, configuration or migration changes, and any security implications.
- Update documentation and `.env.example` when user-facing configuration changes.
- Run the relevant checks for the code you changed and include the commands and results in the pull request.
- Do not bundle unrelated formatting or generated build output.

## Reporting bugs

Use the bug report issue template. Include reproducible steps, expected and actual behavior, environment details, and sanitized logs. Remove tokens, email addresses, IP addresses, prompts, and other personal or secret data before posting.
