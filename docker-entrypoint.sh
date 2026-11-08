#!/bin/sh
set -eu

if [ -z "${JWT_SECRET:-}" ] || [ "${JWT_SECRET:-}" = "replace-with-a-long-random-secret" ] || [ "${#JWT_SECRET}" -lt 32 ]; then
  echo "JWT_SECRET must be set to a unique value of at least 32 characters" >&2
  exit 1
fi
if [ "${DEV_PASSWORD:-}" = "change-me-now" ] || [ -z "${DEV_PASSWORD:-}" ]; then
  echo "Set DEV_PASSWORD to a unique bootstrap password before starting" >&2
  exit 1
fi
if [ "${INITIAL_USER_PASSWORD:-}" = "change-me-now" ] || [ -z "${INITIAL_USER_PASSWORD:-}" ]; then
  echo "Set INITIAL_USER_PASSWORD before starting" >&2
  exit 1
fi
if [ -z "${UPSTREAM_API_KEY:-}" ] || [ "${UPSTREAM_API_KEY:-}" = "replace-with-your-provider-key" ]; then
  echo "Set UPSTREAM_API_KEY before starting" >&2
  exit 1
fi
if [ -z "${CREDENTIALS_ENCRYPTION_KEY:-}" ] || [ "${CREDENTIALS_ENCRYPTION_KEY:-}" = "generate-a-base64-encoded-32-byte-key" ]; then
  echo "Set CREDENTIALS_ENCRYPTION_KEY to a base64 encoded 32-byte key" >&2
  exit 1
fi
exec /usr/local/bin/llmroute-server
