# Experiment: validating n8n-signed JWTs (unfinished)

Written on 2 December 2025 against upstream commit `0f5b0d9` (v2.19.6) while trying out bearer-token checks on the HTTP mode.
**It is not wired in and has not been used in production.** The deployment that motivated it runs the unmodified upstream image.

`src/utils/jwt-auth.ts` validates an HS256 JWT signed by n8n (the kind n8n issues as an API key or MCP access token) using the shared
signing secret, and checks `exp` and that `aud` is `mcp-server-api` or `public-api`. To use it, `src/http-server-single-session.ts` would
import `validateJWT` and call it on the `Authorization: Bearer` token.

Known gaps before anyone relies on it:

- The signature is compared with `!==`, not a constant-time comparison (`crypto.timingSafeEqual`).
- The header's `alg` is not checked, and `nbf` is not checked.
- n8n's signing secret is instance-wide, so rotating it invalidates every issued key.
- There are no tests.

This branch exists only to keep the work from being lost. MIT licence as upstream.
