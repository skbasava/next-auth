# IAM development notes

## Repository baseline (2026-10-07)

The development app uses the app-root `auth.ts`, `middleware.ts`, and `app/`
entry points. Auth.js handlers live at `app/auth/[...nextauth]/route.ts` and
use `/auth` as their base path. Preserve this routing structure when adding
IAM modules under `src/lib/iam/`.

Authentication currently uses JWT sessions. The Prisma client and adapter are
commented out. The credentials provider accepts a fixed demonstration password
and returns a synthetic user identity; it is unsuitable for production IAM.
The current JWT update callback accepts a client-provided display name.

The Prisma datasource is SQLite (`file:./dev.db`). Its schema preserves User,
Account, Session, VerificationToken, and Authenticator. Both existing migration
directories and the migration lock are SQLite history. The migrations each
create the base tables, so they must not be treated as a verified sequential
PostgreSQL initialization. Preserve that history separately before creating a
fresh, dedicated PostgreSQL database; no existing database was migrated or reset
during inspection.

App Router owns `/`, `/dashboard`, `/auth/*`, and `/api/protected`. Older Pages
Router examples also remain. The protected App Router endpoint returns 401
without authentication and the session when authenticated. The older
`pages/api/examples/protected.ts` returns a JSON string, while its example page
expects a `content` property. New IAM routes must use the existing app-root
structure; introducing a second `src/app` root would conflict with this layout.

## Verified baseline commands

Run from the repository root in the existing isolated cloud checkout:

```sh
export PATH=/workspace/.onboarding-tools/node_modules/.bin:$PATH
export npm_config_cache=/workspace/.npm-cache
export XDG_CACHE_HOME=/workspace/.cache
export XDG_DATA_HOME=/workspace/.local/share
node --version
pnpm --version
pnpm --filter @auth/core build
pnpm --filter next-auth build
pnpm --filter @auth/core test
pnpm --filter next-auth test
```

Node 22.23.3 and pnpm 9.2.0 were verified. Both library builds passed. Core
passed 160 tests across 13 files; next-auth passed 17 tests across 3 files.
The existing `/workspace/auth-smoke.py` passed homepage, providers, anonymous
session, credentials sign-in, authenticated session, and sign-out checks against
the onboarding server before it was stopped for rebuilding. These results
establish the original authentication baseline, not the future IAM behavior.

Docker is available and its running-container list was empty at inspection.
PostgreSQL and Redis CLI tools were absent from PATH. Dedicated IAM services,
Prisma dependencies, and integration-test infrastructure remain later tasks.
