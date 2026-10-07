import Credentials from "next-auth/providers/credentials"
import GitHub from "next-auth/providers/github"
import Keycloak from "next-auth/providers/keycloak"
import type { NextAuthConfig } from "next-auth"

/** Shared edge configuration; credential verification and IAM checks use Node. */
export default {
  basePath: "/auth",
  session: { strategy: "jwt", maxAge: 30 * 24 * 60 * 60 },
  providers: [
    Credentials({
      credentials: {
        email: { label: "Email", type: "email" },
        password: { label: "Password", type: "password" },
      },
      authorize: () => null,
    }),
    GitHub,
    Keycloak,
  ],
} satisfies NextAuthConfig
