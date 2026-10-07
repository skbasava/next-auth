import NextAuth, { type NextAuthConfig } from "next-auth"
import Credentials from "next-auth/providers/credentials"
import { PrismaAdapter } from "@auth/prisma-adapter"
import { randomUUID } from "node:crypto"
import authConfig from "./auth.config"
import { prisma } from "./src/lib/prisma"
import { getIamConfig } from "./src/lib/iam/config"
import { assertLiveSession } from "./src/lib/iam/authoritative"
import {
  authorizeCredentials,
  createIamSession,
  logoutIamSession,
  recordAuthenticationFailure,
} from "./src/lib/iam/auth-session"
import type { RequestMeta } from "./src/lib/iam/types"

/** Supports both HTTP requests and server actions. Never copy untrusted headers,
 * credentials, cookie contents or provider errors into audit events. */
export function createAuthConfig(
  _request?: Request,
  meta: RequestMeta = { requestId: randomUUID() }
): NextAuthConfig {
  return {
    ...authConfig,
    adapter: PrismaAdapter(prisma),
    debug: false,
    providers: [
      Credentials({
        credentials: {
          email: { label: "Email", type: "email" },
          password: { label: "Password", type: "password" },
        },
        authorize: (credentials) => authorizeCredentials(credentials, meta),
      }),
      ...authConfig.providers.slice(1),
    ],
    callbacks: {
      async jwt({ token, trigger, user, account, session }) {
        try {
          getIamConfig()
          // Auth.js calls this after credentials verification or after OAuth's
          // adapter has persisted the canonical user and account.
          if (
            (trigger === "signIn" || trigger === "signUp") &&
            user?.id &&
            account
          ) {
            const identity = await createIamSession(user.id, meta)
            token.sub = identity.userId
            token.iamSessionId = identity.sessionId
          }
          if (
            typeof token.sub !== "string" ||
            typeof token.iamSessionId !== "string"
          )
            return null
          const live = await assertLiveSession({
            userId: token.sub,
            sessionId: token.iamSessionId,
          })
          // Build the cookie from an allowlist; never merge client updates.
          const name =
            trigger === "update" &&
            typeof session?.user?.name === "string" &&
            session.user.name.length <= 200
              ? session.user.name
              : token.name
          return {
            sub: token.sub,
            iamSessionId: token.iamSessionId,
            name,
            email: token.email,
            picture: token.picture,
            sessionVersion: live.sessionVersion,
            mfaVerified: live.mfaVerified,
          }
        } catch {
          await recordAuthenticationFailure(meta, "invalid_session").catch(
            () => {}
          )
          return null
        }
      },
      session({ session, token }) {
        session.user = {
          ...session.user,
          name: session.user?.name,
          email: session.user?.email,
          image: session.user?.image,
          ...(typeof token.sub === "string" ? { id: token.sub } : {}),
        }
        session.iamSessionId =
          typeof token.iamSessionId === "string"
            ? token.iamSessionId
            : undefined
        session.sessionVersion =
          typeof token.sessionVersion === "number"
            ? token.sessionVersion
            : undefined
        session.mfaVerified = token.mfaVerified === true
        return session
      },
    },
    events: {
      async signOut(message) {
        if (!("token" in message) || !message.token) return
        const { sub, iamSessionId } = message.token
        if (typeof sub === "string" && typeof iamSessionId === "string")
          await logoutIamSession({ userId: sub, sessionId: iamSessionId }, meta)
      },
    },
    logger: {
      error() {
        // Errors can contain URLs, tokens and DB secrets. Keep only enum reason.
        void recordAuthenticationFailure(meta, "invalid_credentials").catch(
          () => {}
        )
      },
      warn() {},
      debug() {},
    },
  }
}

export const { handlers, auth, signIn, signOut, unstable_update } =
  NextAuth(createAuthConfig)
