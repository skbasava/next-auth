import type { DefaultSession } from "next-auth"

declare module "next-auth" {
  interface Session {
    user: DefaultSession["user"] & { id?: string; address?: string }
    iamSessionId?: string
    sessionVersion?: number
    mfaVerified?: boolean
  }
  interface User { foo?: string }
}
declare module "next-auth/jwt" {
  interface JWT {
    iamSessionId?: string
    sessionVersion?: number
    mfaVerified?: boolean
  }
}
