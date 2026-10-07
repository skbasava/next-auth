import NextAuth from "next-auth"
import { NextResponse } from "next/server"
import authConfig from "./auth.config"

// Edge cookie validation is only a coarse gate. Node handlers must reload the
// live IAM session/membership and enforce permissions, MFA and mutation origin.
export const { auth: middleware } = NextAuth({
  ...authConfig,
  callbacks: {
    authorized({ auth, request }) {
      const path = request.nextUrl.pathname
      // Exact offline verification and SCIM authenticate their own bearer credentials.
      if (path === "/api/iam/verify" && request.method === "GET") return true
      if (path === "/api/iam/scim" || path.startsWith("/api/iam/scim/"))
        return true
      if (path === "/api/iam" || path.startsWith("/api/iam/")) {
        if (!auth?.user)
          return NextResponse.json(
            { error: "unauthorized" },
            { status: 401, headers: { "Cache-Control": "no-store" } }
          )
      }
      // Preserve the existing public ordinary-page middleware behavior.
      return true
    },
  },
})

export const config = {
  matcher: [
    "/api/iam/:path*",
    "/((?!api|_next/static|_next/image|favicon.ico).*)",
  ],
}
