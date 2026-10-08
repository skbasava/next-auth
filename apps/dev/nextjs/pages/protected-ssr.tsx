// This is an example of how to protect content using server rendering
import { auth } from "../auth"
import AccessDenied from "components/access-denied"
import { GetServerSideProps } from "next"

export default function Page({ content, session }) {
  // If no session exists, display access denied message
  if (!session) return <AccessDenied />

  // If session exists, display content
  return (
    <>
      <h1>Protected Page</h1>
      <p>
        <strong>{content}</strong>
      </p>
    </>
  )
}

export const getServerSideProps: GetServerSideProps = async (context) => {
  const session = await auth(context)
  if (session) {
    // The session is already validated here; no HTTP request back to this app
    // is needed to obtain the example's protected content.
    return { props: { session, content: "This is protected content." } }
  }

  return { props: {} }
}
