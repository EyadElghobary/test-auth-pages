import Homepage from './homepage';
import { getCsrfToken, getSession, useSession } from 'next-auth/react';
import { getServerSession } from 'next-auth/next';
import { redirect } from 'next/navigation';

import type {
  GetServerSidePropsContext,
  InferGetServerSidePropsType,
} from 'next';
import { authOptions } from './api/auth/[...nextauth]';

export default function App() {
  const { data: session, status } = useSession();

  if (!session) {
    redirect('/auth/signin');
  }

  // Render the HomePage for logged-in users
  return <Homepage />;
}

// export async function getServerSideProps(context: GetServerSidePropsContext) {
//   const csrfToken = await getCsrfToken(context);
//   const session = await getServerSession(context.req, context.res, authOptions(context.req, context.res));

//   return {
//     props: {
//       csrfToken,
//       session,
//     },
//   };
// }
