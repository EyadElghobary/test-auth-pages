'use client';

import { useSession } from 'next-auth/react';

function Homepage() {
  const { data: session, status } = useSession();

  if (status === 'loading') {
    return <p>Loading...</p>;
  }

  if (status === 'unauthenticated') {
    return <p>Access Denied</p>;
  }

  return (
    <>
      <h1>Protected Page</h1>
      <p>welcom {session?.user?.name}</p>
    </>
  );
}

// async function HomePage({
//   session,
// }: InferGetServerSidePropsType<typeof getServerSideProps>) {
//   if (!session) {
//     // redirect('../api/auth/signin');
//     return null;
//   }

//   return <div>Welcome {session.user?.name}</div>;
// }

// export async function getServerSideProps(context: GetServerSidePropsContext) {
//   const session = await getSession(context);

//   return {
//     props: {
//       session,
//     },
//   };
// }

export default Homepage;
