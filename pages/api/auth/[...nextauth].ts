/* ----This code below we may not need ----*/

// import NextAuth from 'next-auth/next';
// import { authOptions } from './options';

// const handler = NextAuth(authOptions);

// export { handler as GET, handler as POST };

import { PrismaAdapter } from "@auth/prisma-adapter";
import prisma from "@/lib/prisma";
import { NextApiRequest, NextApiResponse } from "next";
import { NextAuthOptions } from "next-auth";
import GoogleProvider from 'next-auth/providers/google';
import CredentialsProvider from 'next-auth/providers/credentials';
import { randomUUID } from "crypto";
import {deleteCookie, getCookie, getCookies, setCookie} from 'cookies-next';
import { encode, decode } from "next-auth/jwt";
import NextAuth from "next-auth/next";


const prismaAdapter = PrismaAdapter(prisma);
const cookiePrefix = '__cp__'

const validatePassword = async (password: string) => {
    const res = await fetch('/api/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          password: password,
        }),
    });

    const user = res.json();

    if (!user) {
        return false;
    }
    return true;
}

export default async function auth(request: NextApiRequest, response: NextApiResponse) {
  const providers = [
    GoogleProvider({
      clientId: process.env.GOOGLE_ID as string,
      clientSecret: process.env.GOOGLE_SECRET as string,
      authorization: {
        params: {
          prompt: 'consent',
          access_type: 'offline', // offline allows for a refresh token to be provided by Google along with an access token
          response_type: 'code',
        },
      },
    }),
    CredentialsProvider({
        name: 'email',
        credentials: {
            email: {label: 'Email', type: 'text', placeholder: 'Enter Email'},
            password: {
                label: 'Password',
                type: 'password',
                placeholder: 'Password',
            },
        },
        async authorize(credentials, request) {
          console.log("Here");
            if (!credentials || !credentials.email || !credentials.password) {
                return null;
            }
            try {
                const user = await prisma.user.findUnique({
                    where: {email: credentials.email},
                    include: {
                        Account: true
                    },
                })

                if (user) {
                    if (
                        !user.Account.some(
                          (account) => account.provider === 'credentials'
                        ) ||
                        !validatePassword(credentials.password)
                      )
                        return null
                    
                    return {
                        id: user.id,
                        email: user.email,
                        name: user.name!,
                        image: user.image,
                        verified: user.emailVerified,
                        resume: user.resume!,
                        cover: user.cover_letter!
                    }
              }
              return null
            } catch (error) {
                console.log(error);
                return null
            }
        }
    })
  ];

  const adapter = prismaAdapter;    

  return await NextAuth(request, response, {
    providers: providers,
    adapter: adapter,
    callbacks: {
      async signIn({user, account, profile, email, credentials}) {
        console.log("SignIn");
        const credentialsLogin = account?.type === 'credentials';
        if (credentialsLogin && !user.verified) {
            throw new Error('verifiedError')
        }

        if (request) {
          console.log("I'm Here");
          if (
              request.query.nextauth!.includes('callback') &&
              request.query.nextauth!.includes('credentials') &&
              request.method === 'POST'
          ) {
              if (user) {
                  const sessionToken = randomUUID();
                  const expires = new Date(Date.now() + 15 * 24 * 60 * 60 * 1000);
                  await prisma.session.create({
                      sessionToken: sessionToken,
                      userId: user.id as string,
                      expires: expires,
                  })
                  setCookie(`${cookiePrefix}session__token`, sessionToken, {
                      expires: expires,
                      req: request,
                      res: response,
                  })
              }
          }
        }
      

        if (user) {
          return true;
        }
        return false;
      },
      async redirect({ url, baseUrl }) {
          if (url && url.includes('callbackUrl'))
            return url.split('callbackUrl=')[1]
          if (url.startsWith(baseUrl)) return url
          // Allows relative callback URLs
          else if (url.startsWith('/')) return new URL(url, baseUrl).toString()
          return baseUrl
      },
      async session({ session, user }) {
          return Promise.resolve({
              ...session,
              user: {
                ...session.user,
                id: user.id,
                email: user.email,
                name: user.name,
                image: user.image,
                verified: user.emailVerified,
              },
            });
      },
    },
    jwt: {
      encode: async ({ token, secret, maxAge }) => {
        if (
          request?.query.nextauth?.includes('callback') &&
          request.query.nextauth.includes('credentials') &&
          request.method === 'POST'
        ) {
          const cookie = getCookie(`${cookiePrefix}session__token`, {
            req: request,
          }) as any
          return cookie ?? ''
        }
        return encode({ token, secret, maxAge })
      },

      decode: async ({ token, secret }) => {
        if (
          request?.query.nextauth?.includes('callback') &&
          request.query.nextauth.includes('credentials') &&
          request.method === 'POST'
        ) {
          return null
        }
        return decode({ token, secret })
      },
    },

    cookies: {
      sessionToken: {
        name: `${cookiePrefix}session__token`,
        options: {
            httpOnly: true,
            sameSite: 'lax',
            path: '/',
            secure: process.env.NODE_ENV === 'production'
        },
      },
      callbackUrl: {
        name: `${cookiePrefix}callback_url`,
        options: {
            httpOnly: true,
            sameSite: 'lax',
            path: '/',
            secure: process.env.NODE_ENV === 'production'
        },
      },
      csrfToken: {
        name: `${cookiePrefix}.csrf-token`,
        options: {
            httpOnly: true,
            sameSite: 'lax',
            path: '/',
            secure: process.env.NODE_ENV === 'production'
        },
      },
      state: {
          name: `${cookiePrefix}.state`,
          options: {
            httpOnly: true,
            sameSite: 'lax',
            path: '/',
            secure: process.env.NODE_ENV === 'production',
          },
      },
    }
  })
}

