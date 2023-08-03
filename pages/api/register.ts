import { PrismaClient } from '@prisma/client';
import prisma from '@/lib/prisma';
import * as bcrypt from 'bcrypt';

interface RequestBody {
  name: string;
  email: string;
  password: string;
  confirm: string;
}

export async function POST(request: Request) {
  const body: RequestBody = await request.json();

  if (
    !(
      body.name &&
      body.email &&
      body.password &&
      body.confirm &&
      body.password.length >= 1
    )
  ) {
    return new Response(JSON.stringify({ error: 'Information is Missing' }), {
      status: 400,
      headers: {
        'Content-Type': 'application/json',
      },
    });
  }

  if (body.password != body.confirm) {
    return new Response(JSON.stringify({ error: 'Password mismatch' }), {
      status: 403,
      headers: {
        'Content-Type': 'application/json',
      },
    });
  }

  const profileExists = await prisma.user.findMany({
    where: {
      email: body.email,
    },
  });

  if (
    profileExists &&
    Array.isArray(profileExists) &&
    profileExists.length > 0
  ) {
    return new Response(JSON.stringify({ error: 'User Already Exists' }), {
      status: 403,
      headers: {
        'Content-Type': 'application/json',
      },
    });
  }

  console.log(body.name);
  console.log(body.password);

  const user = await prisma.user.create({
    data: {
      name: body.name,
      email: body.email,
      password: await bcrypt.hash(body.password, 10),
    },
  });

  if (!user) {
    return new Response(JSON.stringify({ error: 'Something went wrong' }), {
      status: 500,
      headers: {
        'Content-Type': 'application/json',
      },
    });
  }

  const account = await prisma.account.create({
    data: {
      userId: user.id,
      type: 'credentials',
      provider: 'credentials',
      providerAccountId: user.id,
    },
  });

  if (user && account) {
    return new Response(
      JSON.stringify({ id: user.id, name: user.name, email: user.name }),
      {
        status: 200,
        headers: {
          'Content-Type': 'application/json',
        },
      }
    );
  } else {
    return new Response(
      JSON.stringify({ error: "Couldn't link User to Account" }),
      {
        status: 500,
        headers: {
          'Content-Type': 'application/json',
        },
      }
    );
  }
}
