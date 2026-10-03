import { db } from "@cyberpilot/database";
import { headers } from "next/headers";
import { redirect } from "next/navigation";

import { auth } from "./auth";

export async function requireSession() {
  const session = await auth.api.getSession({
    headers: await headers(),
  });

  if (!session) {
    redirect("/login");
  }

  return session;
}

export async function getCurrentUserOrganizations() {
  const session = await requireSession();

  const memberships = await db.membership.findMany({
    where: {
      userId: session.user.id,
    },
    orderBy: {
      createdAt: "asc",
    },
    select: {
      role: true,
      organization: {
        select: {
          id: true,
          name: true,
          slug: true,
        },
      },
    },
  });

  return {
    session,
    memberships,
  };
}
