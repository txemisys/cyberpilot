import { db } from "@cyberpilot/database";
import { notFound } from "next/navigation";

import { requireSession } from "./session";

export async function requireOrganizationAccess(slug: string) {
  const session = await requireSession();

  const membership = await db.membership.findFirst({
    where: {
      userId: session.user.id,
      organization: {
        slug,
      },
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

  if (!membership) {
    notFound();
  }

  return {
    session,
    membership,
  };
}
