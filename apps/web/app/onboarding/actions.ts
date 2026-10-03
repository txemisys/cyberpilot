"use server";

import { db } from "@cyberpilot/database";
import { redirect } from "next/navigation";

import { requireSession } from "../../lib/session";

function toSlug(value: string) {
  return value
    .trim()
    .toLowerCase()
    .normalize("NFKD")
    .replace(/[\u0300-\u036f]/g, "")
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 48);
}

export async function createOrganization(formData: FormData) {
  const session = await requireSession();
  const rawName = formData.get("name");

  if (typeof rawName !== "string") {
    throw new Error("Organization name is required.");
  }

  const name = rawName.trim();

  if (name.length < 2 || name.length > 100) {
    throw new Error("Organization name must contain between 2 and 100 characters.");
  }

  const baseSlug = toSlug(name);

  if (!baseSlug) {
    throw new Error("Organization name must contain letters or numbers.");
  }

  let slug = baseSlug;
  let suffix = 1;

  while (
    await db.organization.findUnique({
      where: { slug },
      select: { id: true },
    })
  ) {
    suffix += 1;
    slug = `${baseSlug.slice(0, 42)}-${suffix}`;
  }

  await db.$transaction(async (tx) => {
    const organization = await tx.organization.create({
      data: {
        name,
        slug,
      },
    });

    await tx.membership.create({
      data: {
        organizationId: organization.id,
        userId: session.user.id,
        role: "OWNER",
      },
    });

    await tx.auditEvent.create({
      data: {
        organizationId: organization.id,
        actorType: "USER",
        actorUserId: session.user.id,
        action: "organization.created",
        resourceType: "organization",
        resourceId: organization.id,
        metadata: {
          slug,
        },
      },
    });
  });

  redirect(`/organizations/${slug}`);
}
