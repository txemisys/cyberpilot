import { db } from "@cyberpilot/database";
import { betterAuth } from "better-auth";
import { prismaAdapter } from "better-auth/adapters/prisma";

const microsoftClientId = process.env.MICROSOFT_CLIENT_ID;
const microsoftClientSecret = process.env.MICROSOFT_CLIENT_SECRET;

const microsoftProvider =
  microsoftClientId && microsoftClientSecret
    ? {
        socialProviders: {
          microsoft: {
            clientId: microsoftClientId,
            clientSecret: microsoftClientSecret,
            tenantId: "organizations",
            prompt: "select_account" as const,
          },
        },
      }
    : {};

export const auth = betterAuth({
  database: prismaAdapter(db, {
    provider: "postgresql",
  }),
  ...microsoftProvider,
});
