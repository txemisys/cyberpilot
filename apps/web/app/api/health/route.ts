import { db } from "@cyberpilot/database";
import { NextResponse } from "next/server";

import { reportOperationalEvent } from "../../../lib/operational-logging";

export const dynamic = "force-dynamic";

export async function GET() {
  try {
    await db.$queryRaw`SELECT 1`;

    return NextResponse.json(
      {
        status: "ok",
        database: "ok",
      },
      {
        status: 200,
        headers: {
          "cache-control": "no-store",
        },
      },
    );
  } catch (error) {
    reportOperationalEvent({
      event: "health.database_unavailable",
      error,
    });

    return NextResponse.json(
      {
        status: "unavailable",
        database: "unavailable",
      },
      {
        status: 503,
        headers: {
          "cache-control": "no-store",
        },
      },
    );
  }
}
