"use client";

import { useState } from "react";

import { authClient } from "../lib/auth-client";

type MicrosoftSignInProps = {
  enabled: boolean;
};

export function MicrosoftSignIn({ enabled }: MicrosoftSignInProps) {
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function signIn() {
    setPending(true);
    setError(null);

    try {
      const result = await authClient.signIn.social({
        provider: "microsoft",
        callbackURL: "/dashboard",
      });

      if (result.error) {
        setError(result.error.message ?? "Microsoft sign-in failed.");
        setPending(false);
      }
    } catch {
      setError("Microsoft sign-in failed.");
      setPending(false);
    }
  }

  return (
    <div className="auth-actions">
      <button
        className="primary-button"
        type="button"
        disabled={!enabled || pending}
        onClick={signIn}
      >
        {pending ? "Connecting…" : "Continue with Microsoft"}
      </button>

      {!enabled ? (
        <p className="auth-note">
          Microsoft authentication is not configured in this environment.
        </p>
      ) : null}

      {error ? (
        <p className="auth-error" role="alert">
          {error}
        </p>
      ) : null}
    </div>
  );
}
