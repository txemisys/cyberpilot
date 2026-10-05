"use client";

import { FormEvent, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";

import { authClient } from "../lib/auth-client";

export function LabResetPassword() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const token = searchParams.get("token");
  const tokenError = searchParams.get("error");
  const [password, setPassword] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(
    tokenError ? "This password reset link is invalid or expired." : null,
  );

  async function resetPassword(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();

    if (!token) {
      setError("This password reset link is invalid or expired.");
      return;
    }

    if (password !== confirmation) {
      setError("Passwords do not match.");
      return;
    }

    setPending(true);
    setError(null);

    try {
      const result = await authClient.resetPassword({
        newPassword: password,
        token,
      });

      if (result.error) {
        setError(result.error.message ?? "Password reset failed.");
        setPending(false);
        return;
      }

      router.push("/login");
      router.refresh();
    } catch {
      setError("Password reset failed.");
      setPending(false);
    }
  }

  return (
    <form className="lab-auth" onSubmit={resetPassword}>
      <div className="lab-auth-heading">
        <strong>Reset Local Lab password</strong>
        <span>Development only</span>
      </div>

      <label htmlFor="lab-new-password">New password</label>
      <input
        id="lab-new-password"
        type="password"
        value={password}
        onChange={(event) => setPassword(event.target.value)}
        minLength={8}
        autoComplete="new-password"
        required
      />

      <label htmlFor="lab-confirm-password">Confirm new password</label>
      <input
        id="lab-confirm-password"
        type="password"
        value={confirmation}
        onChange={(event) => setConfirmation(event.target.value)}
        minLength={8}
        autoComplete="new-password"
        required
      />

      <button
        className="primary-button"
        type="submit"
        disabled={pending || !token}
      >
        {pending ? "Resetting…" : "Reset password"}
      </button>

      {error ? (
        <p className="auth-error" role="alert">
          {error}
        </p>
      ) : null}
    </form>
  );
}
