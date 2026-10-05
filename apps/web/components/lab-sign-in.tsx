"use client";

import { FormEvent, useState } from "react";
import { useRouter } from "next/navigation";

import { authClient } from "../lib/auth-client";

export function LabSignIn() {
  const router = useRouter();
  const [name, setName] = useState("CyberPilot Lab User");
  const [email, setEmail] = useState("lab@cyberpilot.local");
  const [password, setPassword] = useState("");
  const [pending, setPending] = useState<
    "signin" | "signup" | "reset" | null
  >(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  async function signUp(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setPending("signup");
    setError(null);
    setNotice(null);

    try {
      const result = await authClient.signUp.email({
        name,
        email,
        password,
        callbackURL: "/dashboard",
      });

      if (result.error) {
        setError(result.error.message ?? "Lab account creation failed.");
        setPending(null);
        return;
      }

      router.push("/dashboard");
      router.refresh();
    } catch {
      setError("Lab account creation failed.");
      setPending(null);
    }
  }

  async function signIn() {
    setPending("signin");
    setError(null);
    setNotice(null);

    try {
      const result = await authClient.signIn.email({
        email,
        password,
        callbackURL: "/dashboard",
      });

      if (result.error) {
        setError(result.error.message ?? "Lab sign-in failed.");
        setPending(null);
        return;
      }

      router.push("/dashboard");
      router.refresh();
    } catch {
      setError("Lab sign-in failed.");
      setPending(null);
    }
  }

  async function requestPasswordReset() {
    setPending("reset");
    setError(null);
    setNotice(null);

    try {
      const result = await authClient.requestPasswordReset({
        email,
        redirectTo: `${window.location.origin}/reset-password`,
      });

      if (result.error) {
        setError(result.error.message ?? "Password reset request failed.");
        setPending(null);
        return;
      }

      setNotice(
        "If this Local Lab account exists, a one-time reset URL was printed in the terminal running pnpm dev.",
      );
    } catch {
      setError("Password reset request failed.");
    } finally {
      setPending(null);
    }
  }

  return (
    <form className="lab-auth" onSubmit={signUp}>
      <div className="lab-auth-heading">
        <strong>Local Lab access</strong>
        <span>Development only</span>
      </div>

      <label htmlFor="lab-name">Name</label>
      <input
        id="lab-name"
        name="name"
        type="text"
        value={name}
        onChange={(event) => setName(event.target.value)}
        minLength={2}
        maxLength={100}
        required
      />

      <label htmlFor="lab-email">Email</label>
      <input
        id="lab-email"
        name="email"
        type="email"
        value={email}
        onChange={(event) => setEmail(event.target.value)}
        autoComplete="email"
        required
      />

      <label htmlFor="lab-password">Password</label>
      <input
        id="lab-password"
        name="password"
        type="password"
        value={password}
        onChange={(event) => setPassword(event.target.value)}
        minLength={8}
        autoComplete="current-password"
        required
      />

      <div className="lab-auth-actions">
        <button
          className="primary-button"
          type="submit"
          disabled={pending !== null}
        >
          {pending === "signup" ? "Creating…" : "Create Lab account"}
        </button>

        <button
          className="secondary-button"
          type="button"
          disabled={pending !== null}
          onClick={signIn}
        >
          {pending === "signin" ? "Signing in…" : "Sign in"}
        </button>

        <button
          className="secondary-button"
          type="button"
          disabled={pending !== null || email.length === 0}
          onClick={requestPasswordReset}
        >
          {pending === "reset" ? "Creating reset link…" : "Forgot password?"}
        </button>
      </div>

      <p className="auth-note">
        Credentials are stored only in your local CyberPilot database. Do not
        enable this mode in production.
      </p>

      {notice ? <p className="auth-note">{notice}</p> : null}

      {error ? (
        <p className="auth-error" role="alert">
          {error}
        </p>
      ) : null}
    </form>
  );
}
