import { LabResetPassword } from "../../components/lab-reset-password";

export default function ResetPasswordPage() {
  const labAuthEnabled =
    process.env.NODE_ENV !== "production" &&
    process.env.LAB_AUTH_ENABLED === "true";

  return (
    <main className="shell">
      <section className="auth-card">
        <p className="eyebrow">CyberPilot</p>
        <h1 className="auth-title">Reset Local Lab password.</h1>
        <p className="lede">
          This development-only flow uses a short-lived reset token generated
          by Better Auth. No email is sent.
        </p>

        {labAuthEnabled ? (
          <LabResetPassword />
        ) : (
          <p className="auth-error">Local Lab authentication is disabled.</p>
        )}
      </section>
    </main>
  );
}
