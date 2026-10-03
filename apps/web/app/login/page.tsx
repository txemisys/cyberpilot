import { LabSignIn } from "../../components/lab-sign-in";
import { MicrosoftSignIn } from "../../components/microsoft-sign-in";

export default function LoginPage() {
  const microsoftEnabled = Boolean(
    process.env.MICROSOFT_CLIENT_ID && process.env.MICROSOFT_CLIENT_SECRET,
  );
  const labAuthEnabled =
    process.env.NODE_ENV !== "production" &&
    process.env.LAB_AUTH_ENABLED === "true";

  return (
    <main className="shell">
      <section className="auth-card">
        <p className="eyebrow">CyberPilot</p>
        <h1 className="auth-title">Secure access starts here.</h1>
        <p className="lede">
          Use Microsoft for a real deployment. Local Lab authentication exists
          only for development so CyberPilot can be exercised without a
          Microsoft tenant.
        </p>

        {labAuthEnabled ? <LabSignIn /> : null}

        <MicrosoftSignIn enabled={microsoftEnabled} />
      </section>
    </main>
  );
}
