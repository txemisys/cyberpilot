import { MicrosoftSignIn } from "../../components/microsoft-sign-in";

export default function LoginPage() {
  const microsoftEnabled = Boolean(
    process.env.MICROSOFT_CLIENT_ID && process.env.MICROSOFT_CLIENT_SECRET,
  );

  return (
    <main className="shell">
      <section className="auth-card">
        <p className="eyebrow">CyberPilot</p>
        <h1 className="auth-title">Secure access starts here.</h1>
        <p className="lede">
          Sign in with your company Microsoft account. Access to customer
          organizations is granted separately through explicit membership.
        </p>
        <MicrosoftSignIn enabled={microsoftEnabled} />
      </section>
    </main>
  );
}
