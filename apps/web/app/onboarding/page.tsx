import { createOrganization } from "./actions";
import { requireSession } from "../../lib/session";

export default async function OnboardingPage() {
  await requireSession();

  return (
    <main className="shell">
      <section className="auth-card">
        <p className="eyebrow">CyberPilot</p>
        <h1 className="auth-title">Create your security workspace.</h1>
        <p className="lede">
          Your organization is the security boundary for identities, devices,
          findings, evidence, and future Microsoft 365 integrations.
        </p>

        <form action={createOrganization} className="organization-form">
          <label htmlFor="name">Organization name</label>
          <input
            id="name"
            name="name"
            type="text"
            minLength={2}
            maxLength={100}
            autoComplete="organization"
            required
          />
          <button className="primary-button" type="submit">
            Create organization
          </button>
        </form>
      </section>
    </main>
  );
}
