import type { Metadata } from "next";

import AppLink from "@/components/AppLink";

export const metadata: Metadata = {
  title: "Overview",
  description:
    "Create branded mailboxes, inboxes, and delivery flows on your own infrastructure.",
};

const heroSignals = [
  { value: "support@clientbrand.com", label: "Branded inboxes on your own domains" },
  { value: "IMAP + SMTP + API", label: "Human inboxes and delivery in one runtime" },
];

const threadMessages = [
  {
    from: "owner@pinepeak.co",
    role: "Client",
    body: "Need branded inboxes for support, bookings, and billing before launch on Friday.",
    tone: "soft",
  },
  {
    from: "ops@northstarweb.studio",
    role: "You",
    body: "Created the mailboxes, turned on DKIM, and handed the team real IMAP logins instead of another shared Gmail.",
    tone: "accent",
  },
  {
    from: "support@pinepeak.co",
    role: "Inbox",
    body: "Customer replies now land on the branded address the site actually shows.",
    tone: "soft",
  },
];

const useCases = [
  {
    title: "For client websites",
    body: "Spin up real addresses like hello@, support@, and billing@ for each domain you launch.",
  },
  {
    title: "For products on a VPS",
    body: "Keep contact inboxes, transactional sending, and outbound mail on infrastructure you already control.",
  },
  {
    title: "For ops teams who automate",
    body: "Provision domains and mailboxes through the API instead of living inside another admin panel.",
  },
];

const capabilities = [
  {
    title: "Create addresses people actually recognize",
    body: "Use branded inboxes on custom domains instead of routing everything through one generic mailbox.",
  },
  {
    title: "Handle inboxes and delivery in one place",
    body: "Inbound SMTP, outbound relay, IMAP access, DKIM signing, and the admin API stay under one roof.",
  },
  {
    title: "Run mail as part of the work you already host",
    body: "Lightr fits the team with a VPS that needs email for products, launches, and managed client sites.",
  },
];

export default function HomePage() {
  return (
    <div className="site-frame py-6 md:py-8">
      <div className="flex flex-col gap-14 md:gap-20">
        <section className="grid gap-10 pb-2 pt-4 xl:grid-cols-[minmax(0,1.02fr)_430px] xl:items-center">
          <div className="max-w-4xl">
            <div className="inline-flex rounded-full border border-[rgba(37,99,235,0.14)] bg-white/78 px-4 py-2 text-sm font-semibold text-[var(--site-blue-strong)]">
              Self-hosted mail for real domains
            </div>
            <h1 className="mt-6 max-w-[10ch] text-5xl font-bold leading-[0.92] tracking-[-0.08em] text-[var(--site-ink)] md:text-[6.25rem]">
              Create branded email on your own infrastructure.
            </h1>
            <p className="mt-5 max-w-2xl text-lg leading-8 text-[var(--site-muted)] md:text-[1.12rem]">
              Lightr is for people with a VPS who need a simpler way to run inboxes,
              sending, and custom-domain mailboxes for products or client websites
              without piecing together a mail maze.
            </p>
            <div className="mt-8 flex flex-col gap-3 sm:flex-row">
              <AppLink href="/docs/quickstart" className="site-button-primary px-6 py-4 text-base">
                Open quickstart
              </AppLink>
              <AppLink href="#use-cases" className="site-button-quiet px-4 py-4 text-base">
                See use cases
              </AppLink>
            </div>

            <dl className="mt-10 grid gap-5 border-t border-[var(--site-line)] pt-5 sm:grid-cols-2">
              {heroSignals.map((item) => (
                <div key={item.value} className="space-y-2">
                  <dt className="text-sm text-[var(--site-muted)]">{item.label}</dt>
                  <dd className="text-lg font-bold tracking-[-0.03em] text-[var(--site-ink)]">
                    {item.value}
                  </dd>
                </div>
              ))}
            </dl>
          </div>

          <aside className="site-panel-dark p-5 md:p-6">
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div>
                <p className="site-label text-[rgba(230,238,249,0.7)]">Sample thread</p>
                <h2 className="mt-3 break-all text-[1.95rem] font-bold leading-tight tracking-[-0.05em] text-white sm:break-normal sm:text-3xl">
                  support@pinepeak.co
                </h2>
              </div>
              <span className="shrink-0 rounded-full bg-[rgba(37,99,235,0.18)] px-3 py-2 text-xs font-bold text-[#dce8ff]">
                live inbox
              </span>
            </div>

            <p className="mt-4 max-w-sm text-sm leading-7 text-[rgba(230,238,249,0.76)]">
              One example of the kind of email surface teams actually need when
              launching a site or handing a client a branded address.
            </p>

            <div className="mt-6 space-y-4">
              {threadMessages.map((message) => (
                <article
                  key={message.from}
                  className={`rounded-[24px] border p-4 ${
                    message.tone === "accent"
                      ? "border-[rgba(37,99,235,0.18)] bg-[rgba(37,99,235,0.12)]"
                      : "border-[rgba(230,238,249,0.1)] bg-white/5"
                  }`}
                >
                  <div className="flex items-center justify-between gap-4">
                    <p className="text-sm font-semibold text-white">{message.from}</p>
                    <span className="text-xs uppercase tracking-[0.18em] text-[rgba(230,238,249,0.58)]">
                      {message.role}
                    </span>
                  </div>
                  <p className="mt-3 text-sm leading-7 text-[rgba(230,238,249,0.82)]">
                    {message.body}
                  </p>
                </article>
              ))}
            </div>

            <dl className="mt-6 grid gap-3 border-t border-[rgba(230,238,249,0.1)] pt-4 sm:grid-cols-3">
              <div>
                <dt className="text-xs uppercase tracking-[0.18em] text-[rgba(230,238,249,0.58)]">
                  Domain
                </dt>
                <dd className="mt-2 text-sm font-semibold text-white">pinepeak.co</dd>
              </div>
              <div>
                <dt className="text-xs uppercase tracking-[0.18em] text-[rgba(230,238,249,0.58)]">
                  Mailboxes
                </dt>
                <dd className="mt-2 text-sm font-semibold text-white">3 active</dd>
              </div>
              <div>
                <dt className="text-xs uppercase tracking-[0.18em] text-[rgba(230,238,249,0.58)]">
                  Signing
                </dt>
                <dd className="mt-2 text-sm font-semibold text-[#9ce4d8]">DKIM ready</dd>
              </div>
            </dl>
          </aside>
        </section>

        <section
          id="use-cases"
          className="border-t border-[rgba(13,23,38,0.08)] pt-8 md:pt-10"
        >
          <div className="max-w-3xl">
            <p className="site-label text-[var(--site-blue)]">Use cases</p>
            <p className="mt-4 text-2xl font-medium leading-[1.2] tracking-[-0.05em] text-[var(--site-ink)] md:text-4xl">
              This is for the person who already has a server and needs email to stop
              being the annoying part of shipping.
            </p>
          </div>

          <div className="mt-8 grid gap-8 md:grid-cols-3">
            {useCases.map((item) => (
              <div key={item.title} className="border-t border-[var(--site-line)] pt-4">
                <h3 className="max-w-[18ch] text-2xl font-bold leading-tight tracking-[-0.05em] text-[var(--site-ink)]">
                  {item.title}
                </h3>
                <p className="mt-3 max-w-sm text-base leading-7 text-[var(--site-muted)]">
                  {item.body}
                </p>
              </div>
            ))}
          </div>
        </section>

        <section className="site-card site-grid-bg px-6 py-6 md:px-8 md:py-8">
          <div className="grid gap-8 xl:grid-cols-[minmax(0,0.78fr)_minmax(0,1.22fr)] xl:items-start">
            <div className="max-w-2xl">
              <p className="site-label text-[var(--site-blue)]">Features</p>
              <h2 className="mt-3 max-w-[11ch] text-4xl font-bold leading-none tracking-[-0.06em] text-[var(--site-ink)] md:text-6xl">
                The point is not setup. The point is what you can run after setup.
              </h2>
              <p className="mt-4 max-w-lg text-base leading-8 text-[var(--site-muted)]">
                Lightr works best when the homepage talks about the mail surface you
                end up owning: branded inboxes, delivery, and mailbox creation that
                fits real work.
              </p>
            </div>

            <div className="grid gap-6">
              {capabilities.map((item, index) => (
                <div
                  key={item.title}
                  className={`border-t border-[var(--site-line)] pt-5 ${
                    index === 0 ? "border-t-0 pt-0" : ""
                  }`}
                >
                  <h3 className="max-w-[20ch] text-3xl font-bold leading-tight tracking-[-0.05em] text-[var(--site-ink)]">
                    {item.title}
                  </h3>
                  <p className="mt-3 max-w-2xl text-base leading-8 text-[var(--site-muted)]">
                    {item.body}
                  </p>
                </div>
              ))}
            </div>
          </div>
        </section>

        <section className="border-t border-[rgba(13,23,38,0.08)] pb-2 pt-8 md:pt-10">
          <div className="flex flex-col gap-5 lg:flex-row lg:items-end lg:justify-between">
            <div className="max-w-2xl">
              <p className="site-label text-[var(--site-blue)]">Start here</p>
              <h2 className="mt-3 max-w-[12ch] text-4xl font-bold leading-none tracking-[-0.06em] text-[var(--site-ink)] md:text-6xl">
                Open the quickstart when you are ready to make the first domain real.
              </h2>
            </div>

            <div className="flex flex-col gap-3 sm:flex-row">
              <AppLink href="/docs/quickstart" className="site-button-primary px-6 py-4 text-base">
                Open quickstart
              </AppLink>
              <AppLink href="/docs/api" className="site-button-quiet px-4 py-4 text-base">
                Browse API
              </AppLink>
            </div>
          </div>
        </section>
      </div>
    </div>
  );
}
