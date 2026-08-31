import AppLink from "@/components/AppLink";

const linuxInstall = {
  label: "Linux path",
  tag: "Recommended route",
  href: "/docs/install",
  summary: "One-line installer with systemd setup for the host you control.",
  command: "curl -fsSL https://lightr.nigelbasa.tech/install.sh | sudo bash",
  bestFor: "Small VPS and bare-metal hosts.",
  traits: ["systemd", "bootstrap", "production-friendly"],
};

export function InstallTabs() {
  return (
    <div className="rounded-[28px] border border-[rgba(13,23,38,0.08)] bg-white/58 p-5 md:p-6">
      <div className="flex flex-wrap items-center gap-3">
        <span className="rounded-full border border-[rgba(37,99,235,0.16)] bg-[rgba(37,99,235,0.06)] px-4 py-2 text-sm font-semibold text-[var(--site-blue-strong)]">
          Linux
        </span>
        <span className="text-sm text-[var(--site-muted)]">{linuxInstall.tag}</span>
      </div>

      <div className="mt-5">
        <div className="flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
          <div>
            <p className="site-label text-[var(--site-muted)]">{linuxInstall.label}</p>
            <h3 className="mt-3 text-3xl font-semibold leading-none tracking-[-0.05em] text-[var(--site-ink)] md:text-4xl">
              Fastest route
            </h3>
          </div>
          <p className="max-w-sm text-sm leading-7 text-[var(--site-muted)]">
            {linuxInstall.summary}
          </p>
        </div>

        <div className="mt-6 grid gap-5 lg:grid-cols-[minmax(0,1fr)_220px]">
          <div className="site-code-panel overflow-x-auto">
            <p className="site-label text-[var(--site-muted)]">Bootstrap command</p>
            <pre className="mt-4 whitespace-pre-wrap break-words text-[0.93rem] leading-7 text-[var(--site-ink)]">
              {linuxInstall.command}
            </pre>
          </div>

          <div className="space-y-4 border-t border-[var(--site-line)] pt-4 lg:border-l lg:border-t-0 lg:pl-5 lg:pt-0">
            <div>
              <p className="site-label text-[var(--site-muted)]">Best for</p>
              <p className="mt-2 text-sm leading-7 text-[var(--site-muted)]">{linuxInstall.bestFor}</p>
            </div>
            <p className="text-sm leading-7 text-[var(--site-muted)]">{linuxInstall.traits.join(" / ")}</p>
          </div>
        </div>

        <div className="mt-6 flex flex-col gap-3 sm:flex-row">
          <AppLink href={linuxInstall.href} className="site-button-primary px-6 py-4 text-base">
            Open install guide
          </AppLink>
          <AppLink href="/docs/quickstart" className="site-button-quiet px-4 py-4 text-base">
            Read quickstart
          </AppLink>
        </div>
      </div>
    </div>
  );
}
