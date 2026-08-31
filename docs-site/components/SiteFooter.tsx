import AppLink from "@/components/AppLink";

export function SiteFooter() {
  return (
    <footer className="mt-16 border-t border-[var(--site-line)] bg-white/64 md:mt-24">
      <div className="site-frame py-8 md:py-10">
        <div className="flex flex-col gap-8">
          <div className="grid gap-8 md:grid-cols-[minmax(0,1fr)_auto] md:items-end">
            <div className="space-y-2">
              <p className="text-xl font-bold tracking-[-0.04em] text-[var(--site-ink)]">
                Lightr
              </p>
              <p className="text-sm leading-7 text-[var(--site-muted)]">
                Single-binary mail runtime.
              </p>
            </div>

            <div className="flex flex-wrap gap-x-6 gap-y-3">
              <AppLink
                href="/docs/quickstart"
                className="text-sm font-semibold text-[var(--site-ink)] transition-colors hover:text-[var(--site-blue-strong)]"
              >
                Quickstart
              </AppLink>
              <AppLink
                href="/docs/install"
                className="text-sm font-semibold text-[var(--site-ink)] transition-colors hover:text-[var(--site-blue-strong)]"
              >
                Install
              </AppLink>
              <AppLink
                href="/docs/api"
                className="text-sm font-semibold text-[var(--site-ink)] transition-colors hover:text-[var(--site-blue-strong)]"
              >
                API
              </AppLink>
              <a
                href="https://github.com/nigelbasa/lightr"
                target="_blank"
                rel="noreferrer noopener"
                className="text-sm font-semibold text-[var(--site-ink)] transition-colors hover:text-[var(--site-blue-strong)]"
              >
                GitHub
              </a>
            </div>
          </div>

          <div className="border-t border-[var(--site-line)] pt-5 text-sm text-[var(--site-muted)]">
            <a
              href="https://nigelbasa.tech"
              target="_blank"
              rel="noreferrer noopener"
              className="transition-colors hover:text-[var(--site-blue-strong)]"
            >
              Built by nigelbasa
            </a>
          </div>
        </div>
      </div>
    </footer>
  );
}
