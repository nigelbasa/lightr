import AppLink from "@/components/AppLink";

function GitHubMark() {
  return (
    <svg
      aria-hidden="true"
      viewBox="0 0 24 24"
      className="h-4 w-4"
      fill="currentColor"
    >
      <path d="M12 2a10 10 0 0 0-3.16 19.49c.5.08.68-.21.68-.48v-1.68c-2.78.61-3.37-1.18-3.37-1.18a2.66 2.66 0 0 0-1.11-1.47c-.9-.62.07-.61.07-.61a2.1 2.1 0 0 1 1.53 1.04 2.14 2.14 0 0 0 2.93.84 2.15 2.15 0 0 1 .64-1.34c-2.22-.25-4.56-1.11-4.56-4.94a3.9 3.9 0 0 1 1.03-2.7 3.63 3.63 0 0 1 .1-2.66s.84-.27 2.75 1.03a9.46 9.46 0 0 1 5 0c1.9-1.3 2.74-1.03 2.74-1.03a3.63 3.63 0 0 1 .1 2.66 3.9 3.9 0 0 1 1.03 2.7c0 3.84-2.35 4.69-4.58 4.93a2.4 2.4 0 0 1 .68 1.87v2.77c0 .27.18.57.69.47A10 10 0 0 0 12 2Z" />
    </svg>
  );
}

export function SiteHeader() {
  return (
    <header className="sticky top-0 z-40 border-b border-[var(--site-line)] bg-[rgba(248,251,253,0.84)] backdrop-blur-xl">
      <div className="site-frame flex min-h-[72px] items-center justify-between gap-4">
        <AppLink href="/" className="flex min-w-0 items-center gap-3">
          <div className="grid h-11 w-11 place-items-center rounded-2xl bg-[var(--site-blue)] text-base font-bold text-white shadow-[0_14px_30px_rgba(37,99,235,0.24)]">
            L
          </div>
          <div className="min-w-0">
            <p className="text-base font-bold tracking-[-0.03em] text-[var(--site-ink)]">
              Lightr
            </p>
            <p className="hidden text-sm text-[var(--site-muted)] sm:block">
              Single-binary mail runtime
            </p>
          </div>
        </AppLink>

        <div className="flex items-center gap-3">
          <a
            href="https://github.com/nigelbasa/lightr"
            target="_blank"
            rel="noreferrer noopener"
            className="site-button-secondary px-4 py-3 text-sm"
          >
            <GitHubMark />
            GitHub
          </a>
          <AppLink href="/docs/quickstart" className="site-button-primary px-4 py-3 text-sm">
            Quickstart
          </AppLink>
        </div>
      </div>
    </header>
  );
}
