export type NavItem = {
  href: string;
  label: string;
  summary: string;
};

export type NavSection = {
  title: string;
  items: NavItem[];
};

export const docsSections: NavSection[] = [
  {
    title: "Get started",
    items: [
      {
        href: "/docs/install",
        label: "Install",
        summary: "Put Lightr on a machine and understand what the installer creates.",
      },
      {
        href: "/docs/quickstart",
        label: "Quickstart",
        summary: "Start the installed runtime and confirm the host is healthy.",
      },
      {
        href: "/docs/first-domain",
        label: "First Domain",
        summary: "Create the first domain, mailbox, alias, and send/receive loop.",
      },
    ],
  },
  {
    title: "Operate",
    items: [
      {
        href: "/docs/configuration",
        label: "Configuration",
        summary: "Start from a small config and harden it for production.",
      },
      {
        href: "/docs/domains-dns",
        label: "Domains & DNS",
        summary: "Align MX, SPF, DKIM, DMARC, PTR, and your public mail hostname.",
      },
      {
        href: "/docs/health-logs",
        label: "Health & Logs",
        summary: "Use health checks, logs, queue tools, and spam inspection before guessing.",
      },
      {
        href: "/docs/api",
        label: "API",
        summary: "Provision domains, accounts, mailbox flows, and outbound send.",
      },
      {
        href: "/docs/troubleshooting",
        label: "Troubleshooting",
        summary: "Work through runtime, ports, TLS, DNS, queue state, and delivery issues in order.",
      },
    ],
  },
];

export const allDocItems = docsSections.flatMap((section) => section.items);

export function getDocNeighbors(pathname: string) {
  const index = allDocItems.findIndex((item) => item.href === pathname);

  if (index === -1) {
    return { previous: null, next: null };
  }

  return {
    previous: index > 0 ? allDocItems[index - 1] : null,
    next: index < allDocItems.length - 1 ? allDocItems[index + 1] : null,
  };
}
