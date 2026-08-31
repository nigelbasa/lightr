import type { BaseLayoutProps } from "fumadocs-ui/layouts/shared";

export function baseOptions(): BaseLayoutProps {
  return {
    nav: {
      title: "Lightr Docs",
      url: "/docs",
    },
    links: [
      {
        type: "main",
        text: "Home",
        url: "/",
      },
      {
        type: "main",
        text: "Install",
        url: "/docs/install",
      },
      {
        type: "main",
        text: "API",
        url: "/docs/api",
      },
      {
        type: "main",
        text: "GitHub",
        url: "https://github.com/nigelbasa/lightr",
        external: true,
      },
    ],
    githubUrl: "https://github.com/nigelbasa/lightr",
    themeSwitch: {
      enabled: false,
    },
  };
}
