import type { Metadata } from "next";
import { IBM_Plex_Mono, Space_Grotesk } from "next/font/google";
import { RootProvider } from "fumadocs-ui/provider/next";

import "./globals.css";

const spaceGrotesk = Space_Grotesk({
  subsets: ["latin"],
  variable: "--font-sans",
  weight: ["400", "500", "700"],
});

const plexMono = IBM_Plex_Mono({
  subsets: ["latin"],
  variable: "--font-mono",
  weight: ["400", "500"],
});

export const metadata: Metadata = {
  metadataBase: new URL("https://lightr.nigelbasa.tech"),
  title: {
    default: "Lightr Docs",
    template: "%s | Lightr Docs",
  },
  description:
    "Documentation for Lightr, a self-hosted email engine written in Go.",
  applicationName: "Lightr Docs",
  openGraph: {
    title: "Lightr Docs",
    description:
      "Install, configure, and operate a self-hosted email engine written in Go.",
    url: "https://lightr.nigelbasa.tech",
    siteName: "Lightr Docs",
    type: "website",
  },
  twitter: {
    card: "summary_large_image",
    title: "Lightr Docs",
    description:
      "Install, configure, and operate a self-hosted email engine written in Go.",
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body className={`${spaceGrotesk.variable} ${plexMono.variable}`}>
        <RootProvider>{children}</RootProvider>
      </body>
    </html>
  );
}
