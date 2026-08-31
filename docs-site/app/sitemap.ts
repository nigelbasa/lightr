import type { MetadataRoute } from "next";

import { source } from "@/lib/source";

export default function sitemap(): MetadataRoute.Sitemap {
  const base = "https://lightr.nigelbasa.tech";
  const items = [{ url: "/" }, ...source.getPages().map((page) => ({ url: page.url }))];

  return items.map((item) => ({
    url: `${base}${item.url}`,
    lastModified: new Date(),
    changeFrequency: item.url === "/" ? "weekly" : "monthly",
    priority: item.url === "/" ? 1 : 0.7,
  }));
}
