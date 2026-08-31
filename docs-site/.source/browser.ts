// @ts-nocheck
import { browser } from 'fumadocs-mdx/runtime/browser';
import type * as Config from '../source.config';

const create = browser<typeof Config, import("fumadocs-mdx/runtime/types").InternalTypeConfig & {
  DocData: {
  }
}>();
const browserCollections = {
  docs: create.doc("docs", {"(getting-started)/first-domain.mdx": () => import("../content/docs/(getting-started)/first-domain.mdx?collection=docs"), "(getting-started)/index.mdx": () => import("../content/docs/(getting-started)/index.mdx?collection=docs"), "(getting-started)/install.mdx": () => import("../content/docs/(getting-started)/install.mdx?collection=docs"), "(getting-started)/quickstart.mdx": () => import("../content/docs/(getting-started)/quickstart.mdx?collection=docs"), "(operate)/api.mdx": () => import("../content/docs/(operate)/api.mdx?collection=docs"), "(operate)/configuration.mdx": () => import("../content/docs/(operate)/configuration.mdx?collection=docs"), "(operate)/domains-dns.mdx": () => import("../content/docs/(operate)/domains-dns.mdx?collection=docs"), "(operate)/health-logs.mdx": () => import("../content/docs/(operate)/health-logs.mdx?collection=docs"), "(operate)/troubleshooting.mdx": () => import("../content/docs/(operate)/troubleshooting.mdx?collection=docs"), }),
};
export default browserCollections;