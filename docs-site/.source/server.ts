// @ts-nocheck
import * as __fd_glob_10 from "../content/docs/(operate)/troubleshooting.mdx?collection=docs"
import * as __fd_glob_9 from "../content/docs/(operate)/health-logs.mdx?collection=docs"
import * as __fd_glob_8 from "../content/docs/(operate)/domains-dns.mdx?collection=docs"
import * as __fd_glob_7 from "../content/docs/(operate)/configuration.mdx?collection=docs"
import * as __fd_glob_6 from "../content/docs/(operate)/api.mdx?collection=docs"
import * as __fd_glob_5 from "../content/docs/(getting-started)/quickstart.mdx?collection=docs"
import * as __fd_glob_4 from "../content/docs/(getting-started)/install.mdx?collection=docs"
import * as __fd_glob_3 from "../content/docs/(getting-started)/index.mdx?collection=docs"
import * as __fd_glob_2 from "../content/docs/(getting-started)/first-domain.mdx?collection=docs"
import { default as __fd_glob_1 } from "../content/docs/(operate)/meta.json?collection=docs"
import { default as __fd_glob_0 } from "../content/docs/(getting-started)/meta.json?collection=docs"
import { server } from 'fumadocs-mdx/runtime/server';
import type * as Config from '../source.config';

const create = server<typeof Config, import("fumadocs-mdx/runtime/types").InternalTypeConfig & {
  DocData: {
  }
}>({"doc":{"passthroughs":["extractedReferences"]}});

export const docs = await create.docs("docs", "content/docs", {"(getting-started)/meta.json": __fd_glob_0, "(operate)/meta.json": __fd_glob_1, }, {"(getting-started)/first-domain.mdx": __fd_glob_2, "(getting-started)/index.mdx": __fd_glob_3, "(getting-started)/install.mdx": __fd_glob_4, "(getting-started)/quickstart.mdx": __fd_glob_5, "(operate)/api.mdx": __fd_glob_6, "(operate)/configuration.mdx": __fd_glob_7, "(operate)/domains-dns.mdx": __fd_glob_8, "(operate)/health-logs.mdx": __fd_glob_9, "(operate)/troubleshooting.mdx": __fd_glob_10, });