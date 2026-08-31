import { chmodSync, copyFileSync, existsSync, mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const docsRoot = resolve(__dirname, "..");
const source = resolve(docsRoot, "..", "quickstart.sh");
const destination = resolve(docsRoot, "public", "install.sh");

if (!existsSync(source)) {
  throw new Error(`Missing installer source: ${source}`);
}

mkdirSync(dirname(destination), { recursive: true });
copyFileSync(source, destination);

try {
  chmodSync(destination, 0o755);
} catch {
  // Best-effort permission update for local Windows checkouts.
}

console.log(`Synced installer to ${destination}`);
