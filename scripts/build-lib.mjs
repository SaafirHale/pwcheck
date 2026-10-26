// Library build: type-check and emit dist/ with tsc, then copy the stylesheet.
// tsc is called through node because npx.cmd cannot be spawned from Node on Windows.
import { spawnSync } from "node:child_process";
import { copyFileSync, mkdirSync, rmSync } from "node:fs";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("..", import.meta.url));
const require = createRequire(import.meta.url);
const tsc = require.resolve("typescript/bin/tsc");

rmSync(`${root}dist`, { recursive: true, force: true });
const r = spawnSync(process.execPath, [tsc, "-p", "tsconfig.build.json"], { cwd: root, stdio: "inherit" });
if (r.status !== 0) process.exit(r.status ?? 1);

mkdirSync(`${root}dist/react`, { recursive: true });
copyFileSync(`${root}src/react/styles.css`, `${root}dist/react/styles.css`);
