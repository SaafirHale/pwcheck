import { defineConfig, type Plugin } from "vite";
import react from "@vitejs/plugin-react";

/**
 * Production builds get a Content-Security-Policy that allows exactly one
 * outside connection: the Pwned Passwords range API. Left out of the dev server,
 * whose hot reload needs inline scripts and a websocket.
 */
const CSP = [
  "default-src 'self'",
  "script-src 'self'",
  "style-src 'self'",
  "font-src 'self'",
  "img-src 'self' data:",
  "connect-src https://api.pwnedpasswords.com",
  "base-uri 'none'",
  "form-action 'none'",
  "object-src 'none'",
].join("; ");

function csp(): Plugin {
  return {
    name: "pwcheck-csp",
    apply: "build",
    transformIndexHtml: (html) =>
      html.replace('<meta charset="UTF-8" />', `<meta charset="UTF-8" />\n    <meta http-equiv="Content-Security-Policy" content="${CSP}" />`),
  };
}

export default defineConfig({
  root: "demo",
  base: "./",
  plugins: [react(), csp()],
  server: { port: 5179, strictPort: true, fs: { allow: [".."] } },
  preview: { port: 5180, strictPort: true },
  // No inlined data: assets, so the CSP can keep font-src and img-src to 'self'.
  build: { outDir: "../dist-demo", emptyOutDir: true, assetsInlineLimit: 0 },
});
