import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  root: "demo",
  base: "./",
  plugins: [react()],
  server: { port: 5179, strictPort: true, fs: { allow: [".."] } },
  preview: { port: 5180, strictPort: true },
  build: { outDir: "../dist-demo", emptyOutDir: true },
});
