import { cloudflare } from "@cloudflare/vite-plugin";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

export default defineConfig({
  plugins: [react(), cloudflare()],
  // Nothing from the environment is exposed to client code. Secrets belong to
  // the Worker only; an empty prefix list would expose everything, so use a
  // prefix nothing is allowed to use.
  envPrefix: "LIGHTAGENT_PUBLIC_",
  // Vite marks the tags it emits (and, in dev, the <style> elements it injects)
  // with this placeholder; the Worker replaces it with a per-response nonce.
  html: { cspNonce: "LIGHTAGENT_CSP_NONCE" },
  build: {
    sourcemap: false,
  },
});
