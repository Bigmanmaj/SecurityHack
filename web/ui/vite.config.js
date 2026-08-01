import { fileURLToPath, URL } from "node:url";
import { defineConfig } from "vite";
import vue from "@vitejs/plugin-vue";

// Built assets land in web/static, which the Python server serves directly, so the
// demo needs no npm at run time. `npm run dev` proxies the API to that server.
export default defineConfig({
  plugins: [vue()],
  base: "./",
  build: {
    outDir: fileURLToPath(new URL("../static", import.meta.url)),
    emptyOutDir: true,
  },
  server: {
    port: 5173,
    proxy: { "/api": "http://127.0.0.1:8000" },
  },
});
