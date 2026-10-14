import { defineConfig, loadEnv } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import { fileURLToPath, URL } from "node:url";

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), "");
  return {
    plugins: [react(), tailwindcss()],
    resolve: {
      alias: { "@": fileURLToPath(new URL("./src", import.meta.url)) },
    },
    server: {
      port: 5173,
      strictPort: true,
      proxy: {
        "/api": {
          target: env.AEGIS_API_TARGET || "http://127.0.0.1:8000",
          changeOrigin: true,
          rewrite: (path) => path.replace(/^\/api/, ""),
          timeout: 0,
          proxyTimeout: 0,
        },
      },
    },
    preview: {
      port: 4173,
      proxy: {
        "/api": {
          target: env.AEGIS_API_TARGET || "http://127.0.0.1:8000",
          changeOrigin: true,
          rewrite: (path) => path.replace(/^\/api/, ""),
          timeout: 0,
          proxyTimeout: 0,
        },
      },
    },
  };
});
