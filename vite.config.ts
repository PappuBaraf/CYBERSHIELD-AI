import { defineConfig } from "vite";
import react from "@vitejs/plugin-react-swc";
import path from "path";

const apiPort = process.env.PORT || "3001";

export default defineConfig({
  plugins: [react()],
  resolve: { alias: { "@": path.resolve(__dirname, "src") } },
  server: {
    port: 5000,
    host: process.env.VITE_HOST || "127.0.0.1",
    allowedHosts: ["contractscan.replit.app"],
    proxy: {
      "/api": { target: `http://127.0.0.1:${apiPort}`, changeOrigin: true },
    },
  },
  preview: { allowedHosts: ["contractscan.replit.app"] },
  build: { outDir: "dist/public" },
});
