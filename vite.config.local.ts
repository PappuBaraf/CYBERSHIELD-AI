import { defineConfig, mergeConfig } from "vite";
import baseConfig from "./vite.config";

export default mergeConfig(
  baseConfig,
  defineConfig({
    server: {
      watch: {
        ignored: ["**/.local/**", "**/node_modules/**"],
      },
    },
  })
);
