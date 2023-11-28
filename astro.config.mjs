import { defineConfig } from 'astro/config';
import tailwind from "@astrojs/tailwind";
import react from "@astrojs/react";
import solidJs from "@astrojs/solid-js";
import node from "@astrojs/node";

// https://astro.build/config
export default defineConfig({
  // remove this line
  // renderers: ['@astrojs/renderer-react'],
  // add this line
  integrations: [tailwind(), react(), solidJs()],
  // ... other configurations ...
  output: "server",
  adapter: node({
    mode: "standalone"
  }),
});
