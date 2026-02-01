import { defineConfig } from 'astro/config';
import tailwind from '@astrojs/tailwind';

export default defineConfig({
  site: 'https://artifactkeeper.com',
  integrations: [tailwind()],
});
