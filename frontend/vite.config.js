import { defineConfig } from 'vite'
import { svelte } from '@sveltejs/vite-plugin-svelte'

export default defineConfig({
  plugins: [svelte()],
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: 'http://localhost:8091',
        changeOrigin: true,
      },
    },
  },
  build: {
    rollupOptions: {
      output: {
        // bp8: pull the always-needed Svelte runtime into a long-lived
        // `vendor` chunk so it caches across route navigations. sortablejs
        // is deliberately NOT forced here — it is only imported by the
        // RuleEditor route (via lib/sortable.js), so Rollup naturally bundles
        // it INTO the lazy RuleEditor chunk, keeping it off the first-paint
        // critical path. Per-route splitting itself comes from the
        // {#await import('./routes/X.svelte')} calls in App.svelte; no need
        // to enumerate the routes here.
        manualChunks(id) {
          if (id.includes('node_modules/svelte/')) {
            return 'vendor'
          }
        },
      },
    },
  },
})
