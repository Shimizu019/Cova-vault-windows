import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// Tauri sets TAURI_DEV_HOST when developing against a physical device or a
// remote host. On plain localhost it is unset and the defaults below apply.
const host = process.env.TAURI_DEV_HOST

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],

  // Tauri owns the terminal output; keep Vite's banner out of the way.
  clearScreen: false,

  server: {
    // Tauri expects a fixed port and fails loudly if it is taken.
    port: 1420,
    strictPort: true,
    host: host || false,
    // HMR on a dedicated port so it never collides with the app window.
    hmr: host ? { protocol: 'ws', host, port: 1421 } : undefined,
    watch: {
      // Rust sources are rebuilt by Cargo, not Vite.
      ignored: ['**/src-tauri/**'],
    },
  },

  envPrefix: ['VITE_', 'TAURI_ENV_*'],

  build: {
    // Tauri v2 ships a modern Chromium (WebView2); target it directly.
    target: 'esnext',
    sourcemap: false,
    chunkSizeWarningLimit: 1200,
  },
})
