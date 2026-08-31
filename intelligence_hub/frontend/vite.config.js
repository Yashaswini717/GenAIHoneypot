import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// Where the dashboard's /api and /ws calls get proxied.
//
// This must be the backend's address *as seen from wherever Vite is running*,
// which is not the same in both setups:
//
//   docker compose   Vite runs inside the frontend container, so `localhost`
//                    is that container — nothing listens on :8000 there. It
//                    has to be the compose service name, `backend`.
//   npm run dev      Vite runs on your machine, where localhost:8000 is the
//                    backend's published port. Set VITE_API_TARGET for this.
//
// Hardcoding localhost is why the dashboard hung on "Loading intelligence
// data..." under compose: every /api request was proxied into the frontend
// container itself and never reached the backend at all.
const target = process.env.VITE_API_TARGET || 'http://backend:8000'
const wsTarget = target.replace(/^http/, 'ws')

export default defineConfig({
  plugins: [react()],
  server: {
    host: '0.0.0.0',
    port: 5173,
    proxy: {
      '/api': {
        target,
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/api/, '')
      },
      '/ws': {
        target: wsTarget,
        ws: true
      }
    }
  }
})
