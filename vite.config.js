import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite'; // <-- NEW IMPORT

export default defineConfig({
  plugins: [react(), tailwindcss()], // <-- ADDED tailwindcss() TO PLUGINS ARRAY
  server: {
    // The port for the web browser (Frontend)
    port: 5173, 
  },
});