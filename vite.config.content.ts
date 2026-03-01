// vite.config.content.ts - Build content script as IIFE
import { defineConfig } from 'vite';
import { resolve } from 'path';

export default defineConfig({
  build: {
    outDir: 'dist',
    lib: {
      entry: resolve(__dirname, 'src/content/index.ts'),
      name: 'ContentScript',
      formats: ['iife'],
      fileName: () => 'content.js'
    },
    rollupOptions: {
      output: {
        extend: true,
        inlineDynamicImports: true // Bundle everything into one file
      }
    },
    minify: false,
    sourcemap: true,
    emptyOutDir: false // Don't delete other files
  },
  resolve: {
    alias: {
      '@': resolve(__dirname, './src')
    }
  }
});
