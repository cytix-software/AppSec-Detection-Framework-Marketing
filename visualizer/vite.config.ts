import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import yaml from '@modyfi/vite-plugin-yaml'
import path from 'path'
import AutoImport from 'unplugin-auto-import/vite'
import AutoComponent from 'unplugin-vue-components/vite'

export default defineConfig({
  plugins: [
    vue(),
    AutoImport({
      imports: ['vue', 'vue-router'],
      dts: true,
      eslintrc: { enabled: true },
    }),
    AutoComponent({ dts: true }),
    yaml(),
  ],
  build: {
    target: 'es2022',
  },
  server: {
    fs: {
      allow: [path.resolve('..')],
    },
  },
  resolve: {
    alias: {
      '@data': path.resolve(__dirname, '../'),
    },
  },
})
