<template>
  <div class="app-container">
    <NConfigProvider>
      <Suspense>
        <template #default>
          <DashboardPage />
        </template>
        <template #fallback>
          <div class="loading-container">
            <n-spin size="large" />
            <p>Loading...</p>
          </div>
        </template>
      </Suspense>
    </NConfigProvider>
  </div>
</template>

<script setup lang="ts">
import DashboardPage from './components/DashboardPage.vue'
import { NConfigProvider, NSpin } from 'naive-ui'
</script>

<style>
/* Global styles that need to affect child components */
.app-container {
  font-family:
    -apple-system,
    BlinkMacSystemFont,
    'Segoe UI',
    Roboto,
    'Helvetica Neue',
    Arial,
    sans-serif;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
  color: #020E1E;
  background: linear-gradient(135deg, #ffffff 0%, #f5f5f5 100%);
  min-height: 100vh;
}

.loading-container {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  min-height: 100vh;
  gap: 1rem;
  background: linear-gradient(135deg, #ffffff 0%, #f5f5f5 100%);
}

.loading-container p {
  color: #FF822E;
  font-weight: 600;
}

/* Global ApexCharts tooltip styling */
.apexcharts-tooltip {
  background: #ffffff !important;
  border: 2px solid #FF822E !important;
  border-radius: 12px !important;
  box-shadow: 0 4px 20px rgba(255, 130, 46, 0.2) !important;
}

.apexcharts-tooltip-title {
  background: #020E1E !important;
  color: #ffffff !important;
  font-family: 'Plus Jakarta Sans', sans-serif !important;
  font-weight: 700 !important;
  padding: 12px !important;
  border-radius: 8px 8px 0 0 !important;
}

.apexcharts-tooltip-series-group {
  background: #ffffff !important;
  padding: 8px 12px !important;
}

.apexcharts-tooltip-marker {
  background: #FF822E !important;
}

/* Global table styling */
:deep(.n-data-table .n-data-table-th) {
  background: #020E1E !important;
  color: #ffffff !important;
  font-weight: 700 !important;
  font-family: 'Plus Jakarta Sans', sans-serif !important;
}

:deep(.n-data-table .n-data-table-td) {
  border-bottom: 1px solid #F0F0F0 !important;
}

:deep(.n-data-table .n-data-table-tr:hover) {
  background: rgba(255, 130, 46, 0.05) !important;
}

/* Global Naive UI customizations */
:deep(.n-spin) {
  color: #FF822E;
}

:deep(.n-spin-item) {
  background: #FF822E;
}
</style>
