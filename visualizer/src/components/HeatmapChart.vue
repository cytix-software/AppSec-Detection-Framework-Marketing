<!-- HeatmapChart.vue -->
<template>
  <div class="heatmap-chart">
    <apexchart
      type="heatmap"
      width="100%"
      :options="options"
      :series="series"
    />
  </div>
</template>

<script setup lang="ts">
import { defineComponent } from 'vue'
import VueApexCharts from 'vue3-apexcharts'

defineComponent({
  components: {
    apexchart: VueApexCharts
  }
})

defineProps({
  options: { type: Object, required: true },
  series: { type: Array, required: true }
})
</script>

<style scoped>
.heatmap-chart {
  width: 100%;
  overflow-x: auto;
  overflow-y: hidden;
  -webkit-overflow-scrolling: touch;
}

/* Mobile optimizations */
@media (max-width: 768px) {
  .heatmap-chart {
    margin: 0 -1.5rem;
    padding: 0 1.5rem;
  }
}

@media (max-width: 480px) {
  .heatmap-chart {
    margin: 0 -0.75rem;
    padding: 0 0.75rem;
  }
}

.chart-description {
  margin-top: 1rem;
  color: #666;
  line-height: 1.6;
}

/* Ensure ApexCharts canvas is responsive */
:deep(.apexcharts-canvas) {
  margin: 0 auto;
}

:deep(.apexcharts-toolbar) {
  top: 0 !important;
  right: 0 !important;
  padding: 0.5rem 0.75rem;
}

/* Mobile-friendly toolbar */
@media (max-width: 768px) {
  :deep(.apexcharts-toolbar) {
    padding: 0.5rem;
  }

  :deep(.apexcharts-menu-icon svg) {
    width: 20px !important;
    height: 20px !important;
  }
}
</style>
