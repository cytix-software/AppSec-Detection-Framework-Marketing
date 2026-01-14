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
.chart-description {
  margin-top: 1rem;
  color: #666;
  line-height: 1.6;
}
</style>
