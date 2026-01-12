<!-- DashboardPage.vue -->
<template>
  <div class="dashboard-container">
    <div class="page-header">
      <div class="header-content">
        <h1 class="page-title">
          <span class="title-part-1">AppSec Detection Framework</span>
          <span class="title-part-2">Visualiser</span>
        </h1>
        <p class="page-subheading">Reducing vulnerability blindspots across SAST, DAST & AI Pentesting</p>
      </div>
      <img src="https://cdn.builder.io/api/v1/image/assets%2F0ae2d7cfe4b54f369c000b904ffc735e%2Fa5aecfd598a046dc9db2297204b0fd74?format=webp&width=800" alt="Cytix Logo" class="cytix-logo" />
    </div>

    <div class="main-content">
      <!-- Coverage Gap Analysis -->
      <n-card class="coverage-gap-wrapper">
        <ToolCoverageGap @tools-selected="handleToolsSelected" />
      </n-card>
      
      <!-- Charts Section -->
      <div class="charts-section">
        <!-- Heatmap and Radar Charts in Tabs -->
        <n-card title="Vulnerability Detection Coverage Analysis" class="chart-wrapper">
          <div class="chart-description">
            <p class="chart-subheading">
              Compare the detection coverage for OWASP Top 10 vulnerabilities against selected security tools.<br><br>The higher the percentage, the higher the detection capabilities.
            </p>
          </div>
          <div class="chart-tools-filter">
            <label class="filter-label">Security Tools</label>
            <n-select
              v-model:value="selectedChartTools"
              multiple
              filterable
              placeholder="Select tools to display"
              :options="toolOptions"
              style="width: 100%; max-width: 400px"
            />
          </div>
          <n-tabs type="line" animated>
            <n-tab-pane name="heatmap-2021" tab="OWASP 2021 (Heatmap)">
              <div class="tab-content">
                <HeatmapChart
                  :options="heatmapOptions"
                  :series="filteredHeatmapSeries2021"
                />
              </div>
            </n-tab-pane>
            <n-tab-pane name="heatmap-2025" tab="OWASP 2025 (Heatmap)">
              <div class="tab-content">
                <p class="tab-description">OWASP Top 10 2025 - Shows detection coverage across the 2025 vulnerability classification</p>
                <HeatmapChart
                  :options="heatmapOptions"
                  :series="filteredHeatmapSeries2025"
                />
              </div>
            </n-tab-pane>
            <n-tab-pane name="radar" tab="Tool Comparison">
              <div class="tab-content">
                <p class="tab-description">Tool Comparison - Radar chart showing relative detection coverage for each security tool across all OWASP categories</p>
                <RadarChart :options="radarOptions" :series="filteredRadarSeries" />
              </div>
            </n-tab-pane>
          </n-tabs>
        </n-card>

        <!-- Bar Chart -->
        <n-card title="Tool Performance (Bar)" class="chart-wrapper">
          <BarChart :options="filteredBarOptions" :series="filteredBarSeries" />
        </n-card>
      </div>

      <!-- Dataset Table -->
      <n-collapse class="data-table-wrapper">
        <n-collapse-item title="Dataset" name="dataset">
          <DataTable :data="filteredHydratedTests" />
        </n-collapse-item>
      </n-collapse>
    </div>
  </div>
</template>

<script setup lang="ts">
// -----------------------------------------------------------------------------
// Imports
// -----------------------------------------------------------------------------
import { NCard, NTabs, NTabPane, NCollapse, NCollapseItem } from 'naive-ui'
import { groupBy, filter, find, some, includes, flatten, map } from 'lodash-es'
import { loadData } from './data'
import RadarChart from './RadarChart.vue'
import BarChart from './BarChart.vue'
import HeatmapChart from './HeatmapChart.vue'
import DataTable from './DataTable.vue'
import ToolCoverageGap from './ToolCoverageGap.vue'
import { computed, ref } from 'vue'

const { hydratedTests, hydratedHeatmapTests, vulnerabilities } = loadData()

// Split the combined list by year
const vulnerabilities2021 = computed(() =>
  vulnerabilities.filter(v => v.OWASP.includes('2021'))
)
const vulnerabilities2025 = computed(() =>
  vulnerabilities.filter(v => v.OWASP.includes('2025'))
)

// Technologies used for bar chart calculations
const technologies = ['php', 'nodejs']

// Selected tools state for charts (independent from Coverage Gap Analysis)
const selectedChartTools = ref<string[]>([])

// Tool options for the chart filter
const toolOptions = computed(() => {
  const scanners = [...new Set(hydratedHeatmapTests.map((t) => t.scanner))]
  return scanners.map((scanner) => ({
    label: scanner,
    value: scanner
  }))
})

// Filter hydrated tests based on selected tools (for dataset table)
// Note: Dataset is only filtered by Coverage Gap Analysis selection
const filteredHydratedTests = computed(() => hydratedTests)

// Filter hydrated heatmap tests based on selected chart tools
const filteredHydratedHeatmapTests = computed(() => {
  if (selectedChartTools.value.length === 0) return hydratedHeatmapTests

  return hydratedHeatmapTests.filter(test =>
    selectedChartTools.value.includes(test.scanner)
  )
})

// -----------------------------------------------------------------------------
// forHeatMap (Heatmap Chart Logic) - 2021
// -----------------------------------------------------------------------------
const heatmapData2021 = computed(() =>
  // Use the 2021-specific list
  vulnerabilities2021.value.flatMap(({ OWASP, CWEDetails }) => {
    const uniqueTests = filteredHydratedHeatmapTests.value
    
    const groupedByScanner = groupBy(uniqueTests, 'scanner')
    return Object.entries(groupedByScanner).map(([scanner, tests]) => {
      // For each test, count how many CWEs from this OWASP category were detected/undetected
      let detectedCount = 0
      let totalCount = 0

      tests.forEach(test => {
        // Count detected CWEs that belong to this OWASP category
        const detectedInCategory = test.detectedCWEs.filter(cwe => 
          CWEDetails.some(detail => detail.id === cwe)
        )
        detectedCount += detectedInCategory.length

        // Count total CWEs that belong to this OWASP category
        const totalInCategory = [
          ...test.detectedCWEs,
          ...(test.undetectedCWEs || [])
        ].filter(cwe => CWEDetails.some(detail => detail.id === cwe))
        totalCount += totalInCategory.length
      })

      return {
        scanner,
        OWASP,
        detectedCWEs: detectedCount,
        totalCount
      }
    })
  })
)

const heatmapSeries2021 = computed(() => {
  const scanners = [...new Set(hydratedHeatmapTests.map((t) => t.scanner))]

  return scanners.map((scanner) => {
    // Use the 2021-specific list
    const data = vulnerabilities2021.value.map(({ OWASP }) => {
      // Use the 2021-specific data
      const entry = find(heatmapData2021.value, { scanner, OWASP })

      // If no test coverage at all, treat as "No Data"
      const isNoData = !entry || entry.totalCount === 0
      const percentage = isNoData ? 0 : Math.round((entry.detectedCWEs / entry.totalCount) * 100)
      const labelColor = isNoData || percentage <= 25 ? '#000' : '#fff'

      return {
        x: OWASP,
        y: percentage,
        isNoData,
        dataLabels: {
          enabled: true,
          style: {
            colors: [labelColor],
          },
        },
      }
    })

    return { name: scanner, data }
  })
})

const filteredHeatmapSeries2021 = computed(() => {
  if (selectedChartTools.value.length === 0) return heatmapSeries2021.value

  return heatmapSeries2021.value.filter(series =>
    selectedChartTools.value.includes(series.name)
  )
})

// -----------------------------------------------------------------------------
// forHeatMap (Heatmap Chart Logic) - 2025
// -----------------------------------------------------------------------------
const heatmapData2025 = computed(() =>
  // Use the 2025-specific list
  vulnerabilities2025.value.flatMap(({ OWASP, CWEDetails }) => {
    const uniqueTests = filteredHydratedHeatmapTests.value

    const groupedByScanner = groupBy(uniqueTests, 'scanner')
    return Object.entries(groupedByScanner).map(([scanner, tests]) => {
      let detectedCount = 0
      let totalCount = 0

      tests.forEach(test => {
        const detectedInCategory = test.detectedCWEs.filter(cwe => 
          CWEDetails.some(detail => detail.id === cwe)
        )
        detectedCount += detectedInCategory.length

        const totalInCategory = [
          ...test.detectedCWEs,
          ...(test.undetectedCWEs || [])
        ].filter(cwe => CWEDetails.some(detail => detail.id === cwe))
        totalCount += totalInCategory.length
      })

      return {
        scanner,
        OWASP,
        detectedCWEs: detectedCount,
        totalCount
      }
    })
  })
)

const heatmapSeries2025 = computed(() => {
  const scanners = [...new Set(hydratedHeatmapTests.map((t) => t.scanner))]

  return scanners.map((scanner) => {
    // Use the 2025-specific list
    const data = vulnerabilities2025.value.map(({ OWASP }) => {
      // Use the 2025-specific data
      const entry = find(heatmapData2025.value, { scanner, OWASP })

      const isNoData = !entry || entry.totalCount === 0
      const percentage = isNoData ? 0 : Math.round((entry.detectedCWEs / entry.totalCount) * 100)
      const labelColor = isNoData || percentage <= 25 ? '#000' : '#fff'

      return {
        x: OWASP,
        y: percentage,
        isNoData,
        // Per data point override for text styling
        dataLabels: {
          enabled: true,
          style: {
            colors: [labelColor],
          },
        },
      }
    })

    return { name: scanner, data }
  })
})

const filteredHeatmapSeries2025 = computed(() => {
  if (selectedChartTools.value.length === 0) return heatmapSeries2025.value

  return heatmapSeries2025.value.filter(series =>
    selectedChartTools.value.includes(series.name)
  )
})

// -----------------------------------------------------------------------------
// Shared Heatmap Options
// -----------------------------------------------------------------------------

const heatmapOptions = computed(() => ({
  chart: { type: 'heatmap' },
  plotOptions: {
    heatmap: {
      shadeIntensity: 0.5,
      colorScale: {
        ranges: [
          { from: 0, to: 0, color: '#EBEBEB' },
          { from: 1, to: 25, color: '#FFD9B8' },
          { from: 26, to: 50, color: '#FFB366' },
          { from: 51, to: 75, color: '#FF822E' },
          { from: 76, to: 100, color: '#020E1E' },
        ],
      },
    },
  },

  // 1) Data labels in each cell
  dataLabels: {
    enabled: true,
    formatter(val: number, opts: any) {
      // Access the data object
      const point = opts.w.config.series[opts.seriesIndex].data[opts.dataPointIndex]
      return point.isNoData ? 'No Data' : `${val}%`
    },
  },

  // 2) Tooltip
  tooltip: {
    y: {
      formatter(val: number, opts: any) {
        const point = opts.w.config.series[opts.seriesIndex].data[opts.dataPointIndex]
        if (point.isNoData) return 'No Data'

        // Find the entry in the correct heatmapData (try 2021 then 2025)
        const scannerName = opts.w.config.series[opts.seriesIndex].name
        const owaspCategory = point.x

        let entry = find(heatmapData2021.value, {
          scanner: scannerName,
          OWASP: owaspCategory
        })

        if (!entry) {
          entry = find(heatmapData2025.value, {
            scanner: scannerName,
            OWASP: owaspCategory
          })
        }

        if (entry) {
          return `${entry.detectedCWEs}/${entry.totalCount} (${val}%)`
        }

        return `${val}%`
      },
    },
  },
}))

// -----------------------------------------------------------------------------
// forPerformance (Bar Chart Logic)
// -----------------------------------------------------------------------------
function calculateWeightedScores() {
  const grouped = groupBy(filteredHydratedHeatmapTests.value, 'scanner')

  return Object.entries(grouped).map(([scanner, tests]) => {
    // group all technologies for these tests
    const techCounts = groupBy(
      tests.flatMap((t) => t.profiles.filter((p) => includes(technologies, p))),
      (tech) => tech,
    )

    let totalWeight = 0
    let detectedWeight = 0

    tests.forEach((test) => {
      // relevant techs for each test
      const relevantTechs = test.profiles.filter((p) => includes(technologies, p))
      if (!relevantTechs.length) return

      // weighting for these techs
      const weight =
        relevantTechs.reduce((sum, tech) => sum + 1 / (techCounts[tech]?.length || 1), 0) /
        relevantTechs.length

      totalWeight += weight

      // avoid dividing by zero
      const cweCount = (test.detectedCWEs?.length || 0) + (test.undetectedCWEs?.length || 0)
      if (cweCount > 0) {
        const weightContribution = (weight / cweCount) * test.detectedCWEs.length
        detectedWeight += weightContribution
      }
    })

    const score = totalWeight ? Number(((detectedWeight / totalWeight) * 100).toFixed(2)) : 0
    return { scanner, score }
  })
}

const barSeries = computed(() => [
  {
    name: 'Weighted Detection Score',
    data: calculateWeightedScores().map((d) => d.score),
  },
])

// Filtered bar series based on selected chart tools
const filteredBarSeries = computed(() => {
  if (selectedChartTools.value.length === 0) return barSeries.value

  const scores = calculateWeightedScores()
  const filteredScores = scores.filter(score =>
    selectedChartTools.value.includes(score.scanner)
  )

  return [{
    name: 'Weighted Detection Score',
    data: filteredScores.map((d) => d.score),
  }]
})

const barOptions = computed(() => ({
  chart: { type: 'bar' },
  xaxis: {
    categories: calculateWeightedScores().map((d) => d.scanner),
    title: { text: 'Tools' },
  },
  yaxis: {
    title: { text: 'Weighted Detection Score (%)' },
    max: 100,
  },
  colors: ['#FF822E'],
  plotOptions: {
    bar: {
      borderRadius: 8,
      dataLabels: {
        position: 'top'
      }
    }
  }
}))

// Filtered bar options based on selected chart tools
const filteredBarOptions = computed(() => {
  if (selectedChartTools.value.length === 0) return barOptions.value

  const scores = calculateWeightedScores()
  const filteredScores = scores.filter(score =>
    selectedChartTools.value.includes(score.scanner)
  )

  return {
    ...barOptions.value,
    xaxis: {
      ...barOptions.value.xaxis,
      categories: filteredScores.map((d) => d.scanner),
    }
  }
})

// -----------------------------------------------------------------------------
// Radar Chart Logic
// -----------------------------------------------------------------------------
const radarData = computed(() => {
  const scanners = [...new Set(filteredHydratedHeatmapTests.value.map((t) => t.scanner))]
  
  return scanners.map(scanner => {
    const data = vulnerabilities.map(({ OWASP }) => {
      let entry = find(heatmapData2021.value, { scanner, OWASP })
      if (!entry) {
        entry = find(heatmapData2025.value, { scanner, OWASP })
      }
      if (!entry || entry.totalCount === 0) return 0
      return Math.round((entry.detectedCWEs / entry.totalCount) * 100)
    })

    return {
      name: scanner,
      data
    }
  })
})

const radarSeries = computed(() => radarData.value)

// Filtered radar series based on selected chart tools
const filteredRadarSeries = computed(() => {
  if (selectedChartTools.value.length === 0) return radarSeries.value

  return radarSeries.value.filter(series =>
    selectedChartTools.value.includes(series.name)
  )
})

const radarOptions = computed(() => ({
  chart: {
    type: 'radar',
    toolbar: {
      show: false
    }
  },
  xaxis: {
    categories: vulnerabilities.map(v => v.OWASP)
  },
  yaxis: {
    show: false,
    min: 0,
    max: 100
  },
  plotOptions: {
    radar: {
      size: 140,
      polygons: {
        strokeColors: '#FF822E',
        fill: {
          colors: ['rgba(255, 130, 46, 0.05)', 'rgba(255, 130, 46, 0.1)']
        }
      }
    }
  },
  colors: ['#FF822E', '#89F336', '#DA4100', '#FFB366', '#020E1E', '#8B5CF6'],
  stroke: {
    width: 2
  },
  fill: {
    opacity: 0.15
  },
  markers: {
    size: 4,
    colors: ['#FF822E', '#89F336', '#DA4100', '#FFB366', '#020E1E', '#8B5CF6'],
    strokeColors: ['#ffffff', '#ffffff', '#ffffff', '#ffffff', '#ffffff', '#ffffff'],
    strokeWidth: 2
  },
  tooltip: {
    y: {
      formatter: (val: number) => `${val}%`
    }
  }
}))
</script>

<style>
.dashboard-container {
  padding: 2rem 3rem;
  margin: 0 auto;
  max-width: 1400px;
  overflow-x: hidden;
  background: linear-gradient(135deg, #ffffff 0%, #f5f5f5 100%);
  min-height: 100vh;
}

@media (max-width: 1200px) {
  .dashboard-container {
    padding: 2rem 2rem;
    max-width: 1200px;
  }
}

@media (max-width: 768px) {
  .dashboard-container {
    padding: 1.5rem 1rem;
    max-width: 100%;
  }
}

.page-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: 2rem;
  margin-bottom: 3rem;
  padding-bottom: 2rem;
  border-bottom: 1px solid rgba(255, 130, 46, 0.1);
}

.header-content {
  flex: 1;
}

.page-title {
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
  font-weight: 900;
  font-size: 3rem;
  line-height: 1;
  letter-spacing: -0.02em;
  margin-bottom: 0;
  display: flex;
  flex-wrap: wrap;
  gap: 0.5rem;
  flex: 1;
}

.cytix-logo {
  height: 80px;
  width: auto;
  object-fit: contain;
  flex-shrink: 0;
}

/* sm: text-6xl (3.75rem) */
@media (min-width: 640px) {
  .page-title {
    font-size: 3.75rem;
  }
}

/* lg: text-7xl (4.5rem) + mb-14 (3.5rem) */
@media (min-width: 1024px) {
  .page-title {
    font-size: 4.5rem;
  }

  .page-header {
    margin-bottom: 3.5rem;
  }
}

/* xl: text-8xl (6rem) */
@media (min-width: 1280px) {
  .page-title {
    font-size: 6rem;
  }
}

/* Mobile: adjust header layout for smaller screens */
@media (max-width: 768px) {
  .page-header {
    flex-direction: column;
    align-items: center;
    gap: 1rem;
  }

  .header-content {
    text-align: center;
    width: 100%;
  }

  .page-title {
    text-align: center;
  }

  .page-subheading {
    max-width: 100%;
    margin: 1rem auto 0;
  }

  .cytix-logo {
    height: 60px;
  }
}

.title-part-1 {
  color: #1f2937;
  font-weight: 900;
  display: block;
  width: 100%;
}

.title-part-2 {
  background: linear-gradient(90deg, #FF822E 0%, #FFA84D 100%);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  background-clip: text;
  font-weight: 900;
  display: block;
  width: 100%;
}

.page-subheading {
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
  font-size: 1.125rem;
  font-weight: 500;
  color: #4b5563;
  margin: 1rem 0 0 0;
  line-height: 1.6;
  max-width: 600px;
}

.main-content {
  display: flex;
  flex-direction: column;
  gap: 2rem;
  margin-top: 0;
}

.charts-section {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 2rem;
}

.chart-wrapper {
  overflow: hidden;
  border-radius: 12px;
  border: 2px solid #FF822E;
}

.chart-description {
  margin-bottom: 1.5rem;
  padding: 1rem;
  background: rgba(255, 130, 46, 0.05);
  border-left: 4px solid #FF822E;
  border-radius: 4px;
}

.chart-subheading {
  margin: 0;
  font-size: 0.9375rem;
  font-weight: 500;
  color: #4b5563;
  line-height: 1.6;
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
}

.tab-content {
  padding: 1.5rem 0;
}

.tab-description {
  margin: 0 0 1.5rem 0;
  font-size: 0.875rem;
  font-weight: 500;
  color: #666666;
  line-height: 1.5;
  padding-bottom: 0.75rem;
  border-bottom: 1px solid rgba(255, 130, 46, 0.1);
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
}

.coverage-gap-wrapper {
  width: 100%;
  border-radius: 12px;
  border: 2px solid #FF822E;
}

.data-table-wrapper {
  overflow-x: auto;
  border-radius: 12px;
  border: 2px solid #FF822E;
}

/* Naive UI Card overrides */
:deep(.n-card) {
  border-radius: 12px;
  box-shadow: 0 4px 20px rgba(255, 130, 46, 0.1);
}

:deep(.n-card__header) {
  background: linear-gradient(135deg, #FF822E 0%, #DA4100 100%);
  color: white;
  font-weight: 700;
  padding: 1.5rem;
  border-radius: 12px 12px 0 0;
  border-bottom: 2px solid #FF822E;
}

:deep(.n-card__content) {
  padding: 1.5rem;
}

:deep(.n-card__title) {
  font-weight: 700;
  font-size: 1.1rem;
  color: white;
}

/* Tab styling */
:deep(.n-tabs-nav) {
  border-bottom: 2px solid #E5E5E5;
}

:deep(.n-tab-pane) {
  padding: 1rem 0;
}

:deep(.n-tabs--line .n-tab-pane__nav-wrapper) {
  border-bottom: 2px solid #E5E5E5;
}

:deep(.n-tabs--line:not(.n-tabs--segment) .n-tab-pad) {
  color: #020E1E;
}

:deep(.n-tabs--line .n-tabs-tab) {
  color: #020E1E;
  font-weight: 500;
}

:deep(.n-tabs--line .n-tabs-tab--active) {
  color: #FF822E !important;
  font-weight: 700 !important;
}

:deep(.n-tabs--line .n-tabs-tab--active .n-tab__content) {
  color: #FF822E !important;
  font-weight: 700 !important;
}

:deep(.n-tabs--line .n-tabs-tab--active::after) {
  background: #FF822E !important;
  height: 4px !important;
}

:deep(.n-tabs-tab--active::before) {
  background: #FF822E !important;
  height: 3px !important;
}

:deep(.n-tabs--line.n-tabs--top .n-tabs-tab--active::after) {
  background: #FF822E !important;
}

:deep(.n-tabs--line.n-tabs--bottom .n-tabs-tab--active::after) {
  background: #FF822E !important;
}

/* Button styling */
:deep(.n-button--primary) {
  background: linear-gradient(90deg, #FF822E 0%, #DA4100 100%);
  border: none;
  font-weight: 600;
}

:deep(.n-button--primary:hover) {
  background: linear-gradient(90deg, #DA4100 0%, #FF822E 100%);
}

/* Select dropdown styling */
:deep(.n-select) {
  border-radius: 8px;
}

:deep(.n-input__input) {
  border-radius: 8px;
}

/* Apexcharts custom styling */
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
  padding: 8px 12px !important;
  background: #ffffff !important;
}

.apexcharts-tooltip-marker {
  background: #FF822E !important;
}

/* Statistic styling */
:deep(.n-statistic) {
  border-left: 4px solid #FF822E;
  padding-left: 1rem;
}

:deep(.n-statistic__value) {
  font-weight: 700;
  color: #FF822E;
  font-size: 1.5rem;
}

/* Tag styling */
:deep(.n-tag--error) {
  background: #DA4100;
  border-color: #DA4100;
  color: white;
}

.radar-chart {
  grid-column: 1 / -1;
}

@media (max-width: 1024px) {
  .dashboard-container {
    padding: 1.5rem 2rem;
  }

  .charts-section {
    grid-template-columns: 1fr;
    gap: 1.5rem;
  }

  .radar-chart {
    grid-column: auto;
  }
}

@media (max-width: 640px) {
  .page-header {
    margin-bottom: 2rem;
    padding-bottom: 1.5rem;
  }

  .main-content {
    gap: 1.5rem;
    margin-top: 1.5rem;
  }

  .charts-section {
    gap: 1.5rem;
  }
}
</style>
