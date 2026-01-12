<template>
  <div class="tool-coverage-gap">
    <n-card title="Coverage Gap Analysis">
      <n-space vertical>
        <div class="tool-selection-section">
          <n-space justify="space-between">
            <div class="select-container">
              <n-select
                v-model:value="selectedTools"
                multiple
                filterable
                placeholder="Select tools to analyze"
                :options="toolOptions"
                style="width: 300px"
                :render-label="renderOptionLabel"
              />
              <p class="helper-text">Get started by selecting one or more security testing tools to analyze and compare.</p>
              <a
                v-if="selectedTools.length > 0"
                href="https://owasp.org/Top10/2025/0x00_2025-Introduction/"
                target="_blank"
                rel="noopener noreferrer"
                class="owasp-link"
              >
                Explore the full OWASP 2025 categories →
              </a>
              <a
                v-if="selectedTools.length > 0"
                href="https://owasp.org/Top10/2021/"
                target="_blank"
                rel="noopener noreferrer"
                class="owasp-link"
              >
                Explore the full OWASP 2021 categories →
              </a>
            </div>
            <n-button
              v-if="coverageGaps.length > 0"
              type="primary"
              @click="exportCoverageGaps"
            >
              <template #icon>
                <n-icon><download-outlined /></n-icon>
              </template>
              Export Coverage Gaps
            </n-button>
          </n-space>
        </div>

        <div v-if="coverageGaps.length > 0" class="summary-section">
          <div class="summary-stat">
            <h3 class="summary-stat-title">Total CWEs with Detection Gaps</h3>
            <p class="summary-stat-value">{{ coverageGaps.length }} out of {{ totalCwesWithTests }}</p>
            <ul class="summary-stat-details">
              <li>{{ totalCwesWithTests }} CWEs have defined tests in the 2025 framework</li>
              <li>{{ coverageGaps.length }} of these have detection gaps (not 100% detected by all tools)</li>
              <li>{{ cwesWithPerfectDetection }} CWEs are perfectly detected across all selected tools</li>
            </ul>
          </div>

          <div class="summary-stat">
            <h3 class="summary-stat-title">OWASP Categories Affected</h3>
            <p class="summary-stat-value">{{ affectedOwaspCategories }} out of 10</p>
            <ul class="summary-stat-details">
              <li>All 10 OWASP 2025 categories have at least some detection gaps</li>
              <li>{{ affectedOwaspCategories === 10 ? 'No category has complete coverage' : 'Some categories have good coverage' }}</li>
            </ul>
          </div>

          <div class="summary-stat">
            <h3 class="summary-stat-title">Critical Gaps</h3>
            <p class="summary-stat-value">{{ criticalGapsCount }} CWEs with 0% Detection</p>
            <ul class="summary-stat-details">
              <li>These are vulnerability weaknesses that were NOT found by any tool</li>
              <li>Represents significant "blindspots" in security testing</li>
            </ul>
          </div>
        </div>

        <n-grid v-if="coverageGaps.length > 0" cols="3" :x-gap="12" :y-gap="8">
          <n-gi>
            <n-statistic label="Total CWEs with Detection Gaps">
              <n-number-animation
                ref="numberAnimationInstRef"
                :from="0"
                :to="coverageGaps.length"
              />
              <template #suffix>
                <span class="gap-suffix">/ {{ totalCwesWithTests }}</span>
              </template>
            </n-statistic>
          </n-gi>
          <n-gi>
            <n-statistic label="OWASP Categories Affected">
              <n-number-animation
                ref="numberAnimationInstRef"
                :from="0"
                :to="affectedOwaspCategories"
              />
              <template #suffix>
                <span class="gap-suffix">/ 10</span>
              </template>
            </n-statistic>
          </n-gi>
          <n-gi>
            <n-statistic label="Critical Gaps (0% Detection)">
              <template #prefix>
                <n-tag type="error" size="small">Critical</n-tag>
              </template>
              <n-number-animation
                ref="numberAnimationInstRef"
                :from="0"
                :to="criticalGapsCount"
              />
            </n-statistic>
          </n-gi>
        </n-grid>

        <p v-if="coverageGaps.length > 0" class="critical-gaps-explainer">
          <strong>Critical Gaps:</strong> None of the tests completed were found by tool
        </p>

        <n-collapse v-if="coverageGaps.length > 0" class="results-section">
          <n-collapse-item title="Coverage Gaps" name="gaps">
            <n-tabs type="line" animated>
              <n-tab-pane name="cwe" tab="CWE Gaps">
                <n-list>
                  <n-list-item v-for="cwe in cweGaps" :key="cwe.id">
                    <n-thing :title="`CWE-${cwe.id}: ${cwe.name}`">
                      <template #description>
                        <div class="cwe-details">
                          <div><strong>OWASP Category:</strong> {{ cwe.owasp }}</div>
                          <div><strong>Description:</strong> {{ cwe.description }}</div>
                          
                          <div class="tool-detection-rates">
                            <strong>Detection Rate by Tool:</strong>
                            <div v-for="(rate, tool) in cwe.toolDetectionRates" :key="tool" class="tool-rate">
                              <div class="tool-name">{{ tool }}:</div>
                              <n-progress 
                                type="line" 
                                :percentage="rate.rate" 
                                :color="getProgressColor(rate.rate)"
                                :indicator-placement="'inside'"
                                :height="16"
                                :rail-color="rate.rate === 0 ? '#d03050' : undefined"
                                :show-indicator="true"
                              >
                                {{ rate.detected }}/{{ rate.total }} ({{ rate.rate }}%)
                              </n-progress>
                            </div>
                          </div>
                        </div>
                      </template>
                    </n-thing>
                  </n-list-item>
                </n-list>
              </n-tab-pane>
              
              <n-tab-pane name="owasp" tab="OWASP Category Gaps">
                <n-list>
                  <n-list-item v-for="owasp in owaspGaps" :key="owasp.code">
                    <n-thing :title="owasp.code">
                      <template #description>
                        <div class="owasp-details">
                          <div><strong>Name:</strong> {{ owasp.name }}</div>
                          <div><strong>Missing CWEs:</strong> {{ owasp.missingCwes.length }}</div>
                          
                          <div class="tool-detection-rates">
                            <strong>Detection Rate by Tool:</strong>
                            <div v-for="(rate, tool) in owasp.toolDetectionRates" :key="tool" class="tool-rate">
                              <div class="tool-name">{{ tool }}:</div>
                              <n-progress 
                                type="line" 
                                :percentage="rate.rate" 
                                :color="getProgressColor(rate.rate)"
                                :indicator-placement="'inside'"
                                :height="16"
                                :rail-color="rate.rate === 0 ? '#d03050' : undefined"
                                :show-indicator="true"
                              >
                                {{ rate.detected }}/{{ rate.total }} ({{ rate.rate }}%)
                              </n-progress>
                            </div>
                          </div>
                        </div>
                      </template>
                    </n-thing>
                  </n-list-item>
                </n-list>
              </n-tab-pane>
            </n-tabs>
          </n-collapse-item>
        </n-collapse>
        
        <div v-else-if="selectedTools.length > 0" class="no-results">
          <n-empty description="No coverage gaps found for the selected tools" />
        </div>
      </n-space>
    </n-card>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, watch, h } from 'vue'
import { 
  NCard, 
  NSelect, 
  NSpace, 
  NDivider, 
  NTabs, 
  NTabPane, 
  NList, 
  NListItem, 
  NThing, 
  NEmpty,
  NCollapse,
  NCollapseItem,
  NProgress,
  NStatistic,
  NNumberAnimation,
  NGrid,
  NGi,
  NIcon,
  NTag,
  NButton
} from 'naive-ui'
import { loadData, getDetailsByCwe, dataJson } from './data'
import { groupBy, uniq, difference } from 'lodash-es'
import type { VulnerabilitiesData } from './types'
import { DownloadOutlined } from '@vicons/antd'

const { hydratedHeatmapTests, vulnerabilities } = loadData()

// Get unique DAST tools
const scannerTools = computed(() => {
  return Object.keys(dataJson.recordedTests)
})

// Create options for the select component
const toolOptions = computed(() => {
  return scannerTools.value.map(tool => ({
    label: tool,
    value: tool,
    tooltip: dataJson.recordedTests[tool].scanProfile
  }))
})

// Selected tools
const selectedTools = ref<string[]>([])

// Coverage gaps results
const coverageGaps = ref<any[]>([])

// Define emits
const emit = defineEmits(['tools-selected'])

// CWE gaps
const cweGaps = computed(() => {
  if (coverageGaps.value.length === 0) return []
  
  return coverageGaps.value.map(gap => {
    const cweDetails = getDetailsByCwe(gap.cwe)
    const vulnerability = vulnerabilities.find(v => 
      v.CWEDetails.some(detail => detail.id === gap.cwe)
    )
    
    return {
      id: gap.cwe,
      name: cweDetails?.title || 'Unknown',
      description: vulnerability?.group || 'No description available',
      owasp: vulnerability?.OWASP || 'Unknown',
      detectionRate: gap.detectionRate,
      detectionCount: gap.detectionCount,
      totalCount: gap.totalCount,
      toolDetectionRates: gap.toolDetectionRates
    }
  }).sort((a, b) => a.id - b.id) // Sort by CWE ID
})

// OWASP category gaps
const owaspGaps = computed(() => {
  if (coverageGaps.value.length === 0) return []
  
  // Group gaps by OWASP category
  const groupedByOwasp = groupBy(coverageGaps.value, 'owasp')
  
  return Object.entries(groupedByOwasp).map(([owasp, gaps]) => {
    // Calculate detection rate for this OWASP category
    const detectionStats = calculateOwaspDetectionRate(owasp)
    
    // Calculate detection rates by tool for this OWASP category
    const toolDetectionRates = calculateOwaspToolDetectionRates(owasp)
    
    // Extract category ID (e.g., "A01:2021" -> "A01")
    const categoryId = owasp.split(':')[0]
    
    return {
      code: owasp,
      name: owasp.split(' ')[1] || owasp, // Extract name part if available
      categoryId, // Add category ID for sorting
      missingCwes: gaps.map(gap => gap.cwe),
      detectionRate: detectionStats.rate,
      detectionCount: detectionStats.detected,
      totalCount: detectionStats.total,
      toolDetectionRates
    }
  }).sort((a, b) => {
    // Sort by category ID (e.g., A01, A02, etc.)
    return a.categoryId.localeCompare(b.categoryId)
  })
})

// Calculate detection rate for an OWASP category
const calculateOwaspDetectionRate = (owasp: string) => {
  const cwesInCategory = vulnerabilities
    .filter(v => v.OWASP === owasp)
    .flatMap(v => v.CWEDetails.map(detail => detail.id))
  
  let detected = 0
  let total = 0
  
  // Process tests for selected tools
  hydratedHeatmapTests.forEach(test => {
    if (selectedTools.value.includes(test.scanner)) {
      const testCwes = [...test.detectedCWEs, ...test.undetectedCWEs]
      cwesInCategory.forEach(cwe => {
        if (testCwes.includes(cwe)) {
          total++
          if (test.detectedCWEs.includes(cwe)) {
            detected++
          }
        }
      })
    }
  })
  
  return {
    detected,
    total,
    rate: total > 0 ? (detected / total) * 100 : 0
  }
}

// Calculate detection rates by tool for an OWASP category
function calculateOwaspToolDetectionRates(owaspCategory: string) {
  // Get all CWEs in this OWASP category
  const cwesInCategory = vulnerabilities
    .filter(v => v.OWASP === owaspCategory)
    .flatMap(v => v.CWEDetails.map(detail => detail.id))
  
  const toolRates: Record<string, { detected: number; total: number; rate: number }> = {}
  
  // Initialize rates for each selected tool
  selectedTools.value.forEach(tool => {
    toolRates[tool] = { detected: 0, total: 0, rate: 0 }
  })
  
  // Process all tests for selected tools
  selectedTools.value.forEach(tool => {
    const toolTests = hydratedHeatmapTests.filter(test => test.scanner === tool)
    
    toolTests.forEach(test => {
      // Count detections for CWEs in this category
      cwesInCategory.forEach(cwe => {
        const wasDetected = test.detectedCWEs.includes(cwe)
        const wasUndetected = test.undetectedCWEs && test.undetectedCWEs.includes(cwe)
        
        if (wasDetected || wasUndetected) {
          toolRates[tool].total++
          if (wasDetected) {
            toolRates[tool].detected++
          }
        }
      })
    })
    
    // Calculate rate for this tool
    if (toolRates[tool].total > 0) {
      toolRates[tool].rate = Math.round((toolRates[tool].detected / toolRates[tool].total) * 100)
    }
  })
  
  return toolRates
}

// Analyze coverage gaps
function analyzeCoverageGaps() {
  if (selectedTools.value.length === 0) {
    coverageGaps.value = []
    return
  }
  
  // Emit the selected tools to the parent component
  emit('tools-selected', selectedTools.value)
  
  // Create Sets to track unique CWEs
  const allTestedCwes = new Set<number>()
  const detectedCwes = new Map<number, number>() // CWE -> count of detections
  const totalTests = new Map<number, number>() // CWE -> total tests
  
  // Track detection rates by tool for each CWE
  const toolDetectionRates = new Map<number, Record<string, { detected: number, total: number, rate: number }>>()
  
  // Process all tests for selected tools
  selectedTools.value.forEach(tool => {
    const toolTests = hydratedHeatmapTests.filter(test => test.scanner === tool)
    
    toolTests.forEach(test => {
      // Process detected CWEs
      test.detectedCWEs.forEach(cwe => {
        allTestedCwes.add(cwe)
        detectedCwes.set(cwe, (detectedCwes.get(cwe) || 0) + 1)
        totalTests.set(cwe, (totalTests.get(cwe) || 0) + 1)
        
        // Initialize tool detection rates for this CWE if needed
        if (!toolDetectionRates.has(cwe)) {
          toolDetectionRates.set(cwe, {})
        }
        
        // Initialize tool detection rates for this tool if needed
        if (!toolDetectionRates.get(cwe)![tool]) {
          toolDetectionRates.get(cwe)![tool] = { detected: 0, total: 0, rate: 0 }
        }
        
        // Update tool detection rates
        toolDetectionRates.get(cwe)![tool].detected++
        toolDetectionRates.get(cwe)![tool].total++
      })
      
      // Process undetected CWEs
      if (test.undetectedCWEs) {
        test.undetectedCWEs.forEach(cwe => {
          allTestedCwes.add(cwe)
          totalTests.set(cwe, (totalTests.get(cwe) || 0) + 1)
          
          // Initialize tool detection rates for this CWE if needed
          if (!toolDetectionRates.has(cwe)) {
            toolDetectionRates.set(cwe, {})
          }
          
          // Initialize tool detection rates for this tool if needed
          if (!toolDetectionRates.get(cwe)![tool]) {
            toolDetectionRates.get(cwe)![tool] = { detected: 0, total: 0, rate: 0 }
          }
          
          // Update tool detection rates
          toolDetectionRates.get(cwe)![tool].total++
        })
      }
    })
    
    // Calculate rates for each tool
    toolDetectionRates.forEach((toolRates, cwe) => {
      if (toolRates[tool]) {
        toolRates[tool].rate = toolRates[tool].total > 0 
          ? Math.round((toolRates[tool].detected / toolRates[tool].total) * 100) 
          : 0
      }
    })
  })
  
  // Find CWEs that were tested but not detected 100% of the time by any tool
  const gaps = Array.from(allTestedCwes)
    .filter(cwe => {
      // Check if any tool has 100% detection rate for this CWE
      const hasPerfectDetection = selectedTools.value.some(tool => {
        const toolRate = toolDetectionRates.get(cwe)?.[tool]
        return toolRate && toolRate.total > 0 && toolRate.rate === 100
      })
      
      // Only include if no tool has 100% detection rate
      return !hasPerfectDetection
    })
    .map(cwe => {
      const vuln = vulnerabilities.find(v => v.CWEDetails.some(detail => detail.id === cwe))
      return {
        cwe,
        owasp: vuln?.OWASP || 'Unknown',
        detectionCount: detectedCwes.get(cwe) || 0,
        totalCount: totalTests.get(cwe) || 0,
        detectionRate: Math.round(((detectedCwes.get(cwe) || 0) / (totalTests.get(cwe) || 1)) * 100),
        toolDetectionRates: toolDetectionRates.get(cwe) || {}
      }
    })
  
  // Sort by CWE ID
  gaps.sort((a, b) => a.cwe - b.cwe)
  
  coverageGaps.value = gaps
}

// Get color for progress bar based on detection rate - using Cytix brand colors
function getProgressColor(rate: number) {
  if (rate === 0) return '#DA4100' // Cytix Burnt Orange for 0% detection rate
  if (rate < 25) return '#FFB366' // Light orange for very low detection rate
  if (rate < 50) return '#FF822E' // Cytix Orange for low detection rate
  if (rate < 75) return '#89F336' // Cytix Lime for medium-high detection rate
  if (rate < 100) return '#89F336' // Cytix Lime for high detection rate
  return '#020E1E' // Cytix Black for 100% detection rate
}

// Calculate average detection rate
const averageDetectionRate = computed(() => {
  if (coverageGaps.value.length === 0) return 0
  const sum = coverageGaps.value.reduce((acc, gap) => acc + gap.detectionRate, 0)
  return Number((sum / coverageGaps.value.length).toFixed(1))
})

// Calculate number of affected OWASP categories
const affectedOwaspCategories = computed(() => {
  if (coverageGaps.value.length === 0) return 0
  return new Set(coverageGaps.value.map(gap => gap.owasp)).size
})

// Calculate number of critical gaps (0% detection rate)
const criticalGapsCount = computed(() => {
  if (coverageGaps.value.length === 0) return 0
  return coverageGaps.value.filter(gap => gap.detectionRate === 0).length
})

// Calculate total unique CWEs with tests in 2025 dataset
const totalCwesWithTests = computed(() => {
  // Get all unique CWEs from 2025 vulnerabilities that have tests
  const cwesWithTests = new Set<number>()

  vulnerabilities.forEach(vuln => {
    // Only process 2025 vulnerabilities (OWASP code contains ":2025")
    if (vuln.OWASP.includes(':2025')) {
      vuln.CWEDetails.forEach(cweDetail => {
        // Check if this CWE has tests defined
        if (cweDetail.tests && cweDetail.tests.length > 0) {
          cwesWithTests.add(cweDetail.id)
        }
      })
    }
  })

  return cwesWithTests.size
})

// Calculate CWEs with perfect detection (100% detection across all selected tools)
const cwesWithPerfectDetection = computed(() => {
  if (totalCwesWithTests.value === 0 || coverageGaps.value.length === 0) return 0
  return totalCwesWithTests.value - coverageGaps.value.length
})

// Watch for changes to selectedTools and automatically analyze
watch(selectedTools, () => {
  analyzeCoverageGaps()
}, { immediate: true })

// Export coverage gaps to CSV
function exportCoverageGaps() {
  if (coverageGaps.value.length === 0) return

  // Create CSV header
  const headers = [
    'CWE ID',
    'CWE Name',
    'OWASP Category',
    'Description',
    'Detection Rate (%)',
    'Detected Count',
    'Total Count'
  ]
  
  // Add tool-specific columns
  selectedTools.value.forEach(tool => {
    headers.push(`${tool} Detection Rate (%)`)
    headers.push(`${tool} Detected Count`)
    headers.push(`${tool} Total Count`)
  })

  // Create CSV rows
  const rows = coverageGaps.value.map(gap => {
    const cweDetails = getDetailsByCwe(gap.cwe)
    const vulnerability = vulnerabilities.find(v => 
      v.CWEDetails.some(detail => detail.id === gap.cwe)
    )
    
    const baseRow = [
      gap.cwe,
      cweDetails?.title || 'Unknown',
      gap.owasp,
      vulnerability?.group || 'No description available',
      gap.detectionRate,
      gap.detectionCount,
      gap.totalCount
    ]

    // Add tool-specific data
    selectedTools.value.forEach(tool => {
      const toolRate = gap.toolDetectionRates[tool] || { rate: 0, detected: 0, total: 0 }
      baseRow.push(toolRate.rate)
      baseRow.push(toolRate.detected)
      baseRow.push(toolRate.total)
    })

    return baseRow
  })

  // Combine headers and rows
  const csvContent = [
    headers.join(','),
    ...rows.map(row => row.join(','))
  ].join('\n')

  // Create and trigger download
  const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' })
  const link = document.createElement('a')
  const url = URL.createObjectURL(blob)
  link.setAttribute('href', url)
  link.setAttribute('download', `coverage-gaps-${new Date().toISOString().split('T')[0]}.csv`)
  link.style.visibility = 'hidden'
  document.body.appendChild(link)
  link.click()
  document.body.removeChild(link)
}

// Add the renderOptionLabel function
function renderOptionLabel(option: any) {
  return h(
    'div',
    {
      title: option.tooltip,
      style: {
        cursor: 'help',
        width: '100%',
        height: '100%',
        display: 'flex',
        alignItems: 'center'
      }
    },
    option.label
  )
}
</script>

<style scoped>
.tool-coverage-gap {
  width: 100%;
}

.tool-selection-section {
  width: 100%;
  padding-bottom: 1.5rem;
  border-bottom: 1px solid rgba(255, 130, 46, 0.1);
}

.select-container {
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
}

.helper-text {
  font-size: 0.875rem;
  color: #666666;
  margin: 0;
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
  font-weight: 400;
  line-height: 1.5;
  max-width: 400px;
}

.owasp-link {
  display: block;
  margin-top: 0.25rem;
  font-size: 0.875rem;
  font-weight: 600;
  color: #FF822E;
  text-decoration: none;
  transition: color 0.2s ease, opacity 0.2s ease;
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
}

.summary-section {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
  gap: 1.5rem;
  margin: 1.5rem 0;
  padding: 1.5rem;
  background: linear-gradient(135deg, rgba(255, 130, 46, 0.05) 0%, rgba(255, 130, 46, 0.02) 100%);
  border-radius: 12px;
  border: 1px solid rgba(255, 130, 46, 0.1);
}

.summary-stat {
  padding: 1rem;
  background: white;
  border-radius: 8px;
  border-left: 4px solid #FF822E;
}

.summary-stat-title {
  font-size: 0.875rem;
  font-weight: 700;
  color: #FF822E;
  margin: 0 0 0.75rem 0;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
}

.summary-stat-value {
  font-size: 1.75rem;
  font-weight: 700;
  color: #020E1E;
  margin: 0 0 1rem 0;
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
}

.summary-stat-details {
  margin: 0;
  padding-left: 1.25rem;
  font-size: 0.8125rem;
  color: #666666;
  line-height: 1.6;
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
}

.summary-stat-details li {
  margin-bottom: 0.5rem;
}

.owasp-link:hover {
  color: #DA4100;
  opacity: 0.8;
}

.owasp-link:focus {
  outline: 2px solid #FF822E;
  outline-offset: 2px;
}

.results-section {
  margin-top: 2rem;
  border-radius: 12px;
  border: 2px solid #FF822E;
  padding: 1.5rem;
}

.cwe-details, .owasp-details {
  margin-top: 0.5rem;
  padding: 1rem;
  background: rgba(255, 130, 46, 0.02);
  border-radius: 8px;
}

.detection-rate {
  margin-top: 0.75rem;
}

.detection-rate strong {
  display: block;
  margin-bottom: 0.25rem;
  color: #FF822E;
}

.no-results {
  margin-top: 1rem;
  border-radius: 12px;
  padding: 2rem;
  background: rgba(255, 130, 46, 0.05);
}

.tool-detection-rates {
  margin-top: 0.75rem;
  padding: 1rem;
  background: rgba(255, 130, 46, 0.05);
  border-radius: 8px;
  border-left: 4px solid #FF822E;
}

.tool-detection-rates strong {
  color: #020E1E;
  font-weight: 700;
}

.tool-rate {
  margin-bottom: 1rem;
  padding: 0.5rem;
}

.tool-name {
  margin-bottom: 0.5rem;
  font-weight: 600;
  color: #020E1E;
}

.critical-gaps-explainer {
  font-size: 0.875rem;
  color: #666666;
  margin: 1rem 0 0 0;
  padding: 0.75rem 1rem;
  background: rgba(218, 65, 0, 0.05);
  border-left: 3px solid #DA4100;
  border-radius: 4px;
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
  line-height: 1.5;
}

.critical-gaps-explainer strong {
  color: #DA4100;
  font-weight: 600;
}

.gap-suffix {
  font-size: 0.875rem;
  color: #999999;
  font-weight: 400;
  margin-left: 0.25rem;
}
</style>
