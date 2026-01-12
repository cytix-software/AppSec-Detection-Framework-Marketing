<template>
  <div class="data-table-container">
    <div class="column-filters">
      <div
        v-for="col in columns.filter((c) => c.key !== 'detections')"
        :key="col.key"
        class="filter-input"
      >
        <!-- OWASP Code & Group dropdown -->
        <n-select
          v-if="col.key === 'owasp'"
          v-model:value="filters[col.key]"
          :options="owaspOptions"
          :placeholder="`Filter ${col.title}`"
          clearable
          filterable
        />

        <!-- CWE ID dropdown -->
        <n-select
          v-else-if="col.key === 'cwe'"
          v-model:value="filters[col.key]"
          :options="cweOptions"
          :placeholder="`Filter ${col.title}`"
          clearable
          filterable
        />

        <!-- Test dropdown -->
        <n-select
          v-else-if="col.key === 'test'"
          v-model:value="filters[col.key]"
          :options="testOptions"
          :placeholder="`Filter ${col.title}`"
          clearable
          filterable
        />
      </div>

      <!-- Then place your custom filters (detected + profiles) alongside. -->
      <div class="filter-input">
        <n-select
          v-model:value="filters.detected"
          :options="detectedOptions"
          placeholder="Filter Detected"
          clearable
        />
      </div>

      <div class="filter-input">
        <n-select
          v-model:value="filters.profiles"
          :options="profileOptions"
          placeholder="Filter Profiles"
          multiple
          tag
          clearable
        />
      </div>
    </div>

    <n-data-table
      :columns="columns"
      :data="filteredData"
      :pagination="{ pageSize: pagination }"
      class="results-table"
    />
  </div>
</template>

<script setup lang="tsx">
import { NDataTable, NButton, NInput, NSelect, NPopover } from 'naive-ui'
import { filter as lodashFilter, includes, every, toLower } from 'lodash-es'
import { reactive, computed, h } from 'vue'
import type { HydratedTest } from './types'

//
// 1. Define exactly the columns you want displayed.
//
const columns = [
  { 
    title: 'OWASP Code & Group', 
    key: 'owasp', 
    width: 300,
    ellipsis: true
  },
  {
    title: 'CWE ID',
    key: 'cwe',
    width: 100,
    render: (row: any) => `CWE-${row.cwe}`,
  },
  { 
    title: 'Test', 
    key: 'test',
    ellipsis: true
  },
  {
    title: 'Detections',
    key: 'detections',
    width: 275,
    render: (row: any) => {
      return h(
        'div',
        {
          style: 'display: flex; flex-direction: row; gap: 0.5rem; flex-wrap: wrap;',
        },
        row.detections.map((detection: any, index: number) => {
          return h(
            NPopover,
            { trigger: 'hover', flip: true, key: index },
            {
              trigger: () =>
                h(
                  NButton,
                  { round: true, size: 'small', type: 'info' },
                  {
                    default: () =>
                      h('span', { class: 'flex gap-1' }, [
                        detection.detected ? '✅' : '❌',
                        ' ',
                        detection.scanner,
                      ]),
                  },
                ),

              default: () =>
                h(
                  'div',
                  null,
                  detection.profiles.map((profile: string) => h('div', { key: profile }, profile)),
                ),
            },
          )
        }),
      )
    },
  },
]

//
// 2. Props + defaults
//
const props = withDefaults(defineProps<{ data: HydratedTest[]; pagination?: number }>(), {
  data: () => [],
  pagination: 10,
})

//
// 3. Create your filter state (for all fields, even if they aren't columns).
//
interface FilterState {
  owasp: string
  cwe: string // store as string for easy partial matching
  test: string
  detected: string | null
  profiles: string[]
}

const filters = reactive<FilterState>({
  owasp: '',
  cwe: '',
  test: '',
  detected: null,
  profiles: [],
})

// Boolean options
const detectedOptions = [
  { label: 'Detected ✅', value: 'true' },
  { label: 'Not Detected ❌', value: 'false' },
]

//
// 4. Pre-process your data so each row has top-level _detected and _profiles
//
const processedData = computed(() => {
  return props.data.map((row) => {
    // Flatten all the profiles across detections
    const allProfiles = row.detections.flatMap((d) => d.profiles)
    // Example logic: row is considered "detected" if ANY detection is true
    const isDetected = row.detections.some((d) => d.detected)

    return {
      ...row,
      _detected: isDetected,
      _profiles: Array.from(new Set(allProfiles)), // unique profiles
    }
  })
})

//
// 5. Build the owaspOptions for the dropdown
//
const owaspOptions = computed(() => {
  const uniqueOwaspCodes = Array.from(new Set(processedData.value.map((row) => row.owasp)))
  return uniqueOwaspCodes.sort().map((owasp) => ({
    label: owasp,
    value: owasp,
  }))
})

//
// 6. Build the cweOptions for the dropdown
//
const cweOptions = computed(() => {
  const uniqueCwes = Array.from(new Set(processedData.value.map((row) => row.cwe)))
  return uniqueCwes.sort((a, b) => a - b).map((cwe) => ({
    label: `CWE-${cwe}`,
    value: String(cwe),
  }))
})

//
// 7. Build the testOptions for the dropdown
//
const testOptions = computed(() => {
  const uniqueTests = Array.from(new Set(processedData.value.map((row) => row.test)))
  return uniqueTests.sort().map((test) => ({
    label: test,
    value: test,
  }))
})

//
// 8. Build the profileOptions for the multi-select
//
const profileOptions = computed(() => {
  const allProfiles = processedData.value.flatMap((row) => row._profiles)
  return Array.from(new Set(allProfiles)).map((profile) => ({
    label: profile,
    value: profile,
  }))
})

//
// 7. Final filtered result
//
const filteredData = computed(() => {
  return lodashFilter(processedData.value, (row) => {
    return every([
      // OWASP (string includes check)
      !filters.owasp || includes(toLower(row.owasp), toLower(filters.owasp)),

      // CWE (string includes check)
      !filters.cwe || String(row.cwe).includes(filters.cwe),

      // Test (string includes check)
      !filters.test || includes(toLower(row.test), toLower(filters.test)),

      // Detected (boolean check) - only if filters.detected is set
      filters.detected === null || String(row._detected) === filters.detected,

      // Profiles (must contain all selected)
      filters.profiles.length === 0 ||
        filters.profiles.every((profile) => row._profiles.includes(profile)),
    ])
  })
})
</script>

<style scoped>
.data-table-container {
  display: flex;
  flex-direction: column;
  gap: 1.5rem;
  width: 100%;
  overflow-x: auto;
}

.column-filters {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(150px, 1fr));
  gap: 0.75rem;
  margin-bottom: 1.5rem;
  width: 100%;
  padding: 1rem 0;
  border-bottom: 1px solid rgba(255, 130, 46, 0.1);
}

.filter-input {
  min-width: 150px;
  width: 100%;
}

/* Example styling */
.results-table {
  width: 100%;
  overflow-x: auto;
  font-size: 0.9rem;
}

.results-table :deep(.n-data-table-th) {
  background: #020E1E !important;
  color: #ffffff !important;
  font-size: 11px !important;
  font-weight: 700 !important;
  white-space: nowrap;
  padding: 6px 8px !important;
  border-bottom: 2px solid #FF822E !important;
}

.results-table :deep(.n-data-table-td) {
  white-space: nowrap;
  padding: 6px 8px !important;
  border-bottom: 1px solid #F0F0F0 !important;
}

:deep(.n-button--info) {
  background: #FF822E !important;
  color: white !important;
  border: none !important;
}

:deep(.n-button--info:hover) {
  background: #DA4100 !important;
}

:deep(.n-button--info.n-button--round) {
  border-radius: 20px !important;
}

:deep(.n-button--info--text) {
  color: #FF822E !important;
}

@media (max-width: 768px) {
  .column-filters {
    grid-template-columns: 1fr;
  }
  
  .filter-input {
    min-width: 100%;
  }
}
</style>
