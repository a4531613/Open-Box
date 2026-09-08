<template>
  <div class="ctrls-bar">
    <div class="app-card-padding relative flex h-12 flex-row items-center text-sm">
      <button
        class="btn btn-circle btn-sm absolute top-2 right-2"
        @click="showCardSettingsDialog = true"
      >
        <Cog6ToothIcon class="h-4 w-4" />
      </button>
    </div>
    <OverviewCardSettingsDialog v-model="showCardSettingsDialog" />
  </div>
</template>

<script setup lang="ts">
import OverviewCardSettingsDialog from '@/components/overview/OverviewCardSettingsDialog.vue'
import { useCtrlsBar } from '@/composables/useCtrlsBar'
import { Cog6ToothIcon } from '@heroicons/vue/24/outline'
import { ref } from 'vue'

const showCardSettingsDialog = ref(false)

useCtrlsBar()
</script>
