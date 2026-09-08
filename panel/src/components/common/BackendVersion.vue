<template>
  <span
    class="truncate"
    @mouseenter="checkTruncation"
  >
    {{ version }}
  </span>
</template>

<script setup lang="ts">
import { version } from '@/api'
import { checkTruncation } from '@/helper/tooltip'
</script>
