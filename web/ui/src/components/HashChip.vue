<script setup>
import { ref } from "vue";
import { shortHash } from "../format";

const props = defineProps({
  value: { type: String, default: "" },
  size: { type: Number, default: 10 },
  label: { type: String, default: "" },
});

const copied = ref(false);

async function copy() {
  try {
    await navigator.clipboard.writeText(props.value);
  } catch {
    return;
  }
  copied.value = true;
  setTimeout(() => (copied.value = false), 1200);
}
</script>

<template>
  <button class="hash" :title="`${label} ${value} — click to copy`" @click="copy">
    <span v-if="label" class="hash-label">{{ label }}</span>
    <span class="mono">{{ copied ? "copied" : shortHash(value, size) }}</span>
  </button>
</template>

<style scoped>
.hash {
  display: inline-flex;
  align-items: center;
  gap: 7px;
  padding: 3px 9px;
  background: rgba(8, 11, 20, 0.6);
  border: 1px solid var(--border);
  border-radius: 8px;
  cursor: pointer;
  transition: border-color 0.15s, color 0.15s;
}

.hash:hover {
  border-color: rgba(56, 189, 248, 0.5);
  color: #97dcff;
}

.hash-label {
  font-size: 11px;
  color: var(--faint);
}
</style>
