<script setup>
import { humanise } from "../format";

defineProps({
  tampers: { type: Array, default: () => [] },
  applied: { type: Array, default: () => [] },
  busy: { type: Boolean, default: false },
});
const emit = defineEmits(["tamper", "rebuild"]);
</script>

<template>
  <section class="card">
    <div class="card-head">
      <div>
        <span class="eyebrow">attack it</span>
        <h3>Tamper with the bundle</h3>
      </div>
      <button class="btn" :disabled="busy || !applied.length" @click="emit('rebuild')">
        restore
      </button>
    </div>

    <p class="subtle">
      You have no signing key, exactly like anyone who receives a published bundle. Every button
      edits the files on disk and re-runs the verifier.
    </p>

    <div class="grid">
      <button
        v-for="tamper in tampers"
        :key="tamper.name"
        class="btn tamper"
        :disabled="busy"
        :title="tamper.expects"
        @click="emit('tamper', tamper.name)"
      >
        <strong>{{ humanise(tamper.name) }}</strong>
        <span class="tiny">{{ tamper.expects }}</span>
      </button>
    </div>

    <p v-if="applied.length" class="tiny done">
      applied so far:
      <span v-for="name in applied" :key="name" class="chip chip-red">{{ humanise(name) }}</span>
    </p>
  </section>
</template>

<style scoped>
.grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(215px, 1fr));
  gap: 9px;
  margin-top: 14px;
}

.tamper {
  flex-direction: column;
  align-items: flex-start;
  gap: 2px;
  padding: 11px 13px;
  text-align: left;
}

.tamper:hover:not(:disabled) {
  border-color: rgba(251, 113, 133, 0.45);
  background: var(--red-soft);
}

.tamper strong {
  font-size: 13.5px;
  font-weight: 600;
}

.done {
  display: flex;
  align-items: center;
  gap: 7px;
  flex-wrap: wrap;
  margin-top: 14px;
}
</style>
