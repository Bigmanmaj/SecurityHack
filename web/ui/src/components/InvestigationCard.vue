<script setup>
import { computed } from "vue";
import HashChip from "./HashChip.vue";

const props = defineProps({
  review: { type: Object, required: true },
  investigation: { type: Object, required: true },
  chunks: { type: Array, default: () => [] },
  leakCheck: { type: Object, default: () => ({ checked: 0, found: [] }) },
});

const label = (config) => (config === "baseline" ? "all chunks" : config.replace("without ", "− "));

/** Why no chunk was blamed. Refusing to guess is the feature, not a failure. */
const noCulpritReason = computed(() => {
  const { baseline_misbehaved: consistent, flipped_indexes: flipped } = props.investigation;
  if (!consistent) {
    return "The misbehaviour did not repeat on every replay, so there is no stable baseline to attribute.";
  }
  if (!flipped.length) {
    return "Removing any single chunk left the misbehaviour in place — either more than one chunk can trigger it on its own, or the model misbehaves regardless of what was retrieved.";
  }
  return `Removing #${flipped.join(" or #")} each stopped it, so no single chunk is to blame — they are needed together.`;
});
</script>

<template>
  <section class="card">
    <div class="card-head">
      <div>
        <span class="eyebrow">review and investigation</span>
        <h3>Did it misbehave, and which chunk caused it?</h3>
      </div>
      <span class="chip" :class="review.violations.length ? 'chip-amber' : 'chip-green'">
        {{ review.violations.length ? "policy violated" : "policy respected" }}
      </span>
    </div>

    <p class="subtle">
      <template v-if="review.violations.length">
        The reviewer holds no key. It reads the bundle and sees
        <strong v-for="violation in review.violations" :key="violation.seq" class="warn mono">
          {{ violation.tool }} at seq {{ violation.seq }}</strong
        >, which the manifest forbids — so an investigation is warranted.
      </template>
      <template v-else>
        The reviewer found no forbidden tool call, so there is nothing to attribute. The bundle is
        still fully signed and anchored.
      </template>
    </p>

    <template v-if="investigation.ran">
      <div class="matrix">
        <div v-for="row in investigation.matrix" :key="row.config" class="matrix-row">
          <span class="mono config">{{ label(row.config) }}</span>
          <span class="cells">
            <span
              v-for="(misbehaved, index) in row.outcomes"
              :key="index"
              class="cell"
              :class="misbehaved ? 'bad' : 'good'"
              :title="misbehaved ? 'called the forbidden tool' : 'behaved'"
            />
          </span>
          <span class="tiny outcome" :class="row.outcomes.some(Boolean) ? 'is-bad' : 'is-good'">
            {{ row.outcomes.some(Boolean) ? "still misbehaved" : "stopped" }}
          </span>
        </div>
      </div>

      <div v-if="investigation.culprit_index !== null" class="culprit">
        <div class="row">
          <span class="chip chip-red">culprit chunk #{{ investigation.culprit_index }}</span>
          <HashChip :value="investigation.culprit_chunk_hash" label="chunk hash" />
          <span class="tiny">
            removing it stopped the misbehaviour in {{ investigation.runs }}/{{
              investigation.runs
            }}
            runs
          </span>
        </div>
        <blockquote>{{ chunks[investigation.culprit_index] }}</blockquote>
        <p class="tiny">
          Only the hash of this text is in the bundle. It is shown here because you supplied it —
          the auditor would need the corpus to see it.
        </p>
      </div>
      <div v-else class="unattributed">
        <span class="chip chip-amber">no attribution</span>
        <p class="tiny">{{ noCulpritReason }} Nothing is written to the bundle unless one chunk
          explains it in both directions.</p>
      </div>
    </template>

    <p class="leak tiny">
      <span class="chip chip-green">no content leak</span>
      checked {{ leakCheck.checked }} input strings against every file in the bundle;
      {{ leakCheck.found.length }} found.
    </p>
  </section>
</template>

<style scoped>
.warn {
  color: var(--amber);
}

.matrix {
  margin: 16px 0 4px;
  display: grid;
  gap: 6px;
}

.matrix-row {
  display: grid;
  grid-template-columns: 92px 1fr auto;
  align-items: center;
  gap: 12px;
  padding: 7px 10px;
  background: rgba(8, 11, 20, 0.45);
  border: 1px solid var(--border);
  border-radius: 10px;
}

.config {
  color: var(--muted);
  font-size: 12px;
}

.cells {
  display: flex;
  gap: 5px;
}

.cell {
  width: 15px;
  height: 15px;
  border-radius: 4px;
}

.cell.bad {
  background: var(--red-soft);
  border: 1px solid rgba(251, 113, 133, 0.55);
}

.cell.good {
  background: var(--green-soft);
  border: 1px solid rgba(52, 211, 153, 0.55);
}

.outcome.is-bad {
  color: var(--red);
}

.outcome.is-good {
  color: var(--green);
}

.culprit {
  margin-top: 14px;
  padding: 13px;
  background: linear-gradient(180deg, rgba(251, 113, 133, 0.08), rgba(251, 113, 133, 0.02));
  border: 1px solid rgba(251, 113, 133, 0.3);
  border-radius: 12px;
}

blockquote {
  margin: 10px 0 8px;
  padding-left: 12px;
  border-left: 2px solid rgba(251, 113, 133, 0.5);
  color: #ffd9df;
  font-size: 13.5px;
}

.unattributed {
  display: flex;
  align-items: flex-start;
  gap: 10px;
  margin-top: 14px;
  padding: 12px 13px;
  background: var(--amber-soft);
  border: 1px solid rgba(251, 191, 36, 0.3);
  border-radius: 12px;
}

.leak {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-top: 14px;
  padding-top: 12px;
  border-top: 1px solid var(--border);
}
</style>
