<script setup>
import { ref } from "vue";
import HashChip from "./HashChip.vue";
import { RECORD_BLURB, clockOf, prettyJson, recordSummary, signerStyle } from "../format";

defineProps({ records: { type: Array, default: () => [] } });
const open = ref(null);
const toggle = (seq) => (open.value = open.value === seq ? null : seq);
</script>

<template>
  <section class="card">
    <div class="card-head">
      <div>
        <span class="eyebrow">the bundle</span>
        <h3>{{ records.length }} signed records</h3>
      </div>
      <span class="tiny">click a record to see the payload that was signed</span>
    </div>

    <ol class="timeline">
      <li v-for="record in records" :key="record.seq" class="record">
        <button class="record-head" @click="toggle(record.seq)">
          <span class="seq mono">{{ record.seq }}</span>
          <span class="body">
            <span class="title-row">
              <strong class="mono type">{{ record.type }}</strong>
              <span class="chip" :class="signerStyle(record.signer_id)">
                {{ record.signer_id }}
              </span>
              <span class="tiny clock">{{ clockOf(record.created_at) }}</span>
            </span>
            <span class="tiny summary mono">{{ recordSummary(record) }}</span>
            <span class="tiny blurb">{{ RECORD_BLURB[record.type] }}</span>
          </span>
          <HashChip :value="record.payload_hash" label="hash" />
        </button>

        <Transition name="fade">
          <div v-if="open === record.seq" class="payload">
            <div class="payload-head tiny">
              <span>payload — the exact bytes that were hashed and signed</span>
              <span>ML-DSA-65 signature, {{ record.signature_bytes }} bytes</span>
            </div>
            <pre class="mono">{{ prettyJson(record.payload) }}</pre>
            <p class="tiny sig mono">{{ record.signature_preview }}</p>
          </div>
        </Transition>
      </li>
    </ol>
  </section>
</template>

<style scoped>
.timeline {
  margin: 0;
  padding: 0;
  list-style: none;
}

.record {
  position: relative;
  padding-left: 22px;
}

.record::before {
  content: "";
  position: absolute;
  left: 8px;
  top: 26px;
  bottom: -6px;
  width: 1px;
  background: linear-gradient(rgba(148, 163, 184, 0.35), rgba(148, 163, 184, 0.05));
}

.record:last-child::before {
  display: none;
}

.record::after {
  content: "";
  position: absolute;
  left: 4px;
  top: 20px;
  width: 9px;
  height: 9px;
  border-radius: 50%;
  background: var(--panel-solid);
  border: 1.5px solid rgba(167, 139, 250, 0.75);
}

.record-head {
  display: flex;
  align-items: flex-start;
  gap: 12px;
  width: 100%;
  padding: 11px 12px;
  margin: 4px 0;
  background: rgba(8, 11, 20, 0.4);
  border: 1px solid var(--border);
  border-radius: 12px;
  text-align: left;
  cursor: pointer;
  transition: border-color 0.15s, background 0.15s;
}

.record-head:hover {
  border-color: var(--border-strong);
  background: rgba(8, 11, 20, 0.62);
}

.seq {
  flex: none;
  width: 24px;
  height: 24px;
  display: grid;
  place-items: center;
  border-radius: 7px;
  background: var(--violet-soft);
  color: #c9b8ff;
  font-weight: 700;
  font-size: 12px;
}

.body {
  flex: 1;
  min-width: 0;
  display: block;
}

.title-row {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
}

.type {
  font-size: 13.5px;
  font-weight: 600;
}

.clock {
  color: var(--faint);
}

.summary {
  display: block;
  margin-top: 3px;
  color: var(--muted);
  overflow-wrap: anywhere;
}

.blurb {
  display: block;
  margin-top: 2px;
  color: var(--faint);
}

.payload {
  margin: 2px 0 10px;
  padding: 12px;
  background: rgba(4, 6, 12, 0.8);
  border: 1px solid var(--border);
  border-radius: 12px;
}

.payload-head {
  display: flex;
  justify-content: space-between;
  gap: 10px;
  margin-bottom: 8px;
}

pre {
  margin: 0;
  overflow-x: auto;
  color: #b9c8e4;
}

.sig {
  margin-top: 8px;
  color: var(--faint);
  overflow-wrap: anywhere;
}
</style>
