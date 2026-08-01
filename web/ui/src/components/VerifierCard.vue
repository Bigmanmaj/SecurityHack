<script setup>
defineProps({
  verifier: { type: Object, required: true },
  anchor: { type: Object, default: null },
});
</script>

<template>
  <section class="card verify" :class="verifier.verdict === 'GREEN' ? 'is-green' : 'is-red'">
    <div class="card-head">
      <div>
        <span class="eyebrow">independent check</span>
        <h3>The verifier, as its own process</h3>
      </div>
      <span
        class="verdict"
        :class="verifier.verdict === 'GREEN' ? 'verdict-green' : 'verdict-red'"
      >
        <span class="dot" />{{ verifier.verdict }}
      </span>
    </div>

    <div class="terminal mono">
      <p class="cmd">$ {{ verifier.command }}</p>
      <p v-for="reason in verifier.reasons" :key="reason" class="reason">{{ reason }}</p>
      <p class="line" :class="verifier.verdict === 'GREEN' ? 'ok' : 'no'">
        {{ verifier.verdict }}
      </p>
      <p class="exit">exit {{ verifier.exit_code }}</p>
    </div>

    <div v-if="anchor" class="anchor">
      <div class="row">
        <span class="chip chip-green">anchored by {{ anchor.signer_id }}</span>
        <span class="tiny">{{ anchor.record_count }} records committed</span>
      </div>
      <p class="root mono">{{ anchor.merkle_root }}</p>
      <p class="tiny">
        The Merkle root over every record, signed by a party that holds no recorder key. Nothing can
        be added, removed or edited without moving it.
      </p>
    </div>
    <p v-else class="tiny">There is no readable anchor in this bundle any more.</p>
  </section>
</template>

<style scoped>
.verify.is-green {
  border-color: rgba(52, 211, 153, 0.32);
}

.verify.is-red {
  border-color: rgba(251, 113, 133, 0.35);
}

.terminal {
  padding: 14px;
  background: rgba(3, 5, 10, 0.86);
  border: 1px solid var(--border);
  border-radius: 12px;
}

.terminal p {
  margin: 0;
}

.cmd {
  color: var(--cyan);
  margin-bottom: 6px !important;
}

.reason {
  color: var(--red);
}

.line {
  margin-top: 4px !important;
  font-weight: 700;
  letter-spacing: 0.08em;
}

.line.ok {
  color: var(--green);
}

.line.no {
  color: var(--red);
}

.exit {
  color: var(--faint);
}

.anchor {
  margin-top: 16px;
  padding-top: 14px;
  border-top: 1px solid var(--border);
}

.root {
  margin: 9px 0 7px;
  padding: 9px 11px;
  background: rgba(8, 11, 20, 0.6);
  border: 1px solid var(--border);
  border-radius: 9px;
  color: #86efc4;
  overflow-wrap: anywhere;
}
</style>
