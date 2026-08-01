<script setup>
import { onMounted, ref } from "vue";
import { applyTamper, getDefaults, rebuild, runEpisode } from "./api";
import InputPanel from "./components/InputPanel.vue";
import InvestigationCard from "./components/InvestigationCard.vue";
import RecordTimeline from "./components/RecordTimeline.vue";
import RolesStrip from "./components/RolesStrip.vue";
import TamperPanel from "./components/TamperPanel.vue";
import VerifierCard from "./components/VerifierCard.vue";

const input = ref(null);
const limits = ref({ max_chunks: 12, max_runs: 10 });
const story = ref(null);
const busy = ref(false);
const error = ref("");

onMounted(async () => {
  try {
    const defaults = await getDefaults();
    input.value = defaults.input;
    limits.value = defaults.limits;
  } catch (failure) {
    error.value = failure.message;
  }
});

async function guard(work) {
  busy.value = true;
  error.value = "";
  try {
    story.value = await work();
  } catch (failure) {
    error.value = failure.message;
  } finally {
    busy.value = false;
  }
}

const run = () => guard(() => runEpisode(input.value));
const tamper = (name) => guard(() => applyTamper(story.value.session, name));
const restore = () => guard(() => rebuild(story.value.session));
</script>

<template>
  <div class="shell">
    <header class="masthead">
      <div>
        <span class="eyebrow">SHA3-256 · ML-DSA-65 · Merkle anchor · single-chunk ablation</span>
        <h1>Attested agent episodes</h1>
        <p class="subtle lede">
          An agent answers a question with retrieved context. If a poisoned chunk talks it into a
          forbidden tool call, this records what happened, proves nobody edited the record
          afterwards, and names the chunk that caused it — without publishing a word of the content.
        </p>
      </div>
      <span
        v-if="story"
        class="verdict"
        :class="story.verifier.verdict === 'GREEN' ? 'verdict-green' : 'verdict-red'"
      >
        <span class="dot" />{{ story.verifier.verdict }}
      </span>
    </header>

    <p v-if="error" class="error">{{ error }}</p>

    <main class="layout">
      <div class="left">
        <InputPanel
          v-if="input"
          :input="input"
          :limits="limits"
          :busy="busy"
          @update:input="input = $event"
          @run="run"
        />
        <section v-if="story" class="card">
          <div class="card-head">
            <div>
              <span class="eyebrow">what the agent did</span>
              <h3>The episode itself</h3>
            </div>
          </div>
          <p v-if="story.observation.tool" class="row">
            <span class="chip chip-red">called {{ story.observation.tool }}</span>
            <span class="mono tiny">{{ story.observation.args.cmd }}</span>
          </p>
          <p v-else class="row"><span class="chip chip-green">called no tool</span></p>
          <p class="subtle answer">“{{ story.observation.answer }}”</p>
          <p class="tiny">
            session {{ story.session }} · this text never enters the bundle, only its hash
          </p>
        </section>
      </div>

      <div class="right">
        <template v-if="story">
          <VerifierCard :verifier="story.verifier" :anchor="story.anchor" />
          <InvestigationCard
            :review="story.review"
            :investigation="story.investigation"
            :chunks="story.input.chunks"
            :leak-check="story.leak_check"
          />
          <RecordTimeline :records="story.records" />
          <TamperPanel
            :tampers="story.tampers"
            :applied="story.applied"
            :busy="busy"
            @tamper="tamper"
            @rebuild="restore"
          />
          <RolesStrip :roles="story.roles" />
        </template>

        <section v-else class="card empty">
          <div class="empty-inner">
            <h3>Nothing recorded yet</h3>
            <p class="subtle">
              Edit the question and the chunks on the left, then run the episode. The default corpus
              already contains one poisoned chunk, so the first run shows the whole story: a
              forbidden <span class="mono">shell.exec</span> call, an investigation that pins it to
              chunk #1, and a <span class="mono">GREEN</span> verdict from a verifier that trusts
              nothing but four public keys.
            </p>
            <ul class="subtle">
              <li>Every record is hashed with SHA3-256 and signed with post-quantum ML-DSA-65.</li>
              <li>A separate party anchors the Merkle root over all records.</li>
              <li>Only hashes are published — never the query, chunks or answer.</li>
            </ul>
          </div>
        </section>
      </div>
    </main>

    <footer class="tiny">
      <span>verify any bundle yourself:</span>
      <code class="mono">python3 verify_cli.py --episode DIR --trust DIR</code>
    </footer>
  </div>
</template>

<style scoped>
.shell {
  max-width: 1400px;
  margin: 0 auto;
  padding: 34px 26px 60px;
}

.masthead {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 20px;
  margin-bottom: 26px;
}

h1 {
  margin: 6px 0 8px;
  font-size: 34px;
}

.lede {
  max-width: 74ch;
}

.layout {
  display: grid;
  grid-template-columns: minmax(320px, 400px) minmax(0, 1fr);
  gap: 18px;
  align-items: start;
}

.left {
  position: sticky;
  top: 24px;
}

.answer {
  margin: 10px 0 8px;
  padding-left: 12px;
  border-left: 2px solid var(--border-strong);
}

.error {
  margin-bottom: 18px;
  padding: 11px 14px;
  background: var(--red-soft);
  border: 1px solid rgba(251, 113, 133, 0.4);
  border-radius: 11px;
  color: #ffb0bd;
  font-size: 13.5px;
}

.empty {
  min-height: 320px;
  display: grid;
  place-items: center;
  text-align: center;
  border-style: dashed;
}

.empty-inner {
  max-width: 60ch;
  padding: 20px;
}

.empty h3 {
  margin-bottom: 10px;
  font-size: 20px;
}

.empty ul {
  margin: 14px 0 0;
  padding: 0;
  list-style: none;
  text-align: left;
  font-size: 13.5px;
}

.empty li {
  padding: 5px 0 5px 20px;
  position: relative;
}

.empty li::before {
  content: "→";
  position: absolute;
  left: 0;
  color: var(--violet);
}

footer {
  display: flex;
  align-items: center;
  gap: 9px;
  flex-wrap: wrap;
  margin-top: 26px;
  padding-top: 18px;
  border-top: 1px solid var(--border);
}

code {
  padding: 3px 8px;
  background: rgba(8, 11, 20, 0.7);
  border: 1px solid var(--border);
  border-radius: 7px;
  color: var(--cyan);
}

@media (max-width: 1080px) {
  .layout {
    grid-template-columns: 1fr;
  }

  .left {
    position: static;
  }
}
</style>
