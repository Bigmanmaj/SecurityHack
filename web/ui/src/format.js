export const shortHash = (hash, size = 10) => (hash ? `${hash.slice(0, size)}…` : "—");

export const prettyJson = (value) => JSON.stringify(value, null, 2);

export const humanise = (name) => name.replace(/_/g, " ");

export const clockOf = (timestamp) => (timestamp || "").slice(11, 23);

const SIGNER_STYLE = {
  recorder: "chip-cyan",
  investigator: "chip-violet",
  "anchor-1": "chip-green",
  "anchor-2": "chip-green",
};

export const signerStyle = (signer) => SIGNER_STYLE[signer] || "chip-red";

/** One line describing what a record actually claims, per payload type. */
export function recordSummary(record) {
  const payload = record.payload;
  switch (record.type) {
    case "manifest":
      return `${payload.episode_id} · ${payload.model} · forbids ${payload.policy.forbidden_tools.join(", ")}`;
    case "retrieval":
      return `query ${shortHash(payload.query_hash, 8)} · ${payload.chunk_hashes.length} chunk hashes`;
    case "tool_call":
      return `${payload.tool}(args ${shortHash(payload.args_hash, 8)})`;
    case "answer":
      return `answer ${shortHash(payload.answer_hash, 8)}`;
    case "attribution":
      return `${payload.method} · culprit ${shortHash(payload.culprit_chunk_hash, 8)} · ${payload.runs} runs`;
    default:
      return record.type;
  }
}

export const RECORD_BLURB = {
  manifest: "opens the episode and declares the tool policy — everything else binds to its hash",
  retrieval: "which chunks were retrieved, by hash only, never the text",
  tool_call: "the tool the agent called, with its arguments bound by hash",
  answer: "the answer the agent finally gave, by hash",
  attribution: "the investigator's finding: which single chunk caused the misbehaviour",
};
