async function call(path, body) {
  const response = await fetch(path, {
    method: body ? "POST" : "GET",
    headers: body ? { "Content-Type": "application/json" } : undefined,
    body: body ? JSON.stringify(body) : undefined,
  });
  const payload = await response.json();
  if (!response.ok) throw new Error(payload.error || `request failed (${response.status})`);
  return payload;
}

export const getDefaults = () => call("/api/defaults");
export const runEpisode = (input) => call("/api/episode", input);
export const applyTamper = (session, tamper) => call("/api/tamper", { session, tamper });
export const rebuild = (session) => call("/api/rebuild", { session });
