export type LLMStreamPhase = "idle" | "starting" | "waiting" | "generating" | "done" | "error";

export type LLMStreamMetrics = {
  total_duration_ms?: number;
  load_duration_ms?: number;
  prompt_eval_duration_ms?: number;
  eval_duration_ms?: number;
  prompt_eval_count?: number;
  eval_count?: number;
  tokens_per_second?: number;
};

export type LLMStreamEvent =
  | { type: "status"; phase: Exclude<LLMStreamPhase, "idle">; backend?: string }
  | { type: "content"; delta: string }
  | { type: "thinking"; delta: string }
  | { type: "metrics"; metrics: LLMStreamMetrics }
  | { type: "error"; message: string }
  | { type: "done" };

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

export async function consumeLlmStream(
  response: Response,
  onEvent: (event: LLMStreamEvent) => void,
): Promise<void> {
  if (!response.body) throw new Error("Missing response body");

  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";

  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    const lines = buffer.split("\n");
    buffer = lines.pop() ?? "";
    for (const line of lines) {
      if (!line.startsWith("data: ")) continue;
      const payload = line.slice(6);
      if (payload === "[DONE]") {
        onEvent({ type: "done" });
        continue;
      }
      try {
        const parsed: unknown = JSON.parse(payload);
        if (typeof parsed === "string") {
          onEvent({ type: "content", delta: parsed });
          continue;
        }
        if (!isRecord(parsed) || typeof parsed.type !== "string") continue;
        if (parsed.type === "status" && typeof parsed.phase === "string") {
          onEvent({
            type: "status",
            phase: parsed.phase as Exclude<LLMStreamPhase, "idle">,
            backend: typeof parsed.backend === "string" ? parsed.backend : undefined,
          });
        } else if (parsed.type === "content" && typeof parsed.delta === "string") {
          onEvent({ type: "content", delta: parsed.delta });
        } else if (parsed.type === "thinking" && typeof parsed.delta === "string") {
          onEvent({ type: "thinking", delta: parsed.delta });
        } else if (parsed.type === "metrics" && isRecord(parsed.metrics)) {
          onEvent({ type: "metrics", metrics: parsed.metrics as LLMStreamMetrics });
        } else if (parsed.type === "error" && typeof parsed.message === "string") {
          onEvent({ type: "error", message: parsed.message });
        }
      } catch {
        continue;
      }
    }
  }
}

export function llmPhaseLabel(phase: LLMStreamPhase): string {
  switch (phase) {
    case "starting":
      return "Connecting…";
    case "waiting":
      return "Model preparing…";
    case "generating":
      return "Generating…";
    case "done":
      return "Complete";
    case "error":
      return "Error";
    default:
      return "Idle";
  }
}
