import type {
  ContextPacket,
  PatchResult,
  RemediationPlan,
  ProgressEvent,
  Repository,
  Scan,
} from "./types";

const base = import.meta.env?.VITE_API_BASE || "/api";
export class ApiError extends Error {
  constructor(
    message: string,
    public status: number,
  ) {
    super(message);
  }
}
export function canonicalUrl(value: string) {
  const match = value
    .trim()
    .match(
      /^https:\/\/github\.com\/([a-z\d_.-]+)\/([a-z\d_.-]+?)(?:\.git)?\/?$/i,
    );
  if (!match)
    throw new Error(
      "Enter a public GitHub repository URL, such as https://github.com/OWASP/NodeGoat.",
    );
  return `https://github.com/${match[1]}/${match[2]}`;
}
async function checked(response: Response) {
  if (!response.ok) {
    let message = `Request failed (${response.status}).`;
    try {
      const body = await response.json();
      if (typeof body.detail === "string") message = body.detail;
    } catch {
      /* Non-JSON proxy errors */
    }
    if (response.status >= 500)
      message =
        "The backend is unavailable or the request failed. Check that Aegis is running, then refresh.";
    throw new ApiError(message, response.status);
  }
  return response;
}
export async function get<T>(path: string, signal?: AbortSignal): Promise<T> {
  return (await checked(await fetch(base + path, { signal }))).json();
}
export async function register(
  url: string,
  signal: AbortSignal,
): Promise<Repository> {
  return (
    await checked(
      await fetch(base + "/repositories", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url }),
        signal,
      }),
    )
  ).json();
}
export function parseFrames(buffer: string) {
  const frames: { event: string; data: string }[] = [];
  let start = 0;
  const separator = /\r?\n\r?\n/g;
  for (const match of buffer.matchAll(separator)) {
    const lines = buffer.slice(start, match.index).split(/\r?\n/);
    const data = lines
      .filter((line) => line.startsWith("data:"))
      .map((line) => line.slice(5).replace(/^ /, ""))
      .join("\n");
    const event =
      lines
        .find((line) => line.startsWith("event:"))
        ?.slice(6)
        .trim() || "message";
    if (data) frames.push({ event, data });
    start = match.index! + match[0].length;
  }
  return { frames, remainder: buffer.slice(start) };
}
export async function streamScan(
  repository_id: number,
  options: { use_model: boolean; resolve_dependencies: boolean },
  signal: AbortSignal,
  onProgress: (event: ProgressEvent) => void,
  onResult: (scan: Scan) => void,
) {
  return streamResult<Scan>(
    "/scans/stream",
    { repository_id, ...options },
    signal,
    onProgress,
    onResult,
  );
}
export async function streamContext(
  scan_id: number,
  cve_id: string,
  clarification: string,
  signal: AbortSignal,
  onProgress: (event: ProgressEvent) => void,
  onResult: (packet: ContextPacket) => void,
) {
  return streamResult<ContextPacket>(
    "/remediation/context/stream",
    { scan_id, cve_id, clarification },
    signal,
    onProgress,
    onResult,
  );
}
export async function streamPlan(
  scan_id: number,
  cve_id: string,
  clarification: string,
  signal: AbortSignal,
  onProgress: (event: ProgressEvent) => void,
  onResult: (plan: RemediationPlan) => void,
) {
  return streamResult<RemediationPlan>(
    "/remediation/plan/stream",
    { scan_id, cve_id, clarification },
    signal,
    onProgress,
    onResult,
  );
}
export async function streamPatch(
  scan_id: number,
  cve_id: string,
  plan: RemediationPlan,
  context: ContextPacket,
  signal: AbortSignal,
  onProgress: (event: ProgressEvent) => void,
  onResult: (result: PatchResult) => void,
) {
  return streamResult<PatchResult>(
    "/remediation/patch/stream",
    { scan_id, cve_id, plan, context },
    signal,
    onProgress,
    onResult,
  );
}
async function streamResult<T>(
  path: string,
  body: unknown,
  signal: AbortSignal,
  onProgress: (event: ProgressEvent) => void,
  onResult: (result: T) => void,
) {
  const response = await checked(
    await fetch(base + path, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
      signal,
    }),
  );
  if (!response.body)
    throw new Error("Your browser cannot read the progress stream.");
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "",
    resultReceived = false,
    terminal = false;
  try {
    while (true) {
      const { value, done } = await reader.read();
      buffer += decoder.decode(value, { stream: !done });
      if (buffer.length > 20_000_000)
        throw new Error("Progress payload exceeds the display limit.");
      const parsed = parseFrames(buffer);
      buffer = parsed.remainder;
      for (const frame of parsed.frames) {
        const data = JSON.parse(frame.data);
        if (frame.event === "progress") onProgress(data);
        if (frame.event === "result") {
          resultReceived = true;
          onResult(data);
          terminal = true;
        }
        if (frame.event === "end") terminal = true;
        if (frame.event === "error")
          throw new Error(data.message || "Scan failed.");
        if (terminal) break;
      }
      if (terminal || done) break;
    }
    if (!resultReceived)
      throw new Error(
        "The connection ended before results arrived. Check scan history before retrying.",
      );
  } finally {
    try {
      await reader.cancel();
    } finally {
      reader.releaseLock();
    }
  }
}
export function downloadJson(data: unknown, filename: string) {
  const href = URL.createObjectURL(
    new Blob([JSON.stringify(data, null, 2)], { type: "application/json" }),
  );
  const link = document.createElement("a");
  link.href = href;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(href);
}
export function safeLink(value: string) {
  try {
    const url = new URL(value);
    return ["https:", "http:"].includes(url.protocol) ? url.href : undefined;
  } catch {
    return undefined;
  }
}
